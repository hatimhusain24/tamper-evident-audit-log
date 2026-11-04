package com.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.audit.store.FieldCipher;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

/** Sensitive fields are AES-GCM ciphertext on disk, plaintext through the API, and still verifiable. */
class EncryptionAtRestTest extends ApiTestBase {

    void writeAccountAccess() throws Exception {
        post("/v1/audit/events", Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "emp-1", "resourceType", "CLIENT_ACCOUNT",
                "resourceId", "acc-1", "payload", Map.of("ssn", "123-45-6789", "accountNumber", "ACCT-55501", "purpose", "call")));
    }

    String rawDatabase() throws Exception {
        jdbc.execute("PRAGMA wal_checkpoint(TRUNCATE)");
        StringBuilder all = new StringBuilder();
        try (Stream<Path> files = Files.list(DB_DIR)) {
            for (Path f : files.filter(f -> f.getFileName().toString().startsWith("audit.db")).toList()) {
                all.append(new String(Files.readAllBytes(f), StandardCharsets.ISO_8859_1));
            }
        }
        return all.toString();
    }

    @Test
    void sensitiveValuesNeverReachTheDiskInPlaintext() throws Exception {
        writeAccountAccess();
        String raw = rawDatabase();
        assertThat(raw).doesNotContain("123-45-6789").doesNotContain("ACCT-55501").contains("enc:v1:");
        assertThat(jdbc.queryForObject("SELECT payload FROM events WHERE seq = 1", String.class))
                .contains("\"purpose\":\"call\"");                             // non-sensitive stays readable
    }

    @Test
    void apiReturnsPlaintextAndTheChainVerifies() throws Exception {
        writeAccountAccess();
        var item = get("/v1/audit/events").items().get(0);                     // root has COMPLIANCE
        assertThat(String.valueOf(item.get("payload"))).contains("ssn=123-45-6789");
        assertThat(verify().<Boolean>get("valid")).isTrue();
        var bundle = get("/v1/audit/export", "resourceId", "acc-1");
        assertThat(bundle.body().toString()).contains("123-45-6789");            // compliance export: plaintext
    }

    @Test
    void redactingAnEncryptedFieldStillVerifies() throws Exception {
        writeAccountAccess();
        assertThat(post("/v1/audit/events/1/redactions", Map.of("fields", List.of("ssn"), "reason", "erasure"))
                .status()).isEqualTo(201);
        assertThat(verify().<Boolean>get("valid")).isTrue();
        assertThat(jdbc.queryForObject("SELECT payload FROM events WHERE seq = 1", String.class))
                .contains("\"ssn\":\"[REDACTED]\"").contains("enc:v1:");        // accountNumber still encrypted
    }

    @Test
    void tamperedCiphertextIsReportedAsCorrupt() throws Exception {
        writeAccountAccess();
        String payload = jdbc.queryForObject("SELECT payload FROM events WHERE seq = 1", String.class);
        int at = payload.indexOf("enc:v1:") + 12;
        String flipped = payload.substring(0, at) + (payload.charAt(at) == 'A' ? 'B' : 'A') + payload.substring(at + 1);
        tamper("UPDATE events SET payload = ? WHERE seq = 1", flipped);
        Response v = verify();
        assertThat(v.<String>get("violation")).isEqualTo("CORRUPT_RECORD");      // GCM tag fails
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(1);
    }

    @Test
    void reservedCiphertextPrefixIsRefusedOnInput() throws Exception {
        Map<String, Object> e = new java.util.LinkedHashMap<>(event(1));
        e.put("payload", Map.of("note", "enc:v1:forged"));
        assertThat(post("/v1/audit/events", e).status()).isEqualTo(400);
    }

    @Test
    void cipherRoundTripsAndRejectsTheWrongKey() {
        FieldCipher a = FieldCipher.of("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=", Set.of("ssn"));
        FieldCipher b = FieldCipher.of("HxwdHhscGRgXFhUUExIREA8ODQwLCgkIBwYFBAMCAQA=", Set.of("ssn"));
        Map<String, Object> sealed = a.encrypt(Map.of("ssn", Map.of("nested", List.of(1, 2)), "other", "x"));
        assertThat(sealed.get("ssn")).asString().startsWith(FieldCipher.PREFIX);
        assertThat(a.decrypt(sealed)).containsEntry("ssn", Map.of("nested", List.of(1, 2))).containsEntry("other", "x");
        assertThat(b.decrypt(sealed)).isNull();                                  // wrong key: unreadable
        assertThat(a.encrypt(Map.of("ssn", "[REDACTED]"))).containsEntry("ssn", "[REDACTED]");
    }

    @Test
    void serviceRefusesAMissingOrWrongSizeKey() {
        assertThatThrownBy(() -> FieldCipher.of(null, Set.of())).hasMessageContaining("refuses to start");
        assertThatThrownBy(() -> FieldCipher.of("c2hvcnQ=", Set.of())).hasMessageContaining("32 bytes");
        assertThatThrownBy(() -> FieldCipher.of("not base64!", Set.of())).hasMessageContaining("32 bytes");
    }
}
