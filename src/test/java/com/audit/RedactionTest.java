package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** Scenario B: redaction removes data without breaking the chain, and is itself audited. */
class RedactionTest extends ApiTestBase {

    static final Map<String, Object> REDACT = Map.of(
            "fields", List.of("accountNumber"), "reason", "GDPR erasure #77");

    @BeforeEach
    void seedThree() throws Exception {
        seed(3);
    }

    @Test
    void redactionKeepsChainValidAndIsLogged() throws Exception {
        Response res = post("/v1/audit/events/2/redactions", REDACT);
        assertThat(res.status()).isEqualTo(201);
        assertThat(res.<String>get("eventType")).isEqualTo("RECORD_REDACTED");
        assertThat(res.<String>get("actorId")).isEqualTo("root");          // the authenticated admin
        assertThat(res.<String>get("recordedBy")).isEqualTo("root");
        assertThat(res.<Map<String, Object>>get("payload"))
                .containsEntry("targetSeq", 2).containsEntry("fields", List.of("accountNumber"));

        var record = get("/v1/audit/events", "limit", "1", "cursor", "1").items().get(0);
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) record.get("payload");
        assertThat(payload).containsEntry("accountNumber", "[REDACTED]").containsEntry("n", 2);
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void multipleFieldsAndDuplicatesAreHandled() throws Exception {
        Response res = post("/v1/audit/events/1/redactions", Map.of("fields", List.of("n", "accountNumber", "n"),
                "reason", "erasure"));
        assertThat(res.<Map<String, Object>>get("payload")).containsEntry("fields", List.of("accountNumber", "n"));
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void redactedValueIsGoneFromRawDatabaseFiles() throws Exception {
        post("/v1/audit/events/2/redactions", REDACT);
        try (Stream<Path> files = Files.list(DB_DIR)) {
            for (Path file : files.filter(f -> f.getFileName().toString().startsWith("audit.db")).toList()) {
                assertThat(new String(Files.readAllBytes(file), java.nio.charset.StandardCharsets.ISO_8859_1))
                        .as(file.toString()).doesNotContain("990002");
            }
        }
    }

    @Test
    void secureDeleteIsOnForEveryConnection() {
        assertThat(jdbc.queryForObject("PRAGMA secure_delete", Integer.class)).isEqualTo(1);
    }

    @Test
    void errorCases() throws Exception {
        assertThat(post("/v1/audit/events/99/redactions", REDACT).status()).isEqualTo(404);
        assertThat(post("/v1/audit/events/2/redactions", Map.of("fields", List.of("nope"), "reason", "abc")).status()).isEqualTo(409);
        assertThat(post("/v1/audit/events/2/redactions", Map.of("fields", List.of(), "reason", "abc")).status()).isEqualTo(400);
        assertThat(post("/v1/audit/events/2/redactions", Map.of("fields", List.of("n"), "reason", "")).status()).isEqualTo(400);
    }

    @Test
    void doubleRedactionAndSystemEventsAreRejected() throws Exception {
        post("/v1/audit/events/2/redactions", REDACT);
        assertThat(post("/v1/audit/events/2/redactions", REDACT).status()).isEqualTo(409);
        assertThat(post("/v1/audit/events/4/redactions", Map.of("fields", List.of("reason"), // seq 4 = RECORD_REDACTED
                "reason", "abc")).status()).isEqualTo(409);
    }

    @Test
    void forgedRedactionInDatabaseIsDetected() throws Exception {
        tamper("UPDATE events SET payload = json_set(payload, '$.accountNumber', '[REDACTED]'), "
                + "salts = json_remove(salts, '$.accountNumber') WHERE seq = 2");
        Response v = verify();
        assertThat(v.<String>get("violation")).isEqualTo("UNAUTHORIZED_REDACTION");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(2);
    }

    @Test
    void editingTheRedactionEventItselfIsDetected() throws Exception {
        post("/v1/audit/events/2/redactions", REDACT);
        tamper("UPDATE events SET payload = json_set(payload, '$.reason', 'nothing to see') WHERE seq = 4");
        assertThat(verify().<String>get("violation")).isEqualTo("PAYLOAD_TAMPERED");
    }
}
