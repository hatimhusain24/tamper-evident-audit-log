package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.audit.chain.Bundle;
import com.audit.chain.BundleVerifierCli;
import com.audit.chain.HashChain;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Scenario B: export bundles are independently verifiable offline. */
class ExportTest extends ApiTestBase {

    static final ObjectMapper MAPPER = new ObjectMapper();

    @SuppressWarnings("unchecked")
    Map<String, Object> exportFor(String param, String value) throws Exception {
        return get("/v1/audit/export", param, value).body();
    }

    Bundle bundle(Map<String, Object> raw) {
        return MAPPER.convertValue(raw, Bundle.class);
    }

    @Test
    void bundleHoldsOnlyRequestedRecordsAndVerifies() throws Exception {
        seed(6);                                              // user-1 owns seq 1, 3, 5
        Bundle b = bundle(exportFor("actorId", "user-1"));
        assertThat(b.records()).extracting(r -> r.seq()).containsExactly(1L, 3L, 5L);
        assertThat(b.chain()).extracting(Bundle.Link::seq).containsExactly(1L, 2L, 3L, 4L, 5L, 6L);
        var result = HashChain.verifyBundle(b);
        assertThat(result.valid()).isTrue();
        assertThat(result.recordsChecked()).isEqualTo(3);
        assertThat(result.headSeq()).isEqualTo(6);
    }

    @Test
    void exportByResourceAndEmptyResult() throws Exception {
        seed(6);
        assertThat(bundle(exportFor("resourceId", "acc-0")).records()).extracting(r -> r.seq()).containsExactly(3L, 6L);
        Bundle empty = bundle(exportFor("actorId", "nobody"));
        assertThat(empty.records()).isEmpty();
        assertThat(empty.chain()).isEmpty();
        assertThat(HashChain.verifyBundle(empty).valid()).isTrue();
    }

    @Test
    void exportOnEmptyLog() throws Exception {
        Bundle b = bundle(exportFor("actorId", "anyone"));
        assertThat(b.head().seq()).isZero();
        assertThat(HashChain.verifyBundle(b).valid()).isTrue();
    }

    @Test
    void exactlyOneFilterIsRequired() throws Exception {
        assertThat(get("/v1/audit/export").status()).isEqualTo(400);
        assertThat(get("/v1/audit/export", "actorId", "a", "resourceId", "b").status()).isEqualTo(400);
    }

    @SuppressWarnings("unchecked")
    static Stream<Arguments> bundleTampering() {
        return Stream.of(
                Arguments.of("payload value", (Consumer<Map<String, Object>>) b ->
                        ((Map<String, Object>) record(b, 1).get("payload")).put("n", 999), "PAYLOAD_TAMPERED"),
                Arguments.of("actor", (Consumer<Map<String, Object>>) b ->
                        record(b, 1).put("actorId", "mallory"), "HASH_MISMATCH"),
                Arguments.of("record hash", (Consumer<Map<String, Object>>) b ->
                        record(b, 1).put("hash", "f".repeat(64)), "NOT_IN_CHAIN"),
                Arguments.of("dropped link", (Consumer<Map<String, Object>>) b ->
                        ((List<Object>) b.get("chain")).remove(2), "CHAIN_LINK_BROKEN"),
                Arguments.of("forged head", (Consumer<Map<String, Object>>) b ->
                        ((Map<String, Object>) b.get("head")).put("hash", "0".repeat(64)), "HEAD_MISMATCH"));
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> record(Map<String, Object> bundle, int i) {
        return ((List<Map<String, Object>>) bundle.get("records")).get(i);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("bundleTampering")
    void alteredBundleFails(String name, Consumer<Map<String, Object>> mutate, String violation) throws Exception {
        seed(6);
        Map<String, Object> raw = exportFor("actorId", "user-1");
        mutate.accept(raw);
        assertThat(HashChain.verifyBundle(bundle(raw)).violation()).isEqualTo(violation);
    }

    @Test
    void bundleSpanningRedactedAndArchivedHistoryVerifies() throws Exception {
        seed(4);
        post("/v1/audit/events/3/redactions", Map.of("fields", List.of("accountNumber"), "reason", "erasure"));
        archiveAfterSevenYears();
        post("/v1/audit/events", event(7));
        Bundle b = bundle(exportFor("actorId", "user-1"));
        assertThat(b.records()).extracting(r -> r.seq()).containsExactly(7L);
        assertThat(HashChain.verifyBundle(b).valid()).isTrue();
    }

    String publicKey() throws Exception {
        return callAs(null, org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .get("/v1/audit/signing-key")).get("publicKey");
    }

    @Test
    void publicSigningKeyIsAvailableWithoutLogin() throws Exception {
        Response key = callAs(null, org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .get("/v1/audit/signing-key"));
        assertThat(key.status()).isEqualTo(200);
        assertThat(key.<String>get("algorithm")).isEqualTo("Ed25519");
    }

    @Test
    void signedBundleVerifiesWithThePublicKey() throws Exception {
        seed(6);
        Bundle b = bundle(exportFor("actorId", "user-1"));
        assertThat(b.signature()).isNotBlank();
        assertThat(HashChain.verifyBundle(b, publicKey()).valid()).isTrue();
    }

    @Test
    void droppedRecordIsInvisibleToHashesButBreaksTheSignature() throws Exception {
        seed(6);
        Map<String, Object> raw = exportFor("actorId", "user-1");
        ((List<?>) raw.get("records")).remove(1);                             // silently omit seq 3
        Bundle b = bundle(raw);
        assertThat(HashChain.verifyBundle(b).valid()).isTrue();               // hashes alone: fooled
        var signed = HashChain.verifyBundle(b, publicKey());
        assertThat(signed.valid()).isFalse();
        assertThat(signed.violation()).isEqualTo("SIGNATURE_INVALID");
    }

    @Test
    void unsignedOrForeignSignedBundleFailsTheSignatureCheck() throws Exception {
        seed(2);
        Bundle b = bundle(exportFor("actorId", "user-1"));
        assertThat(HashChain.verifyBundle(b.withSignature(null), publicKey()).violation()).isEqualTo("SIGNATURE_INVALID");
        String otherKey = "MCowBQYDK2VwAyEAQW8c0EveU4tXTie4M3QNrV9sGpyW6mqNXgcTb5dGX74=";   // the dev key
        assertThat(HashChain.verifyBundle(b, otherKey).violation()).isEqualTo("SIGNATURE_INVALID");
    }

    @Test
    void offlineCliVerifiesAndChecksTrustedHead(@TempDir Path dir) throws Exception {
        seed(6);
        Map<String, Object> raw = exportFor("actorId", "user-1");
        Path file = dir.resolve("bundle.json");
        Files.writeString(file, MAPPER.writeValueAsString(raw));
        String head = (String) ((Map<?, ?>) raw.get("head")).get("hash");

        PrintStream original = System.out;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        System.setOut(new PrintStream(out, true, StandardCharsets.UTF_8));
        try {
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle", file.toString()})).isZero();
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle", file.toString(), "--head", head})).isZero();
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle", file.toString(), "--head", "f".repeat(64)})).isEqualTo(1);
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle", file.toString(), "--public-key", publicKey()})).isZero();
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle", file.toString(), "--bogus"})).isEqualTo(2);
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle", dir.resolve("missing.json").toString()})).isEqualTo(2);
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle"})).isEqualTo(2);
            Path headless = dir.resolve("headless.json");
            Files.writeString(headless, "{\"records\":[],\"chain\":[]}");
            assertThat(BundleVerifierCli.run(new String[] {"verify-bundle", headless.toString()})).isEqualTo(1);
        } finally {
            System.setOut(original);
        }
        assertThat(out.toString(StandardCharsets.UTF_8)).contains("HEAD_MISMATCH").contains("MALFORMED_BUNDLE");
    }
}
