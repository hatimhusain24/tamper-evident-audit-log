package com.audit.chain;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/** Pure hash-chain logic: every tamper type must be detected at the right record. */
class HashChainTest {

    private static final ObjectMapper JSON = new ObjectMapper();

    static List<AuditRecord> chain(int n) {
        List<AuditRecord> chain = new ArrayList<>();
        String prev = HashChain.GENESIS_HASH;
        for (int i = 1; i <= n; i++) {
            Map<String, Object> payload = new LinkedHashMap<>();
            payload.put("field", "email");
            payload.put("accountNumber", "12345" + i);
            AuditRecord r = HashChain.build(i, prev, "2026-01-01T00:00:0" + i + ".000000Z",
                    "RECORD_UPDATED", "user-" + i, "svc-test", "ACCOUNT", "acc-1", payload);
            chain.add(r);
            prev = r.hash();
        }
        return chain;
    }

    /** Copy a record with one field changed (records are immutable). */
    static AuditRecord with(AuditRecord r, String field, Object value) {
        @SuppressWarnings("unchecked")
        Map<String, Object> m = JSON.convertValue(r, Map.class);
        m.put(field, value);
        return JSON.convertValue(m, AuditRecord.class);
    }

    @Test
    void canonicalJsonIsKeyOrderIndependentAtEveryLevel() {
        Map<String, Object> a = new LinkedHashMap<>(Map.of("b", 1, "a", Map.of("y", 2, "x", 1)));
        Map<String, Object> b = new LinkedHashMap<>();
        b.put("a", new LinkedHashMap<>(Map.of("x", 1, "y", 2)));
        b.put("b", 1);
        assertThat(HashChain.canonical(a)).isEqualTo(HashChain.canonical(b));
        assertThat(new String(HashChain.canonical(b))).isEqualTo("{\"a\":{\"x\":1,\"y\":2},\"b\":1}");
    }

    @Test
    void intactChainVerifies() {
        List<AuditRecord> chain = chain(5);
        VerifyResult result = HashChain.verify(chain);
        assertThat(result.valid()).isTrue();
        assertThat(result.recordsChecked()).isEqualTo(5);
        assertThat(result.headHash()).isEqualTo(chain.get(4).hash());
    }

    @Test
    void emptyChainIsValid() {
        VerifyResult result = HashChain.verify(List.of());
        assertThat(result.valid()).isTrue();
        assertThat(result.headHash()).isEqualTo(HashChain.GENESIS_HASH);
    }

    @Test
    void unicodeNullNestedAndDecimalPayloadsVerify() {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("name", "José 李 ✓");
        payload.put("missing", null);
        payload.put("nested", Map.of("list", List.of(1, 2.5, true)));
        AuditRecord r = HashChain.build(1, HashChain.GENESIS_HASH, "t", "X_Y", "a", "svc-test", "r", "1", payload);
        assertThat(HashChain.verify(List.of(r)).valid()).isTrue();
    }

    @Test
    void sameValueGetsDifferentCommitmentsBecauseOfSalt() {
        List<AuditRecord> c = chain(2);
        AuditRecord same = HashChain.build(3, c.get(1).hash(), "t", "X_Y", "a", "svc-test", "r", "1",
                Map.of("field", "email"));
        assertThat(same.fieldHashes().get("field")).isNotEqualTo(c.get(0).fieldHashes().get("field"));
    }

    static Stream<Arguments> tampering() {
        return Stream.of(
                Arguments.of("actor edited", (Consumer<List<AuditRecord>>) c ->
                        c.set(2, with(c.get(2), "actorId", "mallory")), "HASH_MISMATCH", 3L),
                Arguments.of("submitter edited", (Consumer<List<AuditRecord>>) c ->
                        c.set(2, with(c.get(2), "recordedBy", "someone-else")), "HASH_MISMATCH", 3L),
                Arguments.of("timestamp edited", (Consumer<List<AuditRecord>>) c ->
                        c.set(2, with(c.get(2), "timestamp", "2020-01-01T00:00:00.000000Z")), "HASH_MISMATCH", 3L),
                Arguments.of("payload value edited", (Consumer<List<AuditRecord>>) c ->
                        c.get(2).payload().put("field", "password"), "PAYLOAD_TAMPERED", 3L),
                Arguments.of("payload field added", (Consumer<List<AuditRecord>>) c ->
                        c.get(2).payload().put("extra", "x"), "PAYLOAD_TAMPERED", 3L),
                Arguments.of("payload field removed", (Consumer<List<AuditRecord>>) c ->
                        c.get(2).payload().remove("field"), "PAYLOAD_TAMPERED", 3L),
                Arguments.of("commitment edited", (Consumer<List<AuditRecord>>) c ->
                        c.get(2).fieldHashes().put("field", "0".repeat(64)), "PAYLOAD_TAMPERED", 3L),
                Arguments.of("record deleted", (Consumer<List<AuditRecord>>) c ->
                        c.remove(2), "SEQUENCE_GAP", 4L),
                Arguments.of("prevHash edited", (Consumer<List<AuditRecord>>) c ->
                        c.set(2, with(c.get(2), "prevHash", "f".repeat(64))), "CHAIN_LINK_BROKEN", 3L));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("tampering")
    void tamperingIsDetectedAtFirstBadRecord(String name, Consumer<List<AuditRecord>> mutate,
                                             String violation, long seq) {
        List<AuditRecord> c = chain(5);
        mutate.accept(c);
        VerifyResult result = HashChain.verify(c);
        assertThat(result.valid()).isFalse();
        assertThat(result.violation()).isEqualTo(violation);
        assertThat(result.firstInvalidSeq()).isEqualTo(seq);
    }

    @Test
    void rehashingAnEditedRecordBreaksTheNextLink() {
        List<AuditRecord> c = chain(4);
        AuditRecord edited = with(c.get(1), "actorId", "mallory");
        c.set(1, HashChain.withHash(edited, HashChain.recordHash(edited))); // attacker recomputes hash
        VerifyResult result = HashChain.verify(c);
        assertThat(result.violation()).isEqualTo("CHAIN_LINK_BROKEN");
        assertThat(result.firstInvalidSeq()).isEqualTo(3);
    }

    @Test
    void swappingRecordsIsDetected() {
        List<AuditRecord> c = chain(4);
        AuditRecord second = c.get(1);
        c.set(1, c.get(2));
        c.set(2, second);
        assertThat(HashChain.verify(c).violation()).isEqualTo("SEQUENCE_GAP");
    }

    @Test
    void literalRedactedTextWithASaltIsNormalData() {
        AuditRecord r = HashChain.build(1, HashChain.GENESIS_HASH, "t", "X_Y", "a", "svc-test", "r", "1",
                new LinkedHashMap<>(Map.of("note", HashChain.REDACTED)));
        assertThat(HashChain.verify(List.of(r)).valid()).isTrue();
    }

    @Test
    void redactionWithoutAuthorizingEventIsFlagged() {
        List<AuditRecord> c = chain(3);
        c.get(0).payload().put("accountNumber", HashChain.REDACTED);
        c.get(0).salts().remove("accountNumber");
        VerifyResult result = HashChain.verify(c);
        assertThat(result.violation()).isEqualTo("UNAUTHORIZED_REDACTION");
        assertThat(result.firstInvalidSeq()).isEqualTo(1);
    }

    @Test
    void tombstoneWithoutPolicyEventIsFlagged() {
        List<AuditRecord> c = chain(3);
        AuditRecord t = c.get(0);
        c.set(0, new AuditRecord(t.seq(), t.timestamp(), null, null, null, null, null, null, null, null,
                t.prevHash(), t.hash(), true, null));
        assertThat(HashChain.verify(c).violation()).isEqualTo("UNAUTHORIZED_ARCHIVE");
    }

    @Test
    void recordThatCannotBeCheckedIsCorruptNotACrash() {
        List<AuditRecord> c = chain(2);
        c.get(1).salts().put("field", null);                       // HexFormat would throw
        VerifyResult result = HashChain.verify(c);
        assertThat(result.violation()).isEqualTo("CORRUPT_RECORD");
        assertThat(result.firstInvalidSeq()).isEqualTo(2);
    }

    @Test
    void untombstonedRecordWithPurgedContentIsCorrupt() {
        List<AuditRecord> c = chain(2);
        AuditRecord t = c.get(0);
        c.set(0, new AuditRecord(t.seq(), t.timestamp(), null, null, null, null, null, null, null, null,
                t.prevHash(), t.hash(), false, null));                    // archived flag cleared, content gone
        assertThat(HashChain.verify(c).violation()).isEqualTo("CORRUPT_RECORD");
    }

    @Test
    void bundleWithoutHeadIsMalformedNotACrash() {
        Bundle b = new Bundle("audit-bundle/v1", "t", "sha256", List.of(), List.of(), null);
        assertThat(HashChain.verifyBundle(b).violation()).isEqualTo("MALFORMED_BUNDLE");
    }

    @Test
    void fieldHashIsDeterministicForSameSalt() {
        String salt = "00".repeat(16);
        assertThat(HashChain.fieldHash(salt, "k", Arrays.asList(1, "a")))
                .isEqualTo(HashChain.fieldHash(salt, "k", List.of(1, "a")));
    }
}
