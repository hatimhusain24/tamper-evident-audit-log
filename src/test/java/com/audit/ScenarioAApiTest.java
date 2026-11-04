package com.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;

/** Scenario A: write -> query -> verify -> tamper directly in the DB -> verify again. */
class ScenarioAApiTest extends ApiTestBase {

    @Test
    void writeReturnsChainedRecordWithServerTimestamp() throws Exception {
        List<Response> r = seed(2);
        assertThat(r.get(0).status()).isEqualTo(201);
        assertThat(r.get(0).<Integer>get("seq")).isEqualTo(1);
        assertThat(r.get(0).<String>get("prevHash")).isEqualTo("0".repeat(64));
        assertThat(r.get(1).<String>get("prevHash")).isEqualTo(r.get(0).get("hash"));
        assertThat(r.get(0).<String>get("timestamp")).matches("\\d{4}-\\d\\d-\\d\\dT\\d\\d:\\d\\d:\\d\\d\\.\\d{6}Z");
        assertThat(r.get(0).body()).doesNotContainKey("salts");   // commitment salts stay internal
    }

    @Test
    void payloadIsOptional() throws Exception {
        Map<String, Object> e = event(1);
        e.remove("payload");
        assertThat(post("/audit/events", e).status()).isEqualTo(201);
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    static Stream<Arguments> invalidEvents() {
        return Stream.of(
                Arguments.of("lowercase type", Map.of("eventType", "lowercase")),
                Arguments.of("blank actor", Map.of("actorId", " ")),
                Arguments.of("actor too long", Map.of("actorId", "a".repeat(129))),
                Arguments.of("payload not object", Map.of("payload", "text")),
                Arguments.of("payload too large", Map.of("payload", Map.of("big", "x".repeat(40_000)))),
                Arguments.of("caller timestamp", Map.of("timestamp", "2020-01-01T00:00:00Z")),
                Arguments.of("reserved redaction type", Map.of("eventType", "RECORD_REDACTED")),
                Arguments.of("reserved archive type", Map.of("eventType", "RECORDS_ARCHIVED")));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("invalidEvents")
    void invalidEventsAreRejected(String name, Map<String, Object> override) throws Exception {
        Map<String, Object> e = event(1);
        e.putAll(override);
        assertThat(post("/audit/events", e).status()).isEqualTo(400);
        assertThat(verify().<Integer>get("recordsChecked")).isZero();
    }

    @Test
    void malformedJsonIsRejected() throws Exception {
        var request = org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/audit/events")
                .contentType(MediaType.APPLICATION_JSON).content("{not json");
        assertThat(call(request).status()).isEqualTo(400);
    }

    @Test
    void noUpdateOrDeleteRoutes() throws Exception {
        seed(1);
        assertThat(call(put("/audit/events/1")).status()).isIn(403, 404, 405);
        assertThat(call(patch("/audit/events/1")).status()).isIn(403, 404, 405);
        assertThat(call(delete("/audit/events/1")).status()).isIn(403, 404, 405);
    }

    @Test
    void filtersCombine() throws Exception {
        seed(6);
        var items = get("/audit/events", "actorId", "user-1", "resourceType", "ACCOUNT", "resourceId", "acc-1").items();
        assertThat(items).extracting(m -> m.get("seq")).containsExactly(1);
        assertThat(get("/audit/events", "eventType", "USER_LOGIN").items()).isEmpty();
        assertThat(get("/audit/events", "resourceId", "acc-0").items()).extracting(m -> m.get("seq")).containsExactly(3, 6);
    }

    @Test
    void timeRangeIsFromInclusiveToExclusive() throws Exception {
        List<Response> r = seed(4);
        var items = get("/audit/events", "from", r.get(1).get("timestamp"), "to", r.get(3).get("timestamp")).items();
        assertThat(items).extracting(m -> m.get("seq")).containsExactly(2, 3);
        // inverted range returns nothing rather than an error
        assertThat(get("/audit/events", "from", r.get(3).get("timestamp"), "to", r.get(0).get("timestamp")).items()).isEmpty();
    }

    @Test
    void keysetPaginationWalksAllPagesOnce() throws Exception {
        seed(7);
        List<Object> seen = new ArrayList<>();
        Object cursor = 0;
        while (cursor != null) {
            Response page = get("/audit/events", "limit", "3", "cursor", String.valueOf(cursor));
            page.items().forEach(m -> seen.add(m.get("seq")));
            cursor = page.get("nextCursor");
        }
        assertThat(seen).containsExactly(1, 2, 3, 4, 5, 6, 7);
        assertThat(get("/audit/events", "cursor", "99").items()).isEmpty();
    }

    @Test
    void paginationLimitsAreEnforced() throws Exception {
        assertThat(get("/audit/events", "limit", "0").status()).isEqualTo(400);
        assertThat(get("/audit/events", "limit", "501").status()).isEqualTo(400);
        assertThat(get("/audit/events", "cursor", "-1").status()).isEqualTo(400);
        assertThat(get("/audit/events", "from", "not-a-date").status()).isEqualTo(400);
    }

    @Test
    void verifyIntactChain() throws Exception {
        List<Response> r = seed(6);
        Response v = verify();
        assertThat(v.<Boolean>get("valid")).isTrue();
        assertThat(v.<Integer>get("recordsChecked")).isEqualTo(6);
        assertThat(v.<String>get("headHash")).isEqualTo(r.get(5).get("hash"));
    }

    static Stream<Arguments> directDbTampering() {
        return Stream.of(
                Arguments.of("UPDATE events SET actor_id = 'mallory' WHERE seq = 3", "HASH_MISMATCH", 3),
                Arguments.of("UPDATE events SET event_type = 'USER_LOGIN' WHERE seq = 5", "HASH_MISMATCH", 5),
                Arguments.of("UPDATE events SET resource_id = 'acc-9' WHERE seq = 1", "HASH_MISMATCH", 1),
                Arguments.of("UPDATE events SET payload = json_set(payload, '$.n', 999) WHERE seq = 3", "PAYLOAD_TAMPERED", 3),
                Arguments.of("UPDATE events SET payload = json_set(payload, '$.extra', 1) WHERE seq = 4", "PAYLOAD_TAMPERED", 4),
                Arguments.of("UPDATE events SET archived = 1 WHERE seq = 6", "UNAUTHORIZED_ARCHIVE", 6));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("directDbTampering")
    void directDatabaseEditsAreDetected(String sql, String violation, int seq) throws Exception {
        seed(6);
        tamper(sql);
        Response v = verify();
        assertThat(v.<Boolean>get("valid")).isFalse();
        assertThat(v.<String>get("violation")).isEqualTo(violation);
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(seq);
    }

    @Test
    void guardrailTriggersBlockNaiveDeleteAndChainEdits() throws Exception {
        seed(2);
        assertThatThrownBy(() -> tamper("DELETE FROM events WHERE seq = 1")).hasMessageContaining("append-only");
        assertThatThrownBy(() -> tamper("UPDATE events SET hash = 'x' WHERE seq = 1")).hasMessageContaining("immutable");
    }

    @Test
    void deletionDetectedEvenWhenGuardrailIsBypassed() throws Exception {
        seed(6);
        tamper("DROP TRIGGER events_no_delete");
        tamper("DELETE FROM events WHERE seq = 2");
        Response v = verify();
        assertThat(v.<String>get("violation")).isEqualTo("SEQUENCE_GAP");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(3);
    }

    @Test
    void forgedRecordInsertedAtTheEndWithWrongLinkIsDetected() throws Exception {
        seed(3);
        tamper("INSERT INTO events (seq, timestamp, event_type, actor_id, recorded_by, resource_type, resource_id, "
                + "payload, salts, field_hashes, prev_hash, hash, mac) VALUES (4, '2099-01-01T00:00:00.000000Z', 'X_Y', "
                + "'a', 'svc', 'r', '1', '{}', '{}', '{}', ?, ?, 'forged')", "0".repeat(64), "f".repeat(64));
        assertThat(verify().<String>get("violation")).isEqualTo("CHAIN_LINK_BROKEN");
    }

    @Test
    void concurrentWritersNeverForkTheChain() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Future<Response>> futures = new ArrayList<>();
        for (int i = 0; i < 80; i++) {
            int n = i;
            futures.add(pool.submit(() -> post("/audit/events", event(n))));
        }
        for (Future<Response> f : futures) {
            assertThat(f.get().status()).isEqualTo(201);
        }
        pool.shutdown();
        Response v = verify();
        assertThat(v.<Boolean>get("valid")).isTrue();
        assertThat(v.<Integer>get("recordsChecked")).isEqualTo(80);
    }

    @Test
    void healthEndpoint() throws Exception {
        assertThat(get("/health").<String>get("status")).isEqualTo("ok");
    }
}
