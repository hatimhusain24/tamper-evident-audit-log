package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Exact limits: the last allowed value passes, one more is rejected. */
class BoundaryTest extends ApiTestBase {

    Map<String, Object> withPayloadOfCanonicalSize(int bytes) {
        Map<String, Object> e = new LinkedHashMap<>(event(1));
        e.put("payload", Map.of("x", "a".repeat(bytes - "{\"x\":\"\"}".length())));
        return e;
    }

    @Test
    void payloadOfExactly32KbIsAcceptedOneByteMoreIsNot() throws Exception {
        assertThat(post("/audit/events", withPayloadOfCanonicalSize(32_768)).status()).isEqualTo(201);
        assertThat(post("/audit/events", withPayloadOfCanonicalSize(32_769)).status()).isEqualTo(400);
    }

    @Test
    void identifiersOf128CharsAreAccepted129AreNot() throws Exception {
        Map<String, Object> ok = new LinkedHashMap<>(event(1));
        ok.put("actorId", "a".repeat(128));
        ok.put("resourceId", "r".repeat(128));
        assertThat(post("/audit/events", ok).status()).isEqualTo(201);
        Map<String, Object> tooLong = new LinkedHashMap<>(event(1));
        tooLong.put("resourceType", "t".repeat(129));
        assertThat(post("/audit/events", tooLong).status()).isEqualTo(400);
    }

    @Test
    void eventTypeLengthLimits() throws Exception {
        Map<String, Object> e = new LinkedHashMap<>(event(1));
        e.put("eventType", "A" + "B".repeat(63));                         // 64 chars: max
        assertThat(post("/audit/events", e).status()).isEqualTo(201);
        e.put("eventType", "A" + "B".repeat(64));                         // 65 chars
        assertThat(post("/audit/events", e).status()).isEqualTo(400);
        e.put("eventType", "A");                                          // too short
        assertThat(post("/audit/events", e).status()).isEqualTo(400);
    }

    @Test
    void redactionFieldAndReasonLimits() throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>();
        for (int i = 0; i < 51; i++) {
            payload.put("f" + i, i);
        }
        Map<String, Object> e = new LinkedHashMap<>(event(1));
        e.put("payload", payload);
        post("/audit/events", e);
        List<String> fifty = new ArrayList<>(payload.keySet()).subList(0, 50);
        List<String> fiftyOne = new ArrayList<>(payload.keySet());
        assertThat(post("/audit/events/1/redactions", Map.of("fields", fiftyOne, "reason", "abc")).status()).isEqualTo(400);
        assertThat(post("/audit/events/1/redactions", Map.of("fields", fifty, "reason", "x".repeat(501))).status()).isEqualTo(400);
        assertThat(post("/audit/events/1/redactions", Map.of("fields", fifty, "reason", "ab")).status()).isEqualTo(400);
        assertThat(post("/audit/events/1/redactions", Map.of("fields", fifty, "reason", "x".repeat(500))).status()).isEqualTo(201);
    }

    @Test
    void pageLimitOf500IsAccepted() throws Exception {
        seed(3);
        Response page = get("/audit/events", "limit", "500");
        assertThat(page.status()).isEqualTo(200);
        assertThat(page.items()).hasSize(3);
        assertThat(page.body().get("nextCursor")).isNull();
    }

    @Test
    void retentionWindowAtTheMaximumIsAccepted() throws Exception {
        assertThat(post("/audit/retention/run", Map.of("olderThanDays", 36_500)).status()).isEqualTo(200);
    }
}
