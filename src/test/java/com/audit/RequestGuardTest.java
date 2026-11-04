package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** Body-size limit and per-client rate limit, both enforced before authentication. */
@TestPropertySource(properties = "audit.rate-limit.per-minute=5")
class RequestGuardTest extends ApiTestBase {

    private static final java.util.concurrent.atomic.AtomicLong WINDOW = new java.util.concurrent.atomic.AtomicLong();

    /** Each test gets its own rate-limit window (the clock is reset to "now" before every test). */
    void freshWindow() {
        clock.advanceDays(10 * WINDOW.incrementAndGet());
    }

    @Test
    void oversizedBodyIsRefusedBeforeParsing() throws Exception {
        freshWindow();
        String huge = "{\"x\":\"" + "a".repeat(5 * 1024 * 1024) + "\"}";   // 5 MB, probe P7
        var request = MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON).content(huge);
        assertThat(callAs("writer", request).status()).isEqualTo(413);
    }

    @Test
    void bodyJustOverTheLimitIsRefused() throws Exception {
        freshWindow();
        String body = "{\"x\":\"" + "a".repeat(65_536) + "\"}";
        var request = MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON).content(body);
        assertThat(callAs("writer", request).status()).isEqualTo(413);
    }

    @Test
    void floodFromOneClientGets429WithRetryAfter() throws Exception {
        freshWindow();
        for (int i = 0; i < 5; i++) {
            assertThat(callAs("reader", MockMvcRequestBuilders.get("/v1/audit/verify")).status()).isEqualTo(200);
        }
        var sixth = mvc.perform(MockMvcRequestBuilders.get("/v1/audit/verify")
                .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                        .httpBasic("reader", PASSWORD))).andReturn().getResponse();
        assertThat(sixth.getStatus()).isEqualTo(429);
        assertThat(sixth.getHeader("Retry-After")).isEqualTo("60");
        clock.advanceDays(1);                                              // next window: allowed again
        assertThat(callAs("reader", MockMvcRequestBuilders.get("/v1/audit/verify")).status()).isEqualTo(200);
    }

    @Test
    void passwordGuessingIsThrottledToo() throws Exception {
        freshWindow();
        int last = 0;
        for (int i = 0; i < 6; i++) {
            last = mvc.perform(MockMvcRequestBuilders.get("/v1/audit/verify")
                    .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                            .httpBasic("admin", "guess-" + i))).andReturn().getResponse().getStatus();
        }
        assertThat(last).isEqualTo(429);                                   // limit applies before auth
    }

    @Test
    void normalWritesStillWork() throws Exception {
        freshWindow();
        assertThat(callAs("writer", MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(event(1)))).status()).isEqualTo(201);
        assertThat(callAs("writer", MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("eventType", "lowercase")))).status()).isEqualTo(400);
    }
}
