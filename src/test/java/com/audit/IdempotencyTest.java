package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** Retries and replays with an Idempotency-Key never create duplicate audit records. */
class IdempotencyTest extends ApiTestBase {

    Response write(String user, String key, Map<String, Object> body) throws Exception {
        var request = MockMvcRequestBuilders.post("/audit/events").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(body));
        if (key != null) {
            request.header("Idempotency-Key", key);
        }
        return callAs(user, request);
    }

    @Test
    void retryReturnsTheOriginalRecordWithoutWritingAgain() throws Exception {
        Response first = write("writer", "order-123-abc", event(1));
        Response retry = write("writer", "order-123-abc", event(1));
        assertThat(first.status()).isEqualTo(201);
        assertThat(retry.status()).isEqualTo(200);
        assertThat(retry.<Integer>get("seq")).isEqualTo(first.<Integer>get("seq"));
        assertThat(retry.<String>get("hash")).isEqualTo(first.<String>get("hash"));
        assertThat(verify().<Integer>get("recordsChecked")).isEqualTo(1);
    }

    @Test
    void sameKeyWithADifferentRequestIsAConflict() throws Exception {
        write("writer", "order-123-abc", event(1));
        assertThat(write("writer", "order-123-abc", event(2)).status()).isEqualTo(409);
        assertThat(verify().<Integer>get("recordsChecked")).isEqualTo(1);
    }

    @Test
    void keysAreScopedPerCaller() throws Exception {
        assertThat(write("writer", "shared-key-01", event(1)).status()).isEqualTo(201);
        assertThat(write("root", "shared-key-01", event(1)).status()).isEqualTo(201);
        assertThat(verify().<Integer>get("recordsChecked")).isEqualTo(2);
    }

    @Test
    void writesWithoutAKeyAreNotDeduplicated() throws Exception {
        write("writer", null, event(1));
        write("writer", null, event(1));
        assertThat(verify().<Integer>get("recordsChecked")).isEqualTo(2);
    }

    @Test
    void malformedKeysAreRejected() throws Exception {
        assertThat(write("writer", "short", event(1)).status()).isEqualTo(400);
        assertThat(write("writer", "has spaces in it", event(1)).status()).isEqualTo(400);
        assertThat(write("writer", "x".repeat(65), event(1)).status()).isEqualTo(400);
    }

    @Test
    void concurrentRetriesWriteExactlyOnce() throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        List<Future<Response>> futures = new ArrayList<>();
        for (int i = 0; i < 16; i++) {
            futures.add(pool.submit(() -> write("writer", "burst-key-001", event(1))));
        }
        int created = 0;
        for (Future<Response> f : futures) {
            int status = f.get().status();
            assertThat(status).isIn(200, 201);
            created += status == 201 ? 1 : 0;
        }
        pool.shutdown();
        assertThat(created).isEqualTo(1);
        assertThat(verify().<Integer>get("recordsChecked")).isEqualTo(1);
    }
}
