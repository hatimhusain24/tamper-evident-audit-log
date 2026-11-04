package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** High-impact endpoints need X-Admin-Key when audit.admin-key is configured. */
@TestPropertySource(properties = "audit.admin-key=s3cret")
class AdminKeyTest extends ApiTestBase {

    Response redact(String key) throws Exception {
        var request = MockMvcRequestBuilders.post("/audit/events/1/redactions").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("fields", List.of("n"), "reason", "abc", "requestedBy", "x")));
        if (key != null) {
            request.header("X-Admin-Key", key);
        }
        return call(request);
    }

    @Test
    void adminOperationsRequireTheKey() throws Exception {
        seed(1);
        assertThat(redact(null).status()).isEqualTo(401);
        assertThat(redact("wrong").status()).isEqualTo(401);
        assertThat(redact("s3cret").status()).isEqualTo(201);
        assertThat(call(MockMvcRequestBuilders.post("/audit/retention/run")).status()).isEqualTo(401);
        assertThat(get("/audit/reports/account-access", "requestedBy", "c").status()).isEqualTo(401);
    }

    @Test
    void ordinaryWritesAndReadsDoNotNeedTheKey() throws Exception {
        assertThat(seed(1).get(0).status()).isEqualTo(201);
        assertThat(get("/audit/events").status()).isEqualTo(200);
        assertThat(verify().status()).isEqualTo(200);
    }
}
