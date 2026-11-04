package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** Security events are JSON (ECS) log lines carrying the user and a request id. */
@ExtendWith(OutputCaptureExtension.class)
class StructuredLoggingTest extends ApiTestBase {

    JsonNode lineContaining(CapturedOutput output, String text) {
        return Arrays.stream(output.getOut().split("\\R"))
                .filter(l -> l.startsWith("{") && l.contains(text))
                .reduce((a, b) -> b)
                .map(l -> {
                    try {
                        return JSON.readTree(l);
                    } catch (Exception e) {
                        throw new AssertionError("log line is not JSON: " + l, e);
                    }
                })
                .orElseThrow(() -> new AssertionError("no JSON log line containing: " + text));
    }

    @Test
    void tamperAlertIsAJsonLineWithUserAndRequestId(CapturedOutput output) throws Exception {
        seed(2);
        tamper("UPDATE events SET actor_id = 'x' WHERE seq = 1");
        var response = mvc.perform(MockMvcRequestBuilders.get("/v1/audit/verify").with(
                org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                        .httpBasic("reader", PASSWORD))).andReturn().getResponse();

        JsonNode line = lineContaining(output, "chain verification failed");
        assertThat(line.at("/log/level").asText()).isEqualTo("ERROR");
        assertThat(line.at("/log/logger").asText()).isEqualTo("audit.security");
        assertThat(line.at("/user/name").asText()).isEqualTo("reader");
        assertThat(line.at("/request/id").asText()).isEqualTo(response.getHeader("X-Request-Id"));
    }

    @Test
    void failedLoginIsLoggedWithoutThePassword(CapturedOutput output) throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/v1/audit/verify").with(
                org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                        .httpBasic("admin", "my-secret-guess")));
        JsonNode line = lineContaining(output, "authentication failed");
        assertThat(line.at("/log/level").asText()).isEqualTo("WARN");
        assertThat(line.toString()).contains("user=admin").doesNotContain("my-secret-guess");
    }

    @Test
    void forgedNewlinesCannotFakeALogEntry(CapturedOutput output) throws Exception {
        mvc.perform(MockMvcRequestBuilders.get("/v1/audit/verify").with(
                org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                        .httpBasic("eve\nFAKE ENTRY", "x")));
        JsonNode line = lineContaining(output, "authentication failed");
        assertThat(line.at("/message").asText()).contains("eve_FAKE ENTRY");
        assertThat(output.getOut()).doesNotContain("\nFAKE ENTRY");
    }
}
