package com.audit;

import com.audit.store.AuditStore;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

/** Full Spring context + real SQLite file. Each test starts from an empty log. */
@SpringBootTest
@AutoConfigureMockMvc
@Import(ApiTestBase.ClockConfig.class)
@ActiveProfiles("test")
public abstract class ApiTestBase {

    /** Every test user has this password (see application-test.properties). */
    protected static final String PASSWORD = "test-pass";

    /** Days that safely exceed the 6-year legal retention minimum. */
    protected static final long SEVEN_YEARS = 7 * 365;

    @TestConfiguration
    static class ClockConfig {
        @Bean
        @Primary
        TestClock testClock() {
            return new TestClock();
        }
    }

    protected static final Path DB_DIR;

    static {
        try {
            DB_DIR = Files.createTempDirectory("audit-test");
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @DynamicPropertySource
    static void database(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> "jdbc:sqlite:" + DB_DIR.resolve("audit.db")
                + "?journal_mode=WAL&busy_timeout=2000&secure_delete=true");
        registry.add("audit.checkpoint.file", () -> DB_DIR.resolve("checkpoints.jsonl").toString());
    }

    protected static final ObjectMapper JSON = new ObjectMapper();

    @Autowired protected MockMvc mvc;
    @Autowired protected JdbcTemplate jdbc;
    @Autowired protected AuditStore store;
    @Autowired protected TestClock clock;

    @BeforeEach
    void emptyLog() {
        clock.set(Instant.now());
        jdbc.execute("DROP TABLE IF EXISTS events");   // also drops the guardrail triggers
        jdbc.execute("DROP TABLE IF EXISTS idempotency_keys");
        try {
            Files.deleteIfExists(DB_DIR.resolve("checkpoints.jsonl"));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
        store.initSchema();
    }

    /** Raw SQL straight against the data store, bypassing the API (a malicious DB admin). */
    protected void tamper(String sql, Object... args) {
        jdbc.update(sql, args);
    }

    protected record Response(int status, Map<String, Object> body) {
        @SuppressWarnings("unchecked")
        public <T> T get(String key) {
            return (T) body.get(key);
        }

        @SuppressWarnings("unchecked")
        public List<Map<String, Object>> items() {
            return (List<Map<String, Object>>) body.get("items");
        }
    }

    /** Calls as "root", a test user holding every role, so functional tests focus on behaviour. */
    protected Response call(MockHttpServletRequestBuilder request) throws Exception {
        return callAs("root", request);
    }

    /** Calls as a given user; null means no credentials at all. */
    protected Response callAs(String user, MockHttpServletRequestBuilder request) throws Exception {
        if (user != null) {
            request.with(SecurityMockMvcRequestPostProcessors.httpBasic(user, PASSWORD));
        }
        MvcResult result = mvc.perform(request).andReturn();
        String text = result.getResponse().getContentAsString();
        @SuppressWarnings("unchecked")
        Map<String, Object> body = text.isEmpty() ? Map.of() : JSON.readValue(text, Map.class);
        return new Response(result.getResponse().getStatus(), body);
    }

    protected Response post(String path, Object body) throws Exception {
        return call(MockMvcRequestBuilders.post(path).contentType(MediaType.APPLICATION_JSON).content(JSON.writeValueAsString(body)));
    }

    protected Response get(String path, String... params) throws Exception {
        var request = MockMvcRequestBuilders.get(path);
        for (int i = 0; i < params.length; i += 2) {
            request.param(params[i], params[i + 1]);
        }
        return call(request);
    }

    protected static Map<String, Object> event(int i) {
        Map<String, Object> e = new LinkedHashMap<>();
        e.put("eventType", "RECORD_UPDATED");
        e.put("actorId", "user-" + (i % 2));
        e.put("resourceType", "ACCOUNT");
        e.put("resourceId", "acc-" + (i % 3));
        e.put("payload", new LinkedHashMap<>(Map.of("n", i, "accountNumber", String.format("99%04d", i))));
        return e;
    }

    protected List<Response> seed(int n) throws Exception {
        List<Response> out = new java.util.ArrayList<>();
        for (int i = 1; i <= n; i++) {
            out.add(post("/v1/audit/events", event(i)));
        }
        return out;
    }

    /** Move time past the legal minimum, then archive everything older than it. */
    protected Response archiveAfterSevenYears() throws Exception {
        clock.advanceDays(SEVEN_YEARS);
        return post("/v1/audit/retention/run", Map.of("olderThanDays", 2190));
    }

    protected Response verify() throws Exception {
        return get("/v1/audit/verify");
    }
}
