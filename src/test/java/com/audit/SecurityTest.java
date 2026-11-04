package com.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.audit.security.AuditSecurityProperties;
import com.audit.security.AuditSecurityProperties.ApiUser;
import com.audit.security.SecurityConfig;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** Endpoint x role x outcome matrix, spoofing attempts, PII masking and fail-closed startup. */
class SecurityTest extends ApiTestBase {

    static MockHttpServletRequestBuilder json(MockHttpServletRequestBuilder b, Object body) throws Exception {
        return b.contentType(MediaType.APPLICATION_JSON).content(JSON.writeValueAsString(body));
    }

    /** One valid request per protected endpoint (fresh builder each time). */
    static MockHttpServletRequestBuilder request(String endpoint) throws Exception {
        return switch (endpoint) {
            case "write" -> json(MockMvcRequestBuilders.post("/v1/audit/events"), event(1));
            case "query" -> MockMvcRequestBuilders.get("/v1/audit/events");
            case "verify" -> MockMvcRequestBuilders.get("/v1/audit/verify");
            case "export" -> MockMvcRequestBuilders.get("/v1/audit/export").param("actorId", "user-1");
            case "report" -> json(MockMvcRequestBuilders.post("/v1/audit/reports/account-access"), Map.of());
            case "redact" -> json(MockMvcRequestBuilders.post("/v1/audit/events/1/redactions"),
                    Map.of("fields", List.of("n"), "reason", "erasure"));
            case "retention" -> json(MockMvcRequestBuilders.post("/v1/audit/retention/run"), Map.of());
            default -> throw new IllegalArgumentException(endpoint);
        };
    }

    static final List<String> ENDPOINTS = List.of("write", "query", "verify", "export", "report", "redact", "retention");

    /** Who may call what. Anything not listed for a role must be 403. */
    static final Map<String, List<String>> ALLOWED = Map.of(
            "writer", List.of("write"),
            "reader", List.of("query", "verify"),
            "compliance", List.of("query", "verify", "export", "report"),
            "admin", List.of("query", "verify", "redact", "retention"));

    static Stream<Arguments> matrix() {
        return ALLOWED.keySet().stream().flatMap(user -> ENDPOINTS.stream()
                .map(endpoint -> Arguments.of(user, endpoint, ALLOWED.get(user).contains(endpoint))));
    }

    @ParameterizedTest(name = "{0} -> {1} allowed={2}")
    @MethodSource("matrix")
    void roleMatrixIsEnforced(String user, String endpoint, boolean allowed) throws Exception {
        seed(1);                                                     // record 1 exists for redact/export
        int status = callAs(user, request(endpoint)).status();
        if (allowed) {
            assertThat(status).as("%s on %s", user, endpoint).isBetween(200, 299);
        } else {
            assertThat(status).as("%s on %s", user, endpoint).isEqualTo(403);
        }
    }

    static Stream<String> endpoints() {
        return ENDPOINTS.stream();
    }

    @ParameterizedTest(name = "anonymous -> {0}")
    @MethodSource("endpoints")
    void everyProtectedEndpointRejectsAnonymousCallers(String endpoint) throws Exception {
        assertThat(callAs(null, request(endpoint)).status()).isEqualTo(401);
    }

    @Test
    void wrongPasswordAndUnknownUserAreRejected() throws Exception {
        var wrong = MockMvcRequestBuilders.get("/v1/audit/verify").with(
                org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                        .httpBasic("reader", "wrong-password"));
        assertThat(mvc.perform(wrong).andReturn().getResponse().getStatus()).isEqualTo(401);
        var unknown = MockMvcRequestBuilders.get("/v1/audit/verify").with(
                org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                        .httpBasic("mallory", PASSWORD));
        assertThat(mvc.perform(unknown).andReturn().getResponse().getStatus()).isEqualTo(401);
    }

    @Test
    void healthIsPublicWithoutDetailsAndUnknownPathsAreDenied() throws Exception {
        Response health = callAs(null, MockMvcRequestBuilders.get("/actuator/health"));
        assertThat(health.status()).isEqualTo(200);
        assertThat(health.<String>get("status")).isEqualTo("UP");
        assertThat(health.body()).doesNotContainKey("components");          // no internals leaked
        assertThat(callAs("admin", MockMvcRequestBuilders.get("/anything-else")).status()).isEqualTo(403);
    }

    @Test
    void unversionedPathsNoLongerExist() throws Exception {
        assertThat(callAs("admin", MockMvcRequestBuilders.get("/audit/verify")).status()).isIn(403, 404);
        assertThat(callAs("reader", MockMvcRequestBuilders.get("/v1/audit/verify")).status()).isEqualTo(200);
    }

    @Test
    void metricsAreAdminOnly() throws Exception {
        assertThat(callAs("reader", MockMvcRequestBuilders.get("/actuator/metrics")).status()).isEqualTo(403);
        assertThat(callAs("admin", MockMvcRequestBuilders.get("/actuator/metrics")).status()).isEqualTo(200);
    }

    @Test
    void swaggerIsOffByDefault() throws Exception {
        assertThat(callAs(null, MockMvcRequestBuilders.get("/v3/api-docs")).status()).isEqualTo(404);
    }

    @Test
    void tamperDetectionIsCountedForAlerting() throws Exception {
        seed(2);
        tamper("UPDATE events SET actor_id = 'x' WHERE seq = 1");
        verify();
        Response m = callAs("admin", MockMvcRequestBuilders.get("/actuator/metrics/audit.verify.failures"));
        assertThat(m.status()).isEqualTo(200);
    }

    @Test
    void recordedByIsTheAuthenticatedUserAndCannotBeSpoofed() throws Exception {
        Response r = callAs("writer", request("write"));
        assertThat(r.<String>get("recordedBy")).isEqualTo("writer");

        Map<String, Object> spoof = new java.util.LinkedHashMap<>(event(2));
        spoof.put("recordedBy", "system:retention");                      // not a request field
        assertThat(callAs("writer", json(MockMvcRequestBuilders.post("/v1/audit/events"), spoof)).status()).isEqualTo(400);
    }

    @Test
    void systemEventTypesCannotBeWrittenByCallers() throws Exception {
        for (String type : List.of("RECORD_REDACTED", "RECORDS_ARCHIVED", "COMPLIANCE_REPORT_GENERATED")) {
            Map<String, Object> e = new java.util.LinkedHashMap<>(event(1));
            e.put("eventType", type);
            assertThat(callAs("writer", json(MockMvcRequestBuilders.post("/v1/audit/events"), e)).status())
                    .as(type).isEqualTo(400);
        }
    }

    @Test
    void redactionAndRetentionAreAttributedToTheAdmin() throws Exception {
        seed(1);
        Response redaction = callAs("admin", request("redact"));
        assertThat(redaction.<String>get("actorId")).isEqualTo("admin");
        assertThat(redaction.<String>get("recordedBy")).isEqualTo("admin");
    }

    @Test
    void readersSeeSensitiveFieldsMaskedComplianceSeesThem() throws Exception {
        post("/v1/audit/events", Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "emp-1", "resourceType", "CLIENT_ACCOUNT",
                "resourceId", "acc-1", "payload", Map.of("ssn", "123-45-6789", "purpose", "call")));

        var asReader = callAs("reader", MockMvcRequestBuilders.get("/v1/audit/events")).items().get(0);
        assertThat(payloadOf(asReader)).containsEntry("ssn", "***").containsEntry("purpose", "call");
        var asCompliance = callAs("compliance", MockMvcRequestBuilders.get("/v1/audit/events")).items().get(0);
        assertThat(payloadOf(asCompliance)).containsEntry("ssn", "123-45-6789");
        assertThat(callAs("reader", MockMvcRequestBuilders.get("/v1/audit/verify")).<Boolean>get("valid")).isTrue();
    }

    @Test
    void crossSiteFormPostsAreRefused() throws Exception {
        seed(2);
        var form = MockMvcRequestBuilders.post("/v1/audit/retention/run")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED).content("olderThanDays=2190");
        assertThat(callAs("admin", form).status()).isEqualTo(415);
        var textPlain = MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.TEXT_PLAIN)
                .content(JSON.writeValueAsString(event(3)));
        assertThat(callAs("writer", textPlain).status()).isEqualTo(415);
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> payloadOf(Map<String, Object> record) {
        return (Map<String, Object>) record.get("payload");
    }

    @Test
    void httpsResponsesCarryHsts() throws Exception {
        var https = mvc.perform(MockMvcRequestBuilders.get("/actuator/health").secure(true)).andReturn().getResponse();
        assertThat(https.getHeader("Strict-Transport-Security")).contains("max-age=");
        var http = mvc.perform(MockMvcRequestBuilders.get("/actuator/health")).andReturn().getResponse();
        assertThat(http.getHeader("Strict-Transport-Security")).isNull();         // only over TLS, per spec
    }

    @Test
    void securityHeadersArePresent() throws Exception {
        var response = mvc.perform(MockMvcRequestBuilders.get("/actuator/health")).andReturn().getResponse();
        assertThat(response.getHeader("X-Content-Type-Options")).isEqualTo("nosniff");
        assertThat(response.getHeader("X-Frame-Options")).isEqualTo("DENY");
        assertThat(response.getHeader("Cache-Control")).contains("no-store");
    }

    // ---- fail-closed configuration (no Spring context needed) ----------------------------

    static AuditSecurityProperties users(ApiUser... users) {
        return new AuditSecurityProperties("basic", List.of(users), null);
    }

    @Test
    void refusesToStartWithoutUsers() {
        assertThatThrownBy(() -> new SecurityConfig().users(new AuditSecurityProperties("basic", List.of(), null), java.time.Clock.systemUTC()))
                .hasMessageContaining("refuses to start");
        assertThatThrownBy(() -> new SecurityConfig().users(new AuditSecurityProperties("basic", null, null), java.time.Clock.systemUTC()))
                .hasMessageContaining("refuses to start");
    }

    @Test
    void refusesPlaintextPasswordsAndUnknownRoles() {
        assertThatThrownBy(() -> new SecurityConfig().users(users(new ApiUser("u", "{noop}secret", List.of("READER"), null, null)), java.time.Clock.systemUTC()))
                .hasMessageContaining("bcrypt");
        assertThatThrownBy(() -> new SecurityConfig().users(users(new ApiUser("u", "{bcrypt}x", List.of("SUPERUSER"), null, null)), java.time.Clock.systemUTC()))
                .hasMessageContaining("unknown roles");
    }
}
