package com.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.audit.security.AuditSecurityProperties;
import com.audit.security.DevTokenCli;
import com.audit.security.SecurityConfig;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** OAuth2 resource server: only valid, short-lived tokens from the trusted issuer get in. */
class OAuth2JwtTest extends ApiTestBase {

    static final String ISSUER = "https://test-issuer.example";

    static String pem(String resource) throws Exception {
        return Files.readString(Path.of(OAuth2JwtTest.class.getResource("/" + resource).toURI()));
    }

    static String token(String sub, List<String> roles, List<String> scopes) throws Exception {
        return DevTokenCli.token(pem("test-jwt-private.pem"), sub, roles, scopes, 15, ISSUER, "audit-log");
    }

    /** A token with claims customised by the test, signed with the trusted test key. */
    static String customToken(Consumer<JWTClaimsSet.Builder> customise) throws Exception {
        Instant now = Instant.now();
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder().issuer(ISSUER).audience("audit-log").subject("svc")
                .issueTime(Date.from(now)).notBeforeTime(Date.from(now)).expirationTime(Date.from(now.plusSeconds(600)))
                .claim("roles", List.of("WRITER"));
        customise.accept(claims);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), claims.build());
        String body = pem("test-jwt-private.pem").replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
        PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
        jwt.sign(new RSASSASigner(key));
        return jwt.serialize();
    }

    MockHttpServletResponse send(String token, MockHttpServletRequestBuilder request) throws Exception {
        return mvc.perform(request.header("Authorization", "Bearer " + token)).andReturn().getResponse();
    }

    MockHttpServletRequestBuilder write(String resourceId) throws Exception {
        return MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "emp-1",
                        "resourceType", "CLIENT_ACCOUNT", "resourceId", resourceId)));
    }

    @Test
    void validTokenWritesAndTheSubjectBecomesRecordedBy() throws Exception {
        var res = send(token("ingest-service", List.of("WRITER"), List.of()), write("acc-1"));
        assertThat(res.getStatus()).isEqualTo(201);
        assertThat(JSON.readTree(res.getContentAsString()).get("recordedBy").asText()).isEqualTo("ingest-service");
    }

    @Test
    void rolesComeFromTheTokenClaim() throws Exception {
        assertThat(send(token("r", List.of("READER"), List.of("CLIENT_ACCOUNT:acc-1*")), write("acc-1")).getStatus())
                .isEqualTo(403);                                                    // READER can't write
        assertThat(send(token("x", List.of("SUPERUSER"), List.of()), write("acc-1")).getStatus()).isEqualTo(403);
    }

    @Test
    void resourceScopesComeFromTheTokenClaim() throws Exception {
        post("/v1/audit/events", Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "e", "resourceType", "CLIENT_ACCOUNT", "resourceId", "acc-1001"));
        post("/v1/audit/events", Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "e", "resourceType", "CLIENT_ACCOUNT", "resourceId", "acc-2001"));
        var res = send(token("alice", List.of("READER"), List.of("CLIENT_ACCOUNT:acc-1*")), MockMvcRequestBuilders.get("/v1/audit/events"));
        assertThat(res.getStatus()).isEqualTo(200);
        assertThat(res.getContentAsString()).contains("acc-1001").doesNotContain("acc-2001");
    }

    @Test
    void readerTokenWithoutScopesIsRefused() throws Exception {
        var res = send(token("bob", List.of("READER"), List.of()), MockMvcRequestBuilders.get("/v1/audit/events"));
        assertThat(res.getStatus()).isEqualTo(403);
        var malformed = send(token("bob", List.of("READER"), List.of("not-a-scope")), MockMvcRequestBuilders.get("/v1/audit/events"));
        assertThat(malformed.getStatus()).isEqualTo(403);
    }

    @Test
    void invalidTokensAreRejected() throws Exception {
        Instant now = Instant.now();
        Map<String, String> bad = Map.of(
                "expired", customToken(c -> c.issueTime(Date.from(now.minusSeconds(900))).notBeforeTime(Date.from(now.minusSeconds(900)))
                        .expirationTime(Date.from(now.minusSeconds(300)))),
                "not yet valid", customToken(c -> c.notBeforeTime(Date.from(now.plusSeconds(600))).expirationTime(Date.from(now.plusSeconds(1200)))),
                "wrong issuer", customToken(c -> c.issuer("https://evil.example")),
                "wrong audience", customToken(c -> c.audience("another-service")),
                "lifetime too long", customToken(c -> c.expirationTime(Date.from(now.plusSeconds(3 * 3600)))),
                "no expiry", customToken(c -> c.expirationTime(null)),
                "no issued-at, far expiry", customToken(c -> c.issueTime(null).expirationTime(Date.from(now.plusSeconds(10L * 365 * 86400)))),
                "garbage", "not.a.jwt");
        for (var entry : bad.entrySet()) {
            assertThat(send(entry.getValue(), write("acc-1")).getStatus()).as(entry.getKey()).isEqualTo(401);
        }
    }

    @Test
    void tokensSignedByAnyOtherKeyOrAlgorithmAreRejected() throws Exception {
        String otherKey = DevTokenCli.token(Files.readString(Path.of("config/dev-jwt/private-key.pem")),
                "svc", List.of("WRITER"), List.of(), 15, ISSUER, "audit-log");          // valid token, wrong key
        assertThat(send(otherKey, write("acc-1")).getStatus()).isEqualTo(401);

        JWTClaimsSet claims = new JWTClaimsSet.Builder().issuer(ISSUER).audience("audit-log").subject("svc")
                .issueTime(new Date()).expirationTime(new Date(System.currentTimeMillis() + 600_000))
                .claim("roles", List.of("WRITER")).build();
        SignedJWT hs256 = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);          // algorithm confusion
        hs256.sign(new MACSigner(pem("test-jwt-public.pem").getBytes(StandardCharsets.UTF_8)));
        assertThat(send(hs256.serialize(), write("acc-1")).getStatus()).isEqualTo(401);
        assertThat(send(new PlainJWT(claims).serialize(), write("acc-1")).getStatus()).isEqualTo(401);   // alg none
    }

    @Test
    void basicAndBearerBothWorkInBothMode() throws Exception {
        assertThat(callAs("writer", write("acc-1")).status()).isEqualTo(201);
        assertThat(send(token("svc", List.of("WRITER"), List.of()), write("acc-1")).getStatus()).isEqualTo(201);
    }

    @Test
    void expiredPasswordIsRejectedAndExpiryFollowsTheClock() throws Exception {
        assertThat(callAs("expired-user", write("acc-1")).status()).isEqualTo(401);
        assertThat(callAs("expiring-user", write("acc-1")).status()).isEqualTo(201);
        clock.set(Instant.parse("2099-01-02T00:00:00Z"));                      // the day after expiry
        assertThat(callAs("expiring-user", write("acc-1")).status()).isEqualTo(401);
    }

    @Test
    void devTokenToolPrintsAUsableToken() throws Exception {
        var out = new java.io.ByteArrayOutputStream();
        var original = System.out;
        System.setOut(new java.io.PrintStream(out, true, StandardCharsets.UTF_8));
        int code;
        try {
            code = DevTokenCli.run(new String[] {"issue-dev-token", "--key",
                    Path.of(OAuth2JwtTest.class.getResource("/test-jwt-private.pem").toURI()).toString(),
                    "--sub", "cli-user", "--roles", "WRITER", "--issuer", ISSUER});
        } finally {
            System.setOut(original);
        }
        assertThat(code).isZero();
        assertThat(send(out.toString(StandardCharsets.UTF_8).trim(), write("acc-1")).getStatus()).isEqualTo(201);
        assertThat(DevTokenCli.run(new String[] {"issue-dev-token", "--sub", "x"})).isEqualTo(2);   // missing key
    }

    // ---- fail-closed configuration --------------------------------------------------------

    @Test
    void jwtModeRefusesToStartWithoutIssuerOrKeySource() {
        var noIssuer = new AuditSecurityProperties.Jwt(null, "audit-log", null, "x", 60);
        var noKey = new AuditSecurityProperties.Jwt(ISSUER, "audit-log", null, null, 60);
        var badKey = new AuditSecurityProperties.Jwt(ISSUER, "audit-log", null, "not-a-key", 60);
        for (var jwt : List.of(noIssuer, noKey, badKey)) {
            assertThatThrownBy(() -> new SecurityConfig().filterChainCheck(new AuditSecurityProperties("jwt", null, jwt)))
                    .isInstanceOf(IllegalStateException.class);
        }
    }

    @Test
    void unknownAuthModeAndBasicWithoutUsersRefuseToStart() {
        assertThatThrownBy(() -> new AuditSecurityProperties("none", null, null).validate()).hasMessageContaining("jwt, basic or both");
        assertThatThrownBy(() -> new SecurityConfig().users(new AuditSecurityProperties("basic", List.of(), null),
                java.time.Clock.systemUTC())).hasMessageContaining("refuses to start");
        assertThat(new SecurityConfig().users(new AuditSecurityProperties("jwt", List.of(), null),
                java.time.Clock.systemUTC())).isNotNull();                          // token-only needs no users
    }
}
