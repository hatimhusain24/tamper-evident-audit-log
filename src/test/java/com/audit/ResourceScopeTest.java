package com.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.audit.security.AuditSecurityProperties;
import com.audit.security.AuditSecurityProperties.ApiUser;
import com.audit.security.SecurityConfig;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** Object-level authorization: a user only reaches the resources in their scope (no IDOR / BOLA). */
class ResourceScopeTest extends ApiTestBase {

    void account(String id) throws Exception {
        post("/v1/audit/events", Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "emp-1", "resourceType", "CLIENT_ACCOUNT",
                "resourceId", id, "payload", Map.of("purpose", "call")));
    }

    @BeforeEach
    void seedAccounts() throws Exception {
        account("acc-1001");   // seq 1: in reader scope (acc-1*)
        account("acc-2001");   // seq 2: another client
        account("acc-1002");   // seq 3: in scope
        account("acc_1");      // seq 4: literal underscore id
        account("accX1");      // seq 5: must not match the pattern acc_1
    }

    List<Object> seqsSeenBy(String user, String... params) throws Exception {
        var request = MockMvcRequestBuilders.get("/v1/audit/events");
        for (int i = 0; i < params.length; i += 2) {
            request.param(params[i], params[i + 1]);
        }
        List<Object> seqs = new ArrayList<>();
        callAs(user, request).items().forEach(m -> seqs.add(m.get("seq")));
        return seqs;
    }

    @Test
    void readerOnlySeesAccountsInScope() throws Exception {
        assertThat(seqsSeenBy("reader")).containsExactly(1, 3);
        assertThat(seqsSeenBy("root")).containsExactly(1, 2, 3, 4, 5);          // unrestricted
    }

    @Test
    void askingForAnotherClientsAccountReturnsNothing() throws Exception {
        assertThat(seqsSeenBy("reader", "resourceId", "acc-2001")).isEmpty();
        assertThat(seqsSeenBy("reader", "resourceType", "CLIENT_ACCOUNT", "resourceId", "acc-2001")).isEmpty();
        assertThat(seqsSeenBy("reader", "resourceId", "acc-1001")).containsExactly(1);
    }

    @Test
    void paginationStaysCorrectInsideTheScope() throws Exception {
        Response first = callAs("reader", MockMvcRequestBuilders.get("/v1/audit/events").param("limit", "1"));
        assertThat(first.items()).extracting(m -> m.get("seq")).containsExactly(1);
        Response second = callAs("reader", MockMvcRequestBuilders.get("/v1/audit/events").param("limit", "1")
                .param("cursor", String.valueOf(first.<Integer>get("nextCursor"))));
        assertThat(second.items()).extracting(m -> m.get("seq")).containsExactly(3);   // skips acc-2001
        assertThat(second.body().get("nextCursor")).isNull();
    }

    @Test
    void likeWildcardsInIdsAreMatchedLiterally() throws Exception {
        assertThat(seqsSeenBy("reader-exact")).containsExactly(4);              // acc_1 only, not accX1
    }

    @Test
    void scopedWriterCannotWriteForOtherResources() throws Exception {
        var inScope = MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "e",
                        "resourceType", "CLIENT_ACCOUNT", "resourceId", "acc-1999")));
        assertThat(callAs("writer-acc1", inScope).status()).isEqualTo(201);
        var outOfScope = MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("eventType", "ACCOUNT_VIEWED", "actorId", "e",
                        "resourceType", "CLIENT_ACCOUNT", "resourceId", "acc-2999")));
        assertThat(callAs("writer-acc1", outOfScope).status()).isEqualTo(403);
        var otherType = MockMvcRequestBuilders.post("/v1/audit/events").contentType(MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(Map.of("eventType", "LOGIN", "actorId", "e",
                        "resourceType", "SESSION", "resourceId", "acc-1")));
        assertThat(callAs("writer-acc1", otherType).status()).isEqualTo(403);
    }

    @Test
    void scopedUsersCannotRunBulkOperations() throws Exception {
        assertThat(callAs("compliance-acc1", MockMvcRequestBuilders.get("/v1/audit/export").param("actorId", "emp-1"))
                .status()).isEqualTo(403);
        assertThat(callAs("compliance-acc1", MockMvcRequestBuilders.post("/v1/audit/reports/account-access")
                .contentType(MediaType.APPLICATION_JSON)).status()).isEqualTo(403);
        assertThat(callAs("compliance", MockMvcRequestBuilders.get("/v1/audit/export").param("actorId", "emp-1"))
                .status()).isEqualTo(200);                                       // unscoped compliance still can
    }

    @Test
    void scopedReaderCanStillVerifyTheChain() throws Exception {
        Response v = callAs("reader", MockMvcRequestBuilders.get("/v1/audit/verify"));
        assertThat(v.<Boolean>get("valid")).isTrue();                           // no record contents revealed
    }

    @Test
    void readersMustDeclareScopesAndPatternsAreValidated() {
        String hash = "{bcrypt}$2a$04$0sIXKTA2vcYfH6SMwIU1R.KjAtxZC.hpo3KnQRJg9yhAqFl7mFy9m";
        SecurityConfig config = new SecurityConfig();
        assertThatThrownBy(() -> config.users(new AuditSecurityProperties(
                List.of(new ApiUser("r", hash, List.of("READER"), null))))).hasMessageContaining("resource-scopes");
        assertThat(config.users(new AuditSecurityProperties(
                List.of(new ApiUser("c", hash, List.of("COMPLIANCE"), null))))).isNotNull();   // unscoped allowed
        for (String bad : List.of("noColon", "TYPE:", ":id", "TY*PE:id", "TYPE:a*b")) {
            assertThatThrownBy(() -> config.resourceScopes(new AuditSecurityProperties(
                    List.of(new ApiUser("u", hash, List.of("WRITER"), List.of(bad)))))).as(bad)
                    .hasMessageContaining("TYPE:ID");
        }
        var scopes = config.resourceScopes(new AuditSecurityProperties(
                List.of(new ApiUser("u", hash, List.of("WRITER"), List.of("*:acc-*", "SESSION:s1")))));
        assertThat(scopes.allows("u", "ANYTHING", "acc-9")).isTrue();
        assertThat(scopes.allows("u", "SESSION", "s1")).isTrue();
        assertThat(scopes.allows("u", "SESSION", "s2")).isFalse();
        assertThat(scopes.allows("unknown-user", "X", "y")).isTrue();            // not configured = unrestricted
    }
}
