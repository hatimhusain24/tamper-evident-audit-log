package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.audit.chain.HashChain;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Scenario C acceptance criteria (docs/04_SCENARIO_C_COMPLIANCE.md, section 2). */
class ComplianceReportTest extends ApiTestBase {

    void access(String action, String actor, String account, String purpose) throws Exception {
        Map<String, Object> payload = new LinkedHashMap<>(Map.of("channel", "portal", "ssn", "123-45-6789"));
        if (purpose != null) {
            payload.put("purpose", purpose);
        }
        post("/v1/audit/events", Map.of("eventType", action, "actorId", actor, "resourceType", "CLIENT_ACCOUNT",
                "resourceId", account, "payload", payload));
    }

    void seedAccesses() throws Exception {
        access("ACCOUNT_VIEWED", "emp-1", "acc-1", "client call");
        access("ACCOUNT_UPDATED", "emp-2", "acc-1", "address change");
        access("ACCOUNT_VIEWED", "emp-1", "acc-2", "client call");
        access("ACCOUNT_EXPORTED", "emp-3", "acc-1", null);
        post("/v1/audit/events", Map.of("eventType", "USER_LOGIN", "actorId", "emp-1", "resourceType", "SESSION",
                "resourceId", "s1"));
    }

    /** POST a report as the compliance user; params are key/value pairs of the scope. */
    Response report(String... params) throws Exception {
        Map<String, Object> body = new HashMap<>();
        for (int i = 0; i < params.length; i += 2) {
            body.put(params[i], params[i + 1]);
        }
        return callAs("compliance", org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .post("/v1/audit/reports/account-access").contentType(org.springframework.http.MediaType.APPLICATION_JSON)
                .content(JSON.writeValueAsString(body)));
    }

    @Test
    void reportScopeSummaryAndExceptions() throws Exception {
        seedAccesses();
        Response r = report("accountId", "acc-1");
        assertThat(r.<List<Map<String, Object>>>get("accesses")).extracting(a -> a.get("seq")).containsExactly(1, 2, 4);
        assertThat(r.<Map<String, Object>>get("summary"))
                .containsEntry("totalAccesses", 3).containsEntry("distinctActors", 3)
                .containsEntry("byAction", Map.of("ACCOUNT_VIEWED", 1, "ACCOUNT_UPDATED", 1, "ACCOUNT_EXPORTED", 1));
        assertThat(r.<List<Object>>get("exceptions")).containsExactly(4);            // no stated purpose
        assertThat(r.body().toString()).doesNotContain("123-45-6789");                 // data minimization
        assertThat(r.<Map<String, Object>>get("integrity")).containsEntry("valid", true);
    }

    @Test
    void allAccountsAndTimeRange() throws Exception {
        seedAccesses();
        assertThat(report().<Map<String, Object>>get("summary")).containsEntry("totalAccesses", 4);
        var events = get("/v1/audit/events", "resourceType", "CLIENT_ACCOUNT").items();
        Response r = report("from", (String) events.get(1).get("timestamp"), "to", (String) events.get(3).get("timestamp"));
        assertThat(r.<List<Map<String, Object>>>get("accesses")).extracting(a -> a.get("seq")).containsExactly(2, 3);
    }

    @Test
    void unknownAccountGivesEmptyReport() throws Exception {
        seedAccesses();
        Response r = report("accountId", "acc-404");
        assertThat(r.<List<Object>>get("accesses")).isEmpty();
        assertThat(r.<Map<String, Object>>get("summary")).containsEntry("totalAccesses", 0);
    }

    @Test
    void reportGenerationIsChainedWithItsDigest() throws Exception {
        seedAccesses();
        Response r = report("accountId", "acc-1");
        Map<String, Object> body = new HashMap<>(r.body());
        body.remove("reportDigest");
        body.remove("reportEvent");
        assertThat(r.<String>get("reportDigest")).isEqualTo(HashChain.sha256(HashChain.canonical(body)));

        var logged = get("/v1/audit/events", "eventType", "COMPLIANCE_REPORT_GENERATED").items();
        assertThat(logged).hasSize(1);
        assertThat(logged.get(0)).containsEntry("actorId", "compliance").containsEntry("recordedBy", "compliance");
        @SuppressWarnings("unchecked")
        Map<String, Object> payload = (Map<String, Object>) logged.get(0).get("payload");
        assertThat(payload).containsEntry("reportDigest", r.get("reportDigest"));
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void reportFlagsATamperedLog() throws Exception {
        seedAccesses();
        tamper("UPDATE events SET actor_id = 'someone-else' WHERE seq = 2");
        Map<String, Object> integrity = report("accountId", "acc-1").get("integrity");
        assertThat(integrity).containsEntry("valid", false).containsEntry("firstInvalidSeq", 2);
    }

    @Test
    void reportIsGeneratedByTheAuthenticatedUserAndNeedsNoBody() throws Exception {
        seedAccesses();
        Response r = callAs("compliance", org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .post("/v1/audit/reports/account-access").contentType(org.springframework.http.MediaType.APPLICATION_JSON));
        assertThat(r.status()).isEqualTo(200);
        assertThat(r.<String>get("generatedBy")).isEqualTo("compliance");
    }

    @Test
    void reportIsNotAvailableAsAGet() throws Exception {
        assertThat(callAs("compliance", org.springframework.test.web.servlet.request.MockMvcRequestBuilders
                .get("/v1/audit/reports/account-access")).status()).isIn(403, 405);
    }
}
