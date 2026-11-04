package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Statement;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Failures in the middle of a write must leave no partial state, and a busy DB is a retryable 503. */
class FaultInjectionTest extends ApiTestBase {

    /** Test-only trigger that makes the INSERT of one event type fail, like a disk-full error. */
    void failInsertsOf(String eventType) {
        tamper("CREATE TRIGGER inject_fault BEFORE INSERT ON events WHEN NEW.event_type = '" + eventType + "' "
                + "BEGIN SELECT RAISE(ABORT, 'injected fault'); END");
    }

    @Test
    void redactionRollsBackWhenItsAuditEventCannotBeWritten() throws Exception {
        seed(2);
        String before = jdbc.queryForObject("SELECT payload FROM events WHERE seq = 2", String.class);
        failInsertsOf("RECORD_REDACTED");

        Response res = post("/v1/audit/events/2/redactions", Map.of("fields", List.of("accountNumber"), "reason", "erasure"));
        assertThat(res.status()).isEqualTo(500);
        assertThat(res.<String>get("detail")).isEqualTo("internal error");          // no internals leaked

        assertThat(jdbc.queryForObject("SELECT payload FROM events WHERE seq = 2", String.class)).isEqualTo(before);
        assertThat(verify().<Boolean>get("valid")).isTrue();                        // nothing half-done
        tamper("DROP TRIGGER inject_fault");
        assertThat(post("/v1/audit/events/2/redactions", Map.of("fields", List.of("accountNumber"), "reason", "erasure"))
                .status()).isEqualTo(201);                                          // retry succeeds
    }

    @Test
    void archiveRollsBackWhenItsAuditEventCannotBeWritten() throws Exception {
        seed(3);
        failInsertsOf("RECORDS_ARCHIVED");
        assertThat(archiveAfterSevenYears().status()).isEqualTo(500);
        assertThat(jdbc.queryForObject("SELECT COUNT(*) FROM events WHERE archived = 1", Integer.class)).isZero();
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void failedWriteDoesNotConsumeASequenceNumber() throws Exception {
        seed(1);
        failInsertsOf("RECORD_UPDATED");
        assertThat(post("/v1/audit/events", event(2)).status()).isEqualTo(500);
        tamper("DROP TRIGGER inject_fault");
        assertThat(post("/v1/audit/events", event(3)).<Integer>get("seq")).isEqualTo(2);  // no gap
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void writeWhileAnotherProcessHoldsTheLockIsARetryable503() throws Exception {
        seed(1);
        try (Connection other = DriverManager.getConnection("jdbc:sqlite:" + DB_DIR.resolve("audit.db"));
             Statement st = other.createStatement()) {
            st.execute("BEGIN IMMEDIATE");                                          // external writer
            var res = mvc.perform(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/v1/audit/events")
                    .contentType(org.springframework.http.MediaType.APPLICATION_JSON).content(JSON.writeValueAsString(event(2)))
                    .with(org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
                            .httpBasic("writer", PASSWORD))).andReturn().getResponse();
            assertThat(res.getStatus()).isEqualTo(503);
            assertThat(res.getHeader("Retry-After")).isEqualTo("1");
            st.execute("ROLLBACK");
        }
        assertThat(post("/v1/audit/events", event(2)).status()).isEqualTo(201);       // lock released
        assertThat(verify().<Integer>get("recordsChecked")).isEqualTo(2);
    }
}
