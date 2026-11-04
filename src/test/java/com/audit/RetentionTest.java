package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Scenario B: retention archival never causes a false positive and cannot hide tampering. */
class RetentionTest extends ApiTestBase {

    Response archiveAll() throws Exception {
        return post("/audit/retention/run", Map.of("olderThanDays", 0, "requestedBy", "ops-1"));
    }

    @Test
    void defaultWindowKeepsRecentRecords() throws Exception {
        seed(3);
        Response res = call(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/audit/retention/run"));
        assertThat(res.<Integer>get("archivedCount")).isZero();      // 365-day default, no body needed
        assertThat(res.body().get("event")).isNull();
    }

    @Test
    void emptyLogArchivesNothing() throws Exception {
        assertThat(archiveAll().<Integer>get("archivedCount")).isZero();
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void archivedRecordsVerifyAndDisappearFromQueries() throws Exception {
        seed(3);
        Response res = archiveAll();
        assertThat(res.<Integer>get("archivedCount")).isEqualTo(3);
        assertThat(res.<Integer>get("throughSeq")).isEqualTo(3);
        @SuppressWarnings("unchecked")
        Map<String, Object> event = (Map<String, Object>) res.body().get("event");
        assertThat(event).containsEntry("eventType", "RECORDS_ARCHIVED").containsEntry("seq", 4);

        assertThat(get("/audit/events").items()).extracting(m -> m.get("seq")).containsExactly(4);
        post("/audit/events", event(9));                                   // chain continues
        Response v = verify();
        assertThat(v.<Boolean>get("valid")).isTrue();
        assertThat(v.<Integer>get("recordsChecked")).isEqualTo(5);
    }

    @Test
    void repeatedRunsAndRedactedRecordsStayValid() throws Exception {
        seed(3);
        post("/audit/events/1/redactions", Map.of("fields", List.of("accountNumber"), "reason", "erasure",
                "requestedBy", "dpo"));
        archiveAll();
        seed(2);
        archiveAll();
        // the previous RECORDS_ARCHIVED event is now old enough to archive too; the newest one covers it
        assertThat(archiveAll().<Integer>get("archivedCount")).isEqualTo(1);
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void archivedRecordCannotBeRedacted() throws Exception {
        seed(2);
        archiveAll();
        assertThat(post("/audit/events/1/redactions", Map.of("fields", List.of("n"), "reason", "abc",
                "requestedBy", "x")).status()).isEqualTo(409);
    }

    @Test
    void negativeWindowIsRejected() throws Exception {
        assertThat(post("/audit/retention/run", Map.of("olderThanDays", -1)).status()).isEqualTo(400);
    }

    @Test
    void tamperingWithATombstoneIsDetected() throws Exception {
        seed(3);
        archiveAll();
        tamper("DROP TRIGGER events_chain_immutable");
        tamper("UPDATE events SET hash = ? WHERE seq = 2", "a".repeat(64));
        Response v = verify();
        assertThat(v.<String>get("violation")).isEqualTo("CHAIN_LINK_BROKEN");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(3);
    }

    @Test
    void tombstoneOutsidePolicyIsDetected() throws Exception {
        seed(2);
        archiveAll();                 // authorizes seq 1-2; seq 3 = RECORDS_ARCHIVED
        seed(2);                      // seq 4-5
        tamper("UPDATE events SET archived = 1, payload = NULL WHERE seq IN (4, 5)");
        Response v = verify();
        assertThat(v.<String>get("violation")).isEqualTo("UNAUTHORIZED_ARCHIVE");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(4);
    }

    @Test
    void hidingTheAuthorizingEventFlagsTheWholePrefix() throws Exception {
        seed(2);
        archiveAll();
        tamper("UPDATE events SET archived = 1, payload = NULL WHERE seq = 3");
        Response v = verify();
        // the authorizing event was destroyed, so no tombstone can be proven legitimate
        assertThat(v.<String>get("violation")).isEqualTo("UNAUTHORIZED_ARCHIVE");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(1);
    }
}
