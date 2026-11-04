package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

/** Scenario B: retention archival never causes a false positive and cannot hide tampering. */
class RetentionTest extends ApiTestBase {

    Response archiveAll() throws Exception {
        return archiveAfterSevenYears();
    }

    @Test
    void defaultWindowKeepsRecentRecords() throws Exception {
        seed(3);
        Response res = call(org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post("/v1/audit/retention/run")
                .contentType(org.springframework.http.MediaType.APPLICATION_JSON));
        assertThat(res.<Integer>get("archivedCount")).isZero();      // 6-year default, no body needed
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

        assertThat(get("/v1/audit/events").items()).extracting(m -> m.get("seq")).containsExactly(4);
        post("/v1/audit/events", event(9));                                   // chain continues
        Response v = verify();
        assertThat(v.<Boolean>get("valid")).isTrue();
        assertThat(v.<Integer>get("recordsChecked")).isEqualTo(5);
    }

    @Test
    void repeatedRunsAndRedactedRecordsStayValid() throws Exception {
        seed(3);
        post("/v1/audit/events/1/redactions", Map.of("fields", List.of("accountNumber"), "reason", "erasure"));
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
        assertThat(post("/v1/audit/events/1/redactions", Map.of("fields", List.of("n"), "reason", "abc")).status()).isEqualTo(409);
    }

    @Test
    void negativeWindowIsRejected() throws Exception {
        assertThat(post("/v1/audit/retention/run", Map.of("olderThanDays", -1)).status()).isEqualTo(400);
    }

    @Test
    void windowBelowTheLegalMinimumIsRejected() throws Exception {
        seed(5);
        Response res = post("/v1/audit/retention/run", Map.of("olderThanDays", 0));
        assertThat(res.status()).isEqualTo(400);
        assertThat(res.<String>get("detail")).contains("2190");
        assertThat(get("/v1/audit/events").items()).hasSize(5);                // nothing purged
        assertThat(post("/v1/audit/retention/run", Map.of("olderThanDays", 2189.9)).status()).isEqualTo(400);
    }

    @Test
    void recordsYoungerThanTheMinimumAreNeverArchived() throws Exception {
        seed(3);
        clock.advanceDays(5 * 365);                                        // only 5 years later
        assertThat(post("/v1/audit/retention/run", Map.of("olderThanDays", 2190)).<Integer>get("archivedCount")).isZero();
    }

    @Test
    void untombstonedRecordIsReportedAsCorrupt() throws Exception {
        seed(2);
        archiveAll();
        tamper("UPDATE events SET archived = 0 WHERE seq = 1");            // content already purged
        Response v = verify();
        assertThat(v.<String>get("violation")).isEqualTo("CORRUPT_RECORD");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(1);
    }

    @Test
    void tamperingWithATombstoneIsDetected() throws Exception {
        seed(3);
        archiveAll();
        tamper("DROP TRIGGER events_chain_immutable");
        tamper("UPDATE events SET hash = ? WHERE seq = 2", "a".repeat(64));
        Response v = verify();
        // the MAC over the hash no longer matches, so it is caught at the edited tombstone itself
        assertThat(v.<String>get("violation")).isEqualTo("MAC_MISMATCH");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(2);
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
