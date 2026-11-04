package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** Incremental verify walks only the records after the last signed checkpoint. */
class IncrementalVerifyTest extends ApiTestBase {

    void checkpoint() throws Exception {
        assertThat(callAs("admin", MockMvcRequestBuilders.post("/v1/audit/checkpoints")
                .contentType(MediaType.APPLICATION_JSON)).status()).isEqualTo(200);
    }

    Response incremental() throws Exception {
        return get("/v1/audit/verify", "mode", "incremental");
    }

    @Test
    void checksOnlyRecordsAfterTheCheckpointAndAgreesWithFull() throws Exception {
        seed(20);
        checkpoint();
        seed(3);
        Response inc = incremental();
        assertThat(inc.<Boolean>get("valid")).isTrue();
        assertThat(inc.<Integer>get("headSeq")).isEqualTo(23);
        assertThat(verify().<String>get("headHash")).isEqualTo(inc.<String>get("headHash"));
    }

    @Test
    void tamperingAfterTheCheckpointIsCaught() throws Exception {
        seed(5);
        checkpoint();
        seed(3);
        tamper("UPDATE events SET actor_id = 'mallory' WHERE seq = 7");
        Response inc = incremental();
        assertThat(inc.<String>get("violation")).isEqualTo("HASH_MISMATCH");
        assertThat(inc.<Integer>get("firstInvalidSeq")).isEqualTo(7);
    }

    @Test
    void changingTheCheckpointedRecordOrTruncatingIsCaught() throws Exception {
        seed(5);
        checkpoint();
        tamper("DROP TRIGGER events_chain_immutable");
        tamper("UPDATE events SET hash = ? WHERE seq = 5", "b".repeat(64));
        assertThat(incremental().<String>get("violation")).isEqualTo("ANCHOR_MISMATCH");
        tamper("DROP TRIGGER events_no_delete");
        tamper("DELETE FROM events WHERE seq >= 4");
        assertThat(incremental().<String>get("violation")).isEqualTo("ANCHOR_MISMATCH");
    }

    @Test
    void olderRecordsAreLeftToTheFullVerify() throws Exception {
        seed(5);
        checkpoint();
        tamper("UPDATE events SET actor_id = 'mallory' WHERE seq = 2");   // before the checkpoint
        assertThat(incremental().<Boolean>get("valid")).isTrue();       // documented trade-off
        assertThat(verify().<String>get("violation")).isEqualTo("HASH_MISMATCH");   // full verify catches it
        assertThat(callAs("admin", MockMvcRequestBuilders.post("/v1/audit/checkpoints")
                .contentType(MediaType.APPLICATION_JSON)).status()).isEqualTo(409);  // never re-signed
    }

    @Test
    void worksAcrossRedactionsAndArchivedRecords() throws Exception {
        seed(3);
        archiveAfterSevenYears();                                       // seq 1-3 tombstoned, seq 4 event
        checkpoint();
        seed(2);                                                        // seq 5-6
        post("/v1/audit/events/5/redactions", java.util.Map.of("fields", java.util.List.of("accountNumber"), "reason", "erasure"));
        assertThat(incremental().<Boolean>get("valid")).isTrue();
    }

    @Test
    void withoutACheckpointItFallsBackToFull() throws Exception {
        seed(3);
        tamper("UPDATE events SET actor_id = 'x' WHERE seq = 1");
        assertThat(incremental().<String>get("violation")).isEqualTo("HASH_MISMATCH");
        assertThat(get("/v1/audit/verify", "mode", "bogus").status()).isEqualTo(400);
    }
}
