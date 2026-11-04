package com.audit;

import static org.assertj.core.api.Assertions.assertThat;

import com.audit.chain.SigningKey;
import com.audit.store.CheckpointService;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

/** Signed checkpoints make tail truncation visible to a plain verify call. */
class CheckpointTest extends ApiTestBase {

    @Autowired CheckpointService checkpoints;

    Path file() {
        return DB_DIR.resolve("checkpoints.jsonl");
    }

    Response checkpointNow() throws Exception {
        return callAs("admin", MockMvcRequestBuilders.post("/v1/audit/checkpoints").contentType(MediaType.APPLICATION_JSON));
    }

    @Test
    void checkpointIsSignedAndVerifiableOffline() throws Exception {
        seed(3);
        Response c = checkpointNow();
        assertThat(c.status()).isEqualTo(200);
        assertThat(c.<Integer>get("seq")).isEqualTo(3);
        String publicKey = callAs(null, MockMvcRequestBuilders.get("/v1/audit/signing-key")).get("publicKey");
        var cp = new CheckpointService.Checkpoint(3, c.get("hash"), c.get("createdAt"), c.get("signature"));
        assertThat(checkpoints.isAuthentic(cp)).isTrue();
        assertThat(SigningKey.verify(publicKey, new byte[] {1}, cp.signature())).isFalse();
    }

    @Test
    void truncationAfterACheckpointIsCaughtByAPlainVerify() throws Exception {
        seed(5);
        checkpointNow();
        tamper("DROP TRIGGER events_no_delete");
        tamper("DELETE FROM events WHERE seq >= 4");
        Response v = verify();                                             // no anchor parameters
        assertThat(v.<Boolean>get("valid")).isFalse();
        assertThat(v.<String>get("violation")).isEqualTo("ANCHOR_MISMATCH");
    }

    @Test
    void logKeepsGrowingAfterACheckpoint() throws Exception {
        seed(2);
        checkpointNow();
        seed(3);
        assertThat(verify().<Boolean>get("valid")).isTrue();
        assertThat(checkpointNow().<Integer>get("seq")).isEqualTo(5);
        assertThat(Files.readAllLines(file())).hasSize(2);
    }

    @Test
    void unchangedHeadDoesNotWriteADuplicate() throws Exception {
        seed(2);
        checkpointNow();
        checkpointNow();
        assertThat(Files.readAllLines(file())).hasSize(1);
    }

    @Test
    void editedCheckpointFileIsDetected() throws Exception {
        seed(5);
        checkpointNow();
        List<String> lines = Files.readAllLines(file());
        Files.writeString(file(), lines.get(0).replace("\"seq\":5", "\"seq\":3"));   // attacker lowers the anchor
        assertThat(verify().<String>get("violation")).isEqualTo("CHECKPOINT_INVALID");
        Files.writeString(file(), "{not json");
        assertThat(verify().<String>get("violation")).isEqualTo("CHECKPOINT_INVALID");
    }

    @Test
    void brokenOrEmptyChainIsNeverCheckpointed() throws Exception {
        assertThat(checkpointNow().status()).isEqualTo(409);               // empty log
        seed(2);
        tamper("UPDATE events SET actor_id = 'x' WHERE seq = 1");
        assertThat(checkpointNow().status()).isEqualTo(409);               // fails verification
        assertThat(Files.exists(file())).isFalse();
    }

    @Test
    void onlyAdminsCanForceACheckpoint() throws Exception {
        seed(1);
        assertThat(callAs("reader", MockMvcRequestBuilders.post("/v1/audit/checkpoints")
                .contentType(MediaType.APPLICATION_JSON)).status()).isEqualTo(403);
    }

    @Test
    void scheduledRunWritesWhenTheHeadMoves() throws Exception {
        seed(2);
        assertThat(checkpoints.checkpoint()).isPresent();                  // what the scheduler calls
        assertThat(checkpoints.latest().orElseThrow().seq()).isEqualTo(2);
    }
}
