package com.audit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.audit.chain.AuditRecord;
import com.audit.chain.ChainVerifier;
import com.audit.chain.HashChain;
import com.audit.chain.IntegrityKey;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;

/** Attacks a plain hash chain can't catch: full rewrite by a DB admin and tail truncation. */
class IntegrityKeyTest extends ApiTestBase {

    /** What a DB admin can do without the key: edit seq 2 and recompute every hash after it. */
    void rewriteChainFromSeq2() {
        List<AuditRecord> records = new ArrayList<>();
        store.streamChain(1, records::add);
        tamper("DROP TRIGGER events_chain_immutable");
        String prev = records.get(0).hash();
        for (AuditRecord r : records.subList(1, records.size())) {
            AuditRecord edited = new AuditRecord(r.seq(), r.timestamp(), r.eventType(),
                    r.seq() == 2 ? "mallory" : r.actorId(), r.recordedBy(), r.resourceType(), r.resourceId(),
                    r.payload(), r.salts(), r.fieldHashes(), prev, null, false, r.mac());
            String hash = HashChain.recordHash(edited);
            tamper("UPDATE events SET actor_id = ?, prev_hash = ?, hash = ? WHERE seq = ?",
                    edited.actorId(), prev, hash, r.seq());
            prev = hash;
        }
    }

    @Test
    void fullRewriteFoolsAPlainHashChainButNotTheMac() throws Exception {
        seed(4);
        rewriteChainFromSeq2();

        List<AuditRecord> rewritten = new ArrayList<>();
        store.streamChain(1, rewritten::add);
        assertThat(HashChain.verify(rewritten).valid()).isTrue();          // hashes alone: fooled

        Response v = verify();                                             // with the server key
        assertThat(v.<String>get("violation")).isEqualTo("MAC_MISMATCH");
        assertThat(v.<Integer>get("firstInvalidSeq")).isEqualTo(2);
    }

    @Test
    void tailTruncationIsCaughtByAnExternalAnchor() throws Exception {
        seed(5);
        Response head = verify();                                          // saved externally (WORM)
        String anchorSeq = String.valueOf(head.<Integer>get("headSeq"));
        String anchorHash = head.get("headHash");

        tamper("DROP TRIGGER events_no_delete");
        tamper("DELETE FROM events WHERE seq >= 4");
        assertThat(verify().<Boolean>get("valid")).isTrue();               // no anchor: undetectable

        Response anchored = get("/v1/audit/verify", "anchorSeq", anchorSeq, "anchorHash", anchorHash);
        assertThat(anchored.<Boolean>get("valid")).isFalse();
        assertThat(anchored.<String>get("violation")).isEqualTo("ANCHOR_MISMATCH");
        assertThat(anchored.<Integer>get("firstInvalidSeq")).isEqualTo(4);
    }

    @Test
    void matchingAnchorPassesAndAWrongAnchorHashFails() throws Exception {
        seed(3);
        Response head = verify();
        String seq = String.valueOf(head.<Integer>get("headSeq"));
        seed(2);                                                           // log keeps growing
        assertThat(get("/v1/audit/verify", "anchorSeq", seq, "anchorHash", head.get("headHash"))
                .<Boolean>get("valid")).isTrue();
        assertThat(get("/v1/audit/verify", "anchorSeq", seq, "anchorHash", "a".repeat(64))
                .<String>get("violation")).isEqualTo("ANCHOR_MISMATCH");
    }

    @Test
    void anchorParametersAreValidated() throws Exception {
        assertThat(get("/v1/audit/verify", "anchorSeq", "3").status()).isEqualTo(400);
        assertThat(get("/v1/audit/verify", "anchorSeq", "3", "anchorHash", "not-a-hash").status()).isEqualTo(400);
        assertThat(get("/v1/audit/verify", "anchorSeq", "0", "anchorHash", "a".repeat(64)).status()).isEqualTo(400);
    }

    @Test
    void archivedRecordsKeepTheirMac() throws Exception {
        seed(3);
        archiveAfterSevenYears();
        assertThat(verify().<Boolean>get("valid")).isTrue();
    }

    @Test
    void serviceRefusesAMissingOrShortKey() {
        assertThatThrownBy(() -> IntegrityKey.of(null)).hasMessageContaining("refuses to start");
        assertThatThrownBy(() -> IntegrityKey.of("too-short")).hasMessageContaining("at least 32 bytes");
        assertThat(IntegrityKey.of("x".repeat(32)).mac("abc")).hasSize(64);
    }

    @Test
    void verifierWithoutKeySkipsMacsSoOfflineBundlesStillWork() {
        AuditRecord r = HashChain.build(1, HashChain.GENESIS_HASH, "t", "X_Y", "a", "svc", "r", "1", java.util.Map.of());
        ChainVerifier keyless = new ChainVerifier();
        keyless.accept(r);
        assertThat(keyless.result().valid()).isTrue();
        ChainVerifier keyed = new ChainVerifier(0, IntegrityKey.of("k".repeat(32)), null, null);
        keyed.accept(r);                                                   // r has no MAC
        assertThat(keyed.result().violation()).isEqualTo("MAC_MISMATCH");
    }
}
