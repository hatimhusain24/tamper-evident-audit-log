package com.audit.chain;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Streaming chain verifier: feed records in seq order with {@link #accept}, then read
 * {@link #result}. O(n) time; memory only for redacted fields, so it can walk any size of log.
 */
public final class ChainVerifier {

    private record SeqField(long seq, String field) {
    }

    private AuditRecord prev;
    private long checked;
    private long lastArchived;
    private long archivedThrough;
    private final List<SeqField> redacted = new ArrayList<>();
    private final Set<SeqField> authorized = new HashSet<>();
    private VerifyResult failure;
    private final double minRetentionDays;
    private final IntegrityKey key;
    private final Long anchorSeq;
    private final String anchorHash;
    private boolean anchorSeen;

    /** Hash-only verifier: no retention floor, no MAC key, no anchor (offline use, tests). */
    public ChainVerifier() {
        this(0, null, null, null);
    }

    /**
     * @param minRetentionDays archive runs below this window are policy violations
     * @param key              if set, every record's MAC must match (detects full rewrites)
     * @param anchorSeq        if set, the chain must still contain this seq with {@code anchorHash}
     *                         (detects truncation against an externally stored head)
     */
    public ChainVerifier(double minRetentionDays, IntegrityKey key, Long anchorSeq, String anchorHash) {
        this.minRetentionDays = minRetentionDays;
        this.key = key;
        this.anchorSeq = anchorSeq;
        this.anchorHash = anchorHash;
    }

    /**
     * Incremental mode: continue from a record already proven good (a signed checkpoint) instead
     * of from genesis, so only newer records are walked.
     */
    public ChainVerifier resumeFrom(AuditRecord anchor) {
        prev = anchor;
        checked = anchor.seq();
        if (anchor.archived()) {
            lastArchived = anchor.seq();
            archivedThrough = anchor.seq();
        }
        return this;
    }

    /** Returns false once a violation is found (the caller can stop reading). */
    public boolean accept(AuditRecord r) {
        if (failure != null) {
            return false;
        }
        Violation v = HashChain.safeCheck(r, prev == null ? HashChain.GENESIS_HASH : prev.hash(), checked + 1);
        if (v == null && key != null && !key.matches(r.hash(), r.mac())) {
            v = new Violation("MAC_MISMATCH", "record was not written by this service (bad, missing or unknown-key MAC)");
        }
        if (v == null && r.archived() && r.seq() != lastArchived + 1) {
            v = new Violation("UNAUTHORIZED_ARCHIVE", "tombstones must form a contiguous prefix of the chain");
        }
        if (v == null && anchorSeq != null && r.seq() == anchorSeq) {
            anchorSeen = true;
            if (!r.hash().equals(anchorHash)) {
                v = new Violation("ANCHOR_MISMATCH", "record at the anchored seq has a different hash (rewritten)");
            }
        }
        if (v != null) {
            failure = fail(r.seq(), v);
            return false;
        }
        if (r.archived()) {
            lastArchived = r.seq();
        } else {
            Map<String, Object> p = r.payload();
            p.keySet().stream().filter(k -> !r.salts().containsKey(k))
                    .forEach(k -> redacted.add(new SeqField(r.seq(), k)));
            if (HashChain.REDACTION_EVENT.equals(r.eventType())) {
                long target = ((Number) p.get("targetSeq")).longValue();
                ((List<?>) p.get("fields")).forEach(f -> authorized.add(new SeqField(target, (String) f)));
            } else if (HashChain.ARCHIVE_EVENT.equals(r.eventType())) {
                double window = ((Number) p.get("olderThanDays")).doubleValue();
                if (window < minRetentionDays) {
                    failure = fail(r.seq(), new Violation("RETENTION_POLICY_VIOLATION", "archive run used a "
                            + window + "-day window, below the " + minRetentionDays + "-day minimum"));
                    return false;
                }
                archivedThrough = Math.max(archivedThrough, ((Number) p.get("throughSeq")).longValue());
            }
        }
        prev = r;
        checked++;
        return true;
    }

    /** Destructive operations are legitimate only if a later chained event authorized them. */
    public VerifyResult result() {
        if (failure != null) {
            return failure;
        }
        for (SeqField sf : redacted) {
            if (!authorized.contains(sf)) {
                return fail(sf.seq(), new Violation("UNAUTHORIZED_REDACTION",
                        "field '" + sf.field() + "' redacted without a " + HashChain.REDACTION_EVENT + " event"));
            }
        }
        if (anchorSeq != null && !anchorSeen) {
            return fail(headSeq() + 1, new Violation("ANCHOR_MISMATCH", "chain ends at seq " + headSeq()
                    + ", before the anchored seq " + anchorSeq + " (records were removed from the end)"));
        }
        if (lastArchived > archivedThrough) {
            return fail(archivedThrough + 1, new Violation("UNAUTHORIZED_ARCHIVE", "records up to seq "
                    + lastArchived + " purged, policy authorized only up to " + archivedThrough));
        }
        return new VerifyResult(true, checked, headSeq(), headHash(), null, null, null);
    }

    private VerifyResult fail(long seq, Violation v) {
        return new VerifyResult(false, checked, headSeq(), headHash(), seq, v.type(), v.detail());
    }

    private long headSeq() {
        return prev == null ? 0 : prev.seq();
    }

    private String headHash() {
        return prev == null ? HashChain.GENESIS_HASH : prev.hash();
    }
}
