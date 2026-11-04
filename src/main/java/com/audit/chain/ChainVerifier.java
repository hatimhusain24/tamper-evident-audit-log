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

    /** Returns false once a violation is found (the caller can stop reading). */
    public boolean accept(AuditRecord r) {
        if (failure != null) {
            return false;
        }
        Violation v = HashChain.safeCheck(r, prev == null ? HashChain.GENESIS_HASH : prev.hash(), checked + 1);
        if (v == null && r.archived() && r.seq() != lastArchived + 1) {
            v = new Violation("UNAUTHORIZED_ARCHIVE", "tombstones must form a contiguous prefix of the chain");
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
