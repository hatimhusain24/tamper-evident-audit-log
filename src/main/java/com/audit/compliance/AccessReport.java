package com.audit.compliance;

import com.audit.chain.VerifyResult;
import java.util.List;
import java.util.Map;

/** Scenario C access report. {@code reportDigest} = SHA-256 of the canonical {@link Body}. */
public record AccessReport(Scope scope, String generatedAt, String generatedBy, VerifyResult integrity,
                           Summary summary, List<Long> exceptions, List<Access> accesses,
                           String reportDigest, EventRef reportEvent) {

    public record Scope(String resourceType, String accountId, String from, String to) {
    }

    public record Summary(int totalAccesses, int distinctActors, Map<String, Long> byAction,
                          Map<String, Long> byActor) {
    }

    /** Access metadata only: never payload contents (data minimization). */
    public record Access(long seq, String timestamp, String actorId, String recordedBy, String action,
                         String accountId, Object purpose, Object channel, String hash) {
    }

    public record EventRef(long seq, String hash) {
    }

    /** The part of the report that the digest covers. */
    record Body(Scope scope, String generatedAt, String generatedBy, VerifyResult integrity,
                Summary summary, List<Long> exceptions, List<Access> accesses) {
    }
}
