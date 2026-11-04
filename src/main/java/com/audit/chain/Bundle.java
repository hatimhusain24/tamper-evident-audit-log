package com.audit.chain;

import java.util.List;

/** Self-verifiable export: matching records plus the chain skeleton up to the head. */
public record Bundle(String format, String exportedAt, String algorithm,
                     List<AuditRecord> records, List<Link> chain, Link head) {

    /** One chain position without content: safe to share. */
    public record Link(long seq, String prevHash, String hash) {
    }
}
