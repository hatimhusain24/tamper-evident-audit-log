package com.audit.chain;

import java.util.List;

/**
 * Self-verifiable export: matching records plus the chain skeleton up to the head.
 * {@code signature} is an Ed25519 signature over the canonical bundle with signature = null, so a
 * recipient holding the service's public key can detect records added, removed or changed.
 */
public record Bundle(String format, String exportedAt, String algorithm,
                     List<AuditRecord> records, List<Link> chain, Link head, String signature) {

    /** The exact bytes that are signed. */
    public byte[] signedBytes() {
        return HashChain.canonical(withSignature(null));
    }

    public Bundle withSignature(String sig) {
        return new Bundle(format, exportedAt, algorithm, records, chain, head, sig);
    }

    /** One chain position without content: safe to share. */
    public record Link(long seq, String prevHash, String hash) {
    }
}
