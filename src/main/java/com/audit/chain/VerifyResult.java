package com.audit.chain;

/** Result of verifying a chain or an export bundle. On failure, headSeq/headHash = last good record. */
public record VerifyResult(
        boolean valid,
        long recordsChecked,
        long headSeq,
        String headHash,
        Long firstInvalidSeq,
        String violation,
        String detail) {
}
