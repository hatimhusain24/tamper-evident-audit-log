package com.audit.chain;

/** A typed integrity violation, e.g. HASH_MISMATCH, with a human-readable detail. */
public record Violation(String type, String detail) {
}
