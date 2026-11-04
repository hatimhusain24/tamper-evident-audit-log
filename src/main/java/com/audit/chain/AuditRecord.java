package com.audit.chain;

import java.util.Map;

/**
 * One stored audit record. {@code salts} and {@code fieldHashes} are the per-field payload
 * commitments; a field with no salt is a redacted field. Archived records (tombstones) have
 * their content set to null but keep seq, timestamp, prevHash and hash.
 */
public record AuditRecord(
        long seq,
        String timestamp,
        String eventType,
        String actorId,
        String resourceType,
        String resourceId,
        Map<String, Object> payload,
        Map<String, String> salts,
        Map<String, String> fieldHashes,
        String prevHash,
        String hash,
        boolean archived) {
}
