package com.audit.chain;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.TreeMap;

/**
 * Hash-chain core: pure functions, no I/O. Used by the service and by the offline verifier.
 *
 * <pre>
 * fieldHashes[k] = SHA-256( salt_k || canonical([k, payload[k]]) )
 * hash           = SHA-256( canonical({seq, timestamp, eventType, actorId, recordedBy,
 *                                      resourceType, resourceId, fieldHashes, prevHash}) )
 * </pre>
 *
 * The record hash covers a salted commitment of each payload field, not the raw value, so a
 * value can be redacted (value and salt deleted, commitment kept) without breaking the chain.
 * The random salt stops anyone guessing a redacted low-entropy value from its commitment.
 */
public final class HashChain {

    public static final String GENESIS_HASH = "0".repeat(64);
    public static final String REDACTED = "[REDACTED]";
    public static final String REDACTION_EVENT = "RECORD_REDACTED";
    public static final String ARCHIVE_EVENT = "RECORDS_ARCHIVED";
    public static final String REPORT_EVENT = "COMPLIANCE_REPORT_GENERATED";

    /** Event types only the service itself may write. */
    public static final java.util.Set<String> SYSTEM_EVENTS = java.util.Set.of(REDACTION_EVENT, ARCHIVE_EVENT, REPORT_EVENT);

    /** Canonical JSON: keys sorted at every level (maps and objects), no whitespace, UTF-8. */
    private static final ObjectMapper CANONICAL = JsonMapper.builder()
            .enable(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS)
            .enable(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY).build();
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final HexFormat HEX = HexFormat.of();

    private HashChain() {
    }

    public static byte[] canonical(Object value) {
        try {
            return CANONICAL.writeValueAsBytes(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException("value is not JSON-serializable", e);
        }
    }

    public static String sha256(byte[]... parts) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            for (byte[] part : parts) {
                digest.update(part);
            }
            return HEX.formatHex(digest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every JVM", e);
        }
    }

    public static String fieldHash(String salt, String key, Object value) {
        return sha256(HEX.parseHex(salt), canonical(Arrays.asList(key, value)));
    }

    public static String recordHash(AuditRecord r) {
        Map<String, Object> body = new TreeMap<>();
        body.put("seq", r.seq());
        body.put("timestamp", r.timestamp());
        body.put("eventType", r.eventType());
        body.put("actorId", r.actorId());
        body.put("recordedBy", r.recordedBy());
        body.put("resourceType", r.resourceType());
        body.put("resourceId", r.resourceId());
        body.put("fieldHashes", r.fieldHashes());
        body.put("prevHash", r.prevHash());
        return sha256(canonical(body));
    }

    /** Create a fully hashed record from validated event fields. */
    public static AuditRecord build(long seq, String prevHash, String timestamp, String eventType,
                                    String actorId, String recordedBy, String resourceType,
                                    String resourceId, Map<String, Object> payload) {
        Map<String, String> salts = new LinkedHashMap<>();
        Map<String, String> fieldHashes = new LinkedHashMap<>();
        payload.forEach((key, value) -> {
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            salts.put(key, HEX.formatHex(salt));
            fieldHashes.put(key, fieldHash(salts.get(key), key, value));
        });
        AuditRecord unsigned = new AuditRecord(seq, timestamp, eventType, actorId, recordedBy,
                resourceType, resourceId, payload, salts, fieldHashes, prevHash, null, false, null);
        return withHash(unsigned, recordHash(unsigned));
    }

    static AuditRecord withHash(AuditRecord r, String hash) {
        return new AuditRecord(r.seq(), r.timestamp(), r.eventType(), r.actorId(), r.recordedBy(),
                r.resourceType(), r.resourceId(), r.payload(), r.salts(), r.fieldHashes(), r.prevHash(), hash,
                r.archived(), r.mac());
    }

    public static AuditRecord withMac(AuditRecord r, String mac) {
        return new AuditRecord(r.seq(), r.timestamp(), r.eventType(), r.actorId(), r.recordedBy(),
                r.resourceType(), r.resourceId(), r.payload(), r.salts(), r.fieldHashes(), r.prevHash(), r.hash(),
                r.archived(), mac);
    }

    /** First problem found in one record, or null if the record is consistent. */
    public static Violation check(AuditRecord r, String prevHash, long expectedSeq) {
        if (r.seq() != expectedSeq) {
            return new Violation("SEQUENCE_GAP",
                    "expected seq " + expectedSeq + ", found " + r.seq() + " (deleted/inserted)");
        }
        if (!Objects.equals(r.prevHash(), prevHash)) {
            return new Violation("CHAIN_LINK_BROKEN",
                    "prevHash does not equal the previous record's hash");
        }
        if (r.archived()) {
            return null; // tombstone: content purged by retention; the link above is still checked
        }
        if (r.timestamp() == null || r.eventType() == null || r.actorId() == null || r.recordedBy() == null
                || r.resourceType() == null
                || r.resourceId() == null || r.payload() == null || r.salts() == null || r.fieldHashes() == null) {
            return new Violation("CORRUPT_RECORD", "a required column is missing or unreadable");
        }
        Map<String, Object> payload = r.payload();
        Map<String, String> salts = r.salts();
        if (!payload.keySet().equals(r.fieldHashes().keySet())) {
            return new Violation("PAYLOAD_TAMPERED", "payload fields were added or removed");
        }
        for (Map.Entry<String, Object> field : payload.entrySet()) {
            String key = field.getKey();
            if (salts.containsKey(key)) {
                if (!fieldHash(salts.get(key), key, field.getValue()).equals(r.fieldHashes().get(key))) {
                    return new Violation("PAYLOAD_TAMPERED", "payload field '" + key + "' was altered");
                }
            } else if (!REDACTED.equals(field.getValue())) {
                return new Violation("PAYLOAD_TAMPERED",
                        "payload field '" + key + "' has no salt but is not redacted");
            }
        }
        if (!Objects.equals(recordHash(r), r.hash())) {
            return new Violation("HASH_MISMATCH", "record content does not match its stored hash");
        }
        return null;
    }

    /**
     * Like {@link #check}, but never throws: a record that can't even be checked (wrong types,
     * missing salt values) is reported as CORRUPT_RECORD instead of crashing the verifier.
     */
    public static Violation safeCheck(AuditRecord r, String prevHash, long expectedSeq) {
        try {
            return check(r, prevHash, expectedSeq);
        } catch (RuntimeException e) {
            return new Violation("CORRUPT_RECORD", "record cannot be checked (" + e.getClass().getSimpleName() + ")");
        }
    }

    /** Verify a whole chain held in memory (tests, small chains). The service streams instead. */
    public static VerifyResult verify(Iterable<AuditRecord> records) {
        ChainVerifier verifier = new ChainVerifier();
        for (AuditRecord r : records) {
            if (!verifier.accept(r)) {
                break;
            }
        }
        return verifier.result();
    }

    /**
     * Independently verify an export bundle (no database or service needed). Proves every
     * record matches its own hash and commitments, and sits at its seq in a contiguous chain
     * segment ending at the head. Comparing headHash with a trusted checkpoint then proves the
     * records were not altered since export.
     */
    public static VerifyResult verifyBundle(Bundle bundle) {
        return verifyBundle(bundle, null);
    }

    /**
     * As {@link #verifyBundle(Bundle)}, and if {@code publicKey} is given, the bundle must also carry
     * a valid service signature: then no record can have been added, removed or changed since export.
     */
    public static VerifyResult verifyBundle(Bundle bundle, String publicKey) {
        if (publicKey != null && (bundle.head() == null
                || !SigningKey.verify(publicKey, bundle.signedBytes(), bundle.signature()))) {
            return new VerifyResult(false, 0, bundle.head() == null ? 0 : bundle.head().seq(), null, null,
                    "SIGNATURE_INVALID", "bundle is not signed by the service key, or was changed after export");
        }
        if (bundle.head() == null || bundle.chain() == null || bundle.records() == null) {
            return new VerifyResult(false, 0, 0, null, null, "MALFORMED_BUNDLE",
                    "bundle must contain head, chain and records");
        }
        var links = bundle.chain();
        for (int i = 1; i < links.size(); i++) {
            var prev = links.get(i - 1);
            var cur = links.get(i);
            if (cur.seq() != prev.seq() + 1 || !Objects.equals(cur.prevHash(), prev.hash())) {
                return bundleFailure(bundle, cur.seq(), new Violation("CHAIN_LINK_BROKEN",
                        "chain segment is not contiguous"));
            }
        }
        if (!links.isEmpty() && !links.get(links.size() - 1).equals(bundle.head())) {
            return bundleFailure(bundle, bundle.head().seq(), new Violation("HEAD_MISMATCH",
                    "segment does not end at the stated head"));
        }
        Map<Long, Bundle.Link> bySeq = new HashMap<>();
        links.forEach(link -> bySeq.put(link.seq(), link));
        for (AuditRecord r : bundle.records()) {
            Bundle.Link link = bySeq.get(r.seq());
            if (link == null || !Objects.equals(link.hash(), r.hash())) {
                return bundleFailure(bundle, r.seq(), new Violation("NOT_IN_CHAIN",
                        "record hash is not in the chain segment"));
            }
            Violation v = safeCheck(r, link.prevHash(), r.seq());
            if (v != null) {
                return bundleFailure(bundle, r.seq(), v);
            }
        }
        return new VerifyResult(true, bundle.records().size(), bundle.head().seq(),
                bundle.head().hash(), null, null, null);
    }

    private static VerifyResult bundleFailure(Bundle b, long seq, Violation v) {
        return new VerifyResult(false, 0, b.head().seq(), b.head().hash(), seq, v.type(), v.detail());
    }
}
