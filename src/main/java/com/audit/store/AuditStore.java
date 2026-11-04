package com.audit.store;

import com.audit.chain.AuditRecord;
import com.audit.chain.Bundle;
import com.audit.chain.ChainVerifier;
import com.audit.chain.HashChain;
import com.audit.chain.IntegrityKey;
import com.audit.chain.VerifyResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.locks.ReentrantLock;
import java.util.function.Predicate;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.ResultSetExtractor;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * SQLite persistence: the only class that touches the database.
 *
 * <ul>
 *   <li>Sensitive payload fields are AES-GCM encrypted before they reach the database
 *       ({@link FieldCipher}); hashes cover the plaintext.</li>
 *   <li>Writes are serialized: an in-process lock, then the SQLite write lock taken by the first
 *       statement of every write transaction, so the chain head never forks (even across processes).
 *       If another process holds the lock past busy_timeout the transaction rolls back cleanly and
 *       the API answers 503 (retryable).</li>
 *   <li>Reads run as single statements. In WAL mode each sees a consistent snapshot and never
 *       blocks the writer, so verify/export can stream the whole chain.</li>
 *   <li>Triggers block DELETE and edits to chain columns: a guardrail against application bugs,
 *       not a security boundary. The hash chain is what detects tampering by a DB admin.</li>
 * </ul>
 */
@Component
public final class AuditStore {

    /** Requested record does not exist (HTTP 404). */
    public static final class NotFound extends RuntimeException {
        public NotFound(String message) {
            super(message);
        }
    }

    /** Operation not allowed in the record's current state (HTTP 409). */
    public static final class Conflict extends RuntimeException {
        public Conflict(String message) {
            super(message);
        }
    }

    /** Request breaks a data policy, e.g. retention below the legal minimum (HTTP 400). */
    public static final class PolicyViolation extends RuntimeException {
        public PolicyViolation(String message) {
            super(message);
        }
    }

    public record Page(List<AuditRecord> items, Long nextCursor) {
    }

    /** replayed = true when an earlier request with the same idempotency key already wrote it. */
    public record Appended(AuditRecord record, boolean replayed) {
    }

    public record RetentionResult(long archivedCount, Long throughSeq, AuditRecord event) {
    }

    private record Head(long seq, String hash, String timestamp) {
    }

    private static final List<String> SCHEMA = List.of("""
            CREATE TABLE IF NOT EXISTS events (
                seq           INTEGER PRIMARY KEY,
                timestamp     TEXT    NOT NULL,
                event_type    TEXT,
                actor_id      TEXT,
                recorded_by   TEXT,             -- authenticated submitter, inside the hash
                resource_type TEXT,
                resource_id   TEXT,
                payload       TEXT,             -- JSON object; redacted fields hold "[REDACTED]"
                salts         TEXT,             -- JSON {field: salt}; a missing salt = redacted field
                field_hashes  TEXT,             -- JSON {field: commitment}
                prev_hash     TEXT    NOT NULL,
                hash          TEXT    NOT NULL,
                archived      INTEGER NOT NULL DEFAULT 0,
                mac           TEXT    NOT NULL   -- "keyId:" + HMAC-SHA256(server key, hash)
            )""",
            """
            CREATE TABLE IF NOT EXISTS idempotency_keys (
                key          TEXT PRIMARY KEY,   -- "<principal>:<Idempotency-Key header>"
                request_hash TEXT NOT NULL,      -- SHA-256 of the canonical request
                seq          INTEGER NOT NULL
            )""",
            "CREATE INDEX IF NOT EXISTS ix_actor ON events(actor_id, seq)",
            "CREATE INDEX IF NOT EXISTS ix_resource ON events(resource_type, resource_id, seq)",
            "CREATE INDEX IF NOT EXISTS ix_type ON events(event_type, seq)",
            "CREATE INDEX IF NOT EXISTS ix_time ON events(timestamp)",
            """
            CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
            BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END""",
            """
            CREATE TRIGGER IF NOT EXISTS events_chain_immutable
            BEFORE UPDATE OF seq, timestamp, prev_hash, hash, mac ON events
            BEGIN SELECT RAISE(ABORT, 'chain columns are immutable'); END""");

    private static final String COLUMNS = "seq, timestamp, event_type, actor_id, recorded_by, "
            + "resource_type, resource_id, payload, salts, field_hashes, prev_hash, hash, archived, mac";
    private static final String SELECT = "SELECT " + COLUMNS + " FROM events";
    private static final Map<String, String> FILTERS = Map.of(   // API name -> column (whitelist)
            "actorId", "actor_id", "resourceType", "resource_type",
            "resourceId", "resource_id", "eventType", "event_type");
    private static final DateTimeFormatter ISO =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSSSS'Z'").withZone(ZoneOffset.UTC);
    private static final TypeReference<Map<String, Object>> OBJECT_MAP = new TypeReference<>() { };
    private static final TypeReference<Map<String, String>> STRING_MAP = new TypeReference<>() { };

    private final JdbcTemplate jdbc;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final ObjectMapper json = new ObjectMapper();
    private final ReentrantLock writeLock = new ReentrantLock();
    private final double retentionMinDays;
    private final IntegrityKey key;
    private final FieldCipher cipher;

    public AuditStore(DataSource dataSource, Clock clock,
                      @Value("${audit.retention-min-days:2190}") double retentionMinDays,
                      IntegrityKey key, FieldCipher cipher) {
        this.key = key;
        this.cipher = cipher;
        this.jdbc = new JdbcTemplate(dataSource);
        this.tx = new TransactionTemplate(new DataSourceTransactionManager(dataSource));
        this.clock = clock;
        this.retentionMinDays = retentionMinDays;
        initSchema();
    }

    public double retentionMinDays() {
        return retentionMinDays;
    }

    public void initSchema() {
        SCHEMA.forEach(jdbc::execute);
    }

    /** Fixed-width UTC ISO-8601, so text order equals time order in SQL. */
    public static String iso(Instant instant) {
        return ISO.format(instant);
    }

    // ---- writes ---------------------------------------------------------------------------

    private <T> T write(Supplier<T> operation) {
        writeLock.lock();
        try {
            return tx.execute(status -> {
                // A no-op write takes SQLite's write lock before we read the head (waits up to
                // busy_timeout). Unlike BEGIN IMMEDIATE, a timeout here leaves the pooled
                // connection healthy: the transaction simply rolls back.
                jdbc.update("UPDATE idempotency_keys SET seq = seq WHERE 0");
                return operation.get();
            });
        } finally {
            writeLock.unlock();
        }
    }

    public AuditRecord append(String eventType, String actorId, String recordedBy, String resourceType,
                              String resourceId, Map<String, Object> payload) {
        return write(() -> appendInTx(eventType, actorId, recordedBy, resourceType, resourceId, payload));
    }

    /**
     * Append at most once per key: a retry with the same key and request returns the original
     * record; the same key with a different request is a conflict. Checked and written in the
     * same transaction as the append, so concurrent retries can't both write.
     */
    public Appended appendOnce(String idempotencyKey, String eventType, String actorId, String recordedBy,
                               String resourceType, String resourceId, Map<String, Object> payload) {
        Map<String, Object> request = new LinkedHashMap<>();
        request.put("eventType", eventType);
        request.put("actorId", actorId);
        request.put("resourceType", resourceType);
        request.put("resourceId", resourceId);
        request.put("payload", payload);
        String requestHash = HashChain.sha256(HashChain.canonical(request));
        return write(() -> {
            List<Map<String, Object>> prior = jdbc.queryForList(
                    "SELECT request_hash, seq FROM idempotency_keys WHERE key = ?", idempotencyKey);
            if (!prior.isEmpty()) {
                byte[] stored = String.valueOf(prior.get(0).get("request_hash")).getBytes(StandardCharsets.UTF_8);
                if (!MessageDigest.isEqual(requestHash.getBytes(StandardCharsets.UTF_8), stored)) {
                    throw new Conflict("Idempotency-Key was already used for a different request");
                }
                return new Appended(find(((Number) prior.get(0).get("seq")).longValue()), true);
            }
            AuditRecord r = appendInTx(eventType, actorId, recordedBy, resourceType, resourceId, payload);
            jdbc.update("INSERT INTO idempotency_keys (key, request_hash, seq) VALUES (?, ?, ?)",
                    idempotencyKey, requestHash, r.seq());
            return new Appended(r, false);
        });
    }

    private AuditRecord appendInTx(String eventType, String actorId, String recordedBy, String resourceType,
                                   String resourceId, Map<String, Object> payload) {
        Head head = jdbc.query("SELECT seq, hash, timestamp FROM events ORDER BY seq DESC LIMIT 1",
                (ResultSetExtractor<Head>) rs -> rs.next()
                        ? new Head(rs.getLong(1), rs.getString(2), rs.getString(3)) : null);
        long seq = head == null ? 0 : head.seq();
        String prev = head == null ? HashChain.GENESIS_HASH : head.hash();
        String now = iso(clock.instant());
        // keep timestamps monotonic even if the wall clock steps back
        String timestamp = head != null && now.compareTo(head.timestamp()) < 0 ? head.timestamp() : now;
        AuditRecord built = HashChain.build(seq + 1, prev, timestamp, eventType, actorId, recordedBy,
                resourceType, resourceId, payload);
        AuditRecord r = HashChain.withMac(built, key.mac(built.hash()));
        jdbc.update("INSERT INTO events (" + COLUMNS + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                r.seq(), r.timestamp(), r.eventType(), r.actorId(), r.recordedBy(), r.resourceType(), r.resourceId(),
                toJson(cipher.encrypt(r.payload())), toJson(r.salts()), toJson(r.fieldHashes()), r.prevHash(), r.hash(), 0,
                r.mac());
        return r;
    }

    /**
     * Remove payload values but keep their commitments, so the chain still verifies. Recorded
     * as a chained RECORD_REDACTED event (who, why, which fields); verify treats any redacted
     * field without such an event as tampering.
     */
    public AuditRecord redact(long seq, List<String> fields, String reason, String requestedBy) {
        AuditRecord event = write(() -> {
            AuditRecord r = find(seq);
            if (r.archived() || HashChain.SYSTEM_EVENTS.contains(r.eventType())) {
                throw new Conflict("archived records and system events cannot be redacted");
            }
            List<String> unknown = fields.stream().filter(f -> !r.payload().containsKey(f)).sorted().toList();
            if (!unknown.isEmpty()) {
                throw new Conflict("unknown payload fields: " + unknown);
            }
            List<String> targets = fields.stream().distinct().filter(r.salts()::containsKey).sorted().toList();
            if (targets.isEmpty()) {
                throw new Conflict("fields are already redacted");
            }
            Map<String, Object> payload = new LinkedHashMap<>(r.payload());
            Map<String, String> salts = new LinkedHashMap<>(r.salts());
            targets.forEach(f -> {
                payload.put(f, HashChain.REDACTED);
                salts.remove(f);
            });
            jdbc.update("UPDATE events SET payload = ?, salts = ? WHERE seq = ?",
                    toJson(cipher.encrypt(payload)), toJson(salts), seq);
            return appendInTx(HashChain.REDACTION_EVENT, requestedBy, requestedBy, "AUDIT_EVENT", String.valueOf(seq),
                    Map.of("targetSeq", seq, "fields", targets, "reason", reason));
        });
        writeLock.lock();   // flush the WAL so the old value is not left in the -wal file
        try {
            jdbc.query("PRAGMA wal_checkpoint(TRUNCATE)", (ResultSetExtractor<Void>) rs -> null);
        } finally {
            writeLock.unlock();
        }
        return event;
    }

    /**
     * Retention: turn records older than the window into tombstones. A tombstone keeps
     * seq/timestamp/prevHash/hash so chain links still verify; content is purged. Timestamps are
     * monotonic, so "older than cutoff" is always a contiguous prefix. The run is authorized by
     * a chained RECORDS_ARCHIVED event; verify flags tombstones beyond its throughSeq. A window
     * below the legal minimum is refused here and flagged by verify if it ever gets in.
     */
    public RetentionResult archive(double olderThanDays, String requestedBy) {
        if (olderThanDays < retentionMinDays) {
            throw new PolicyViolation("olderThanDays must be at least the " + retentionMinDays
                    + "-day legal minimum");
        }
        String cutoff = iso(clock.instant().minus(Duration.ofSeconds(Math.round(olderThanDays * 86_400))));
        return write(() -> {
            Map<String, Object> row = jdbc.queryForMap(
                    "SELECT MAX(seq) AS through, SUM(archived = 0) AS pending FROM events WHERE timestamp < ?",
                    cutoff);
            Long through = row.get("through") == null ? null : ((Number) row.get("through")).longValue();
            long pending = row.get("pending") == null ? 0 : ((Number) row.get("pending")).longValue();
            if (pending == 0) {
                return new RetentionResult(0, through, null);
            }
            jdbc.update("UPDATE events SET archived = 1, event_type = NULL, actor_id = NULL, recorded_by = NULL, "
                    + "resource_type = NULL, resource_id = NULL, payload = NULL, salts = NULL, "
                    + "field_hashes = NULL WHERE seq <= ? AND archived = 0", through);
            AuditRecord event = appendInTx(HashChain.ARCHIVE_EVENT, requestedBy, requestedBy, "AUDIT_LOG", "retention",
                    Map.of("throughSeq", through, "cutoff", cutoff, "count", pending,
                            "olderThanDays", olderThanDays));
            return new RetentionResult(pending, through, event);
        });
    }

    // ---- reads ----------------------------------------------------------------------------

    public AuditRecord find(long seq) {
        List<AuditRecord> found = jdbc.query(SELECT + " WHERE seq = ?", (rs, i) -> toRecord(rs), seq);
        if (found.isEmpty()) {
            throw new NotFound("record " + seq + " not found");
        }
        return found.get(0);
    }

    /** Keyset pagination on seq. {@code from} is inclusive, {@code to} exclusive. */
    public Page query(Map<String, String> filters, Instant from, Instant to, int limit, long cursor) {
        StringBuilder where = new StringBuilder("archived = 0 AND seq > ?");
        List<Object> params = new ArrayList<>(List.of(cursor));
        FILTERS.forEach((key, column) -> {
            if (filters.get(key) != null) {
                where.append(" AND ").append(column).append(" = ?");
                params.add(filters.get(key));
            }
        });
        if (from != null) {
            where.append(" AND timestamp >= ?");
            params.add(iso(from));
        }
        if (to != null) {
            where.append(" AND timestamp < ?");
            params.add(iso(to));
        }
        params.add(limit + 1);
        List<AuditRecord> rows = jdbc.query(SELECT + " WHERE " + where + " ORDER BY seq LIMIT ?",
                (rs, i) -> toRecord(rs), params.toArray());
        List<AuditRecord> page = rows.subList(0, Math.min(limit, rows.size()));
        return new Page(List.copyOf(page), rows.size() > limit ? page.get(page.size() - 1).seq() : null);
    }

    /** Stream records in seq order until the consumer returns false. */
    public void streamChain(long fromSeq, Predicate<AuditRecord> consumer) {
        jdbc.query(SELECT + " WHERE seq >= ? ORDER BY seq", (ResultSetExtractor<Void>) rs -> {
            boolean more = true;
            while (more && rs.next()) {
                more = consumer.test(toRecord(rs));
            }
            return null;
        }, fromSeq);
    }

    public VerifyResult verify() {
        return verify(null, null);
    }

    /** Full verification: hashes, MACs, retention policy and (optionally) an external anchor. */
    public VerifyResult verify(Long anchorSeq, String anchorHash) {
        ChainVerifier verifier = new ChainVerifier(retentionMinDays, key, anchorSeq, anchorHash);
        streamChain(1, verifier::accept);
        return verifier.result();
    }

    /**
     * Self-verifiable bundle: records matching one actorId or resourceId, plus the chain
     * skeleton from the first match to the head, in one streaming pass. The skeleton holds no
     * event content, so it is safe to share.
     */
    public Bundle export(boolean byActor, String value) {
        String column = byActor ? "actor_id" : "resource_id";
        Long first = jdbc.queryForObject(
                "SELECT MIN(seq) FROM events WHERE archived = 0 AND " + column + " = ?", Long.class, value);
        List<AuditRecord> records = new ArrayList<>();
        List<Bundle.Link> links = new ArrayList<>();
        if (first != null) {
            streamChain(first, r -> {
                links.add(new Bundle.Link(r.seq(), r.prevHash(), r.hash()));
                if (!r.archived() && value.equals(byActor ? r.actorId() : r.resourceId())) {
                    records.add(r);
                }
                return true;
            });
        }
        Bundle.Link head = links.isEmpty() ? currentHead() : links.get(links.size() - 1);
        return new Bundle("audit-bundle/v1", iso(clock.instant()),
                "sha256; record and field hashing as specified in HashChain", records, links, head, null);
    }

    private Bundle.Link currentHead() {
        List<Bundle.Link> head = jdbc.query("SELECT seq, prev_hash, hash FROM events ORDER BY seq DESC LIMIT 1",
                (rs, i) -> new Bundle.Link(rs.getLong(1), rs.getString(2), rs.getString(3)));
        return head.isEmpty() ? new Bundle.Link(0, null, HashChain.GENESIS_HASH) : head.get(0);
    }

    // ---- mapping --------------------------------------------------------------------------

    private AuditRecord toRecord(ResultSet rs) throws SQLException {
        return new AuditRecord(rs.getLong("seq"), rs.getString("timestamp"), rs.getString("event_type"),
                rs.getString("actor_id"), rs.getString("recorded_by"), rs.getString("resource_type"), rs.getString("resource_id"),
                decrypted(fromJson(rs.getString("payload"), OBJECT_MAP)), fromJson(rs.getString("salts"), STRING_MAP),
                fromJson(rs.getString("field_hashes"), STRING_MAP), rs.getString("prev_hash"),
                rs.getString("hash"), rs.getInt("archived") == 1, rs.getString("mac"));
    }

    private Map<String, Object> decrypted(Map<String, Object> stored) {
        return stored == null ? null : cipher.decrypt(stored);
    }

    private String toJson(Object value) {
        try {
            return json.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /** Unreadable JSON maps to null, so verify reports CORRUPT_RECORD and queries keep working. */
    private <T> T fromJson(String text, TypeReference<T> type) {
        try {
            return text == null ? null : json.readValue(text, type);
        } catch (JsonProcessingException e) {
            return null;
        }
    }
}
