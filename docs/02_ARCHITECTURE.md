# 02 — Architecture

## 1. Components

```
            ┌────────────── api/AuditController (Spring MVC, @RestController) ─────────────┐
 HTTP ───▶  │ POST /v1/audit/events   GET /v1/audit/events   GET /v1/audit/verify   GET /v1/audit/export │
            │ POST …/redactions 🔒  POST /v1/audit/retention/run 🔒  GET …/account-access 🔒     │
            └──────┬──────────────────────────┬──────────────────────────┬──────────────────┘
                   │ validated by             │ persists via             │ Scenario C
            api/EventRequest, Dtos     store/AuditStore (SQLite)  compliance/AccessReportService
            (Bean Validation)           JdbcTemplate, single        (reuses store.query
                                        write path, streaming reads  + store.verify)
                                              │
                                              ▼ builds / checks records with
                                   chain/HashChain + ChainVerifier — PURE, no I/O
                                   canonical JSON · SHA-256 · verify · verifyBundle
                                              ▲
                                   chain/BundleVerifierCli (java -jar audit-log.jar verify-bundle)
```

**Design rule:** all cryptographic logic sits in one I/O-free package (`chain`). The service, the
tests and an external recipient's offline verifier run *the same code*. That keeps the security
core small (~490 lines including records and the CLI), easy to review and easy to unit-test.
`security/` holds access control and request guards, so the controller has no auth logic.

## 2. Data model (single table `events`)

| Column | Notes |
|---|---|
| `seq` INTEGER PK | Dense 1..n. Gaps mean deletion. Part of the hash, so re-ordering is detected |
| `timestamp` | Server-assigned UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`, monotonic (fixed width, so lexical = chronological) |
| `event_type, actor_id, resource_type, resource_id` | Indexed with `seq` for keyset queries. `actor_id` = who the event is about, as asserted by the submitter |
| `recorded_by` | The **authenticated** submitter (from Spring Security), inside the hash: attribution can't be forged |
| `payload` JSON | Event detail. Redacted fields hold `"[REDACTED]"` |
| `salts` JSON | `{field: 128-bit random salt}`. **A missing salt marks a redacted field** |
| `field_hashes` JSON | `{field: SHA-256(salt ‖ canonical([field, value]))}`: the payload commitments |
| `prev_hash`, `hash` | The chain |
| `mac` | `HMAC-SHA256(server key, hash)`: only the service can produce it |
| `archived` | 1 = retention tombstone (content NULLed, chain columns kept) |

A second table, `idempotency_keys (key, request_hash, seq)`, makes retried writes safe.

DB triggers reject `DELETE` and updates to `seq/timestamp/prev_hash/hash/mac`. These are
**guardrails against application bugs**. Someone with DB admin rights can drop them, which is why
detection relies on the hash chain and MACs, not on the triggers.

## 3. Hash chain design

```
fieldHashes[k] = SHA256( salt_k ‖ canonical([k, payload[k]]) )
hash_n         = SHA256( canonical({seq, timestamp, eventType, actorId, recordedBy, resourceType,
                                    resourceId, fieldHashes, prevHash = hash_{n-1}}) )
mac_n          = HMAC-SHA256( serverKey, hash_n )
hash_0 (genesis prevHash) = "000…0" (64 hex)
```

* **Canonical JSON** (sorted keys, no whitespace, UTF-8) makes hashing deterministic across
  languages, so a Java or Go verifier can reproduce it.
* **`prevHash` is inside the hashed content.** If the content hash excluded `prevHash`, an
  attacker could edit record *k*, recompute *its* hash, patch `prevHash` of record *k+1*, and
  stop there. With it inside, any edit cascades to the head.
* **`seq` is inside the hash**, so swapping two records is detected even if their links are
  re-pointed.
* **The MAC is separate from the hash on purpose.** Anyone can recompute a SHA-256 chain, because
  the algorithm is public, so a DB admin could rewrite everything consistently. They can't produce
  MACs without the key (from `AUDIT_HMAC_KEY`, a secret manager / KMS in production), so a full
  rewrite fails as `MAC_MISMATCH`. Keeping the plain hash chain means export recipients can still
  verify offline without the key.
* **Truncation** of the newest records can't be detected from inside the log. `verify` returns
  `headSeq/headHash`; store them periodically in WORM storage and pass them back as
  `anchorSeq/anchorHash`, and missing tail records are reported as `ANCHOR_MISMATCH`.

### Hash algorithm choice: SHA-256

| Option | Verdict |
|---|---|
| **SHA-256** ✅ | FIPS 180-4 approved (matters in a regulated broker-dealer), built into the JDK and every HSM, 128-bit collision resistance, ~0.03 ms per record here |
| SHA-3 / BLAKE2/3 | Equally secure; BLAKE3 is faster, but neither is a plain JDK/FIPS default everywhere. No benefit at this scale |
| MD5 / SHA-1 | Broken collision resistance. Rejected |
| HMAC-SHA-256 (keyed) | **Added as a per-record MAC** next to the plain hash (see above). Key rotation is not implemented yet |

### Linear chain vs Merkle tree

A linear chain is the simplest structure that meets every requirement. Verification is O(n), and
streaming 10k records takes ~0.3 s. A Merkle tree would give O(log n) inclusion proofs (smaller
export bundles) at a big cost in complexity. **Trade-off accepted**: export bundles carry the
linear chain skeleton from the first exported record to the head (64-byte hashes, no content).

## 4. Scenario B design decisions

### Redaction: salted per-field commitments

| Approach considered | Why not / why |
|---|---|
| Re-hash the chain after removing the value | Destroys tamper evidence: "legitimate" rewrites look exactly like attacks |
| Store an unsalted `H(value)` | Account numbers and SSNs have low entropy, so the value is brute-forceable from the hash. **Privacy fails** |
| Encrypt each field and crypto-shred the key | Strong, but needs per-record key management. Over-engineered for the prototype; a good production evolution |
| **Salted commitment per top-level field** ✅ | The record hash covers `H(salt‖value)`. Redaction deletes value **and** salt, so the commitment stays (chain intact) and can't be brute-forced (128-bit salt) |

Every redaction also appends a chained **`RECORD_REDACTED`** event (`targetSeq`, `fields`,
`reason`, `actorId` = requester). `verify` cross-checks **every** redacted field against these
events, so a DB admin who "redacts" (destroys evidence) without the event is caught
(`UNAUTHORIZED_REDACTION`). Physical erasure is enforced with `PRAGMA secure_delete` and a WAL
checkpoint. A test scans the raw DB and WAL files for the old value.

**Limitations:** granularity is top-level payload keys (nested PII means redacting the parent
key). Core fields (`actorId`, `resourceId`) are not redactable: they are identifiers, and
producers should use pseudonymous IDs. Redaction can't recall copies already exported.

### Retention: tombstones + chained authorization

Archiving NULLs the content columns but keeps `seq, timestamp, prev_hash, hash`. Verification
still checks every link through archived records, so there are no false positives, and editing a
tombstone's hash breaks the next link. Timestamps are monotonic, so "older than cutoff" is always a
**contiguous prefix**. Each run appends a chained **`RECORDS_ARCHIVED`** event (`throughSeq`).
`verify` rejects tombstones that are not a prefix, or that sit beyond the largest authorized
`throughSeq` (`UNAUTHORIZED_ARCHIVE`). If an attacker tombstones the authorizing event itself,
verify conservatively reports the whole prefix from seq 1 as unprovable.

*Rejected alternative:* moving rows to another table and starting a new genesis. That needs
signed checkpoints to bridge the two chains, which is more moving parts.

### Retention floor

`audit.retention-min-days` (default 2190 = 6 years, SEC 17a-4) is enforced in `AuditStore.archive`,
so no caller, including an admin, can archive younger records. The app refuses to start if the
default window is below the floor, and `verify` reports any archive event below the floor as
`RETENTION_POLICY_VIOLATION`.

### Corrupt records

A row whose JSON can't be parsed or whose required columns are NULL is reported by verify as
`CORRUPT_RECORD` at that seq. Queries still return it, with `payload: null`, and the compliance
report notes it in `integrity`. Nothing bad data can do turns verify into an HTTP 500.

### Export bundle

`{records (with salts), chain: [{seq, prevHash, hash}] first→head, head}`. The offline verifier
checks each record's commitments and hash, segment continuity, membership of each record in the
segment, and the head. Comparing `head.hash` with a trusted checkpoint proves the records haven't
changed since export.

## 5. API design notes

* **Server-assigned timestamps** prevent backdating and keep `seq` order equal to time order, which
  retention depends on. Unknown fields such as `timestamp` are rejected (`fail-on-unknown-properties`).
* **Keyset pagination** (`cursor` = last `seq`): constant cost per page (~3 ms at depth 9,000), and
  stable while new events are appended. OFFSET pagination would skip or duplicate rows under
  concurrent writes.
* Time range is `[from, to)`, so adjacent windows never double-count.
* Reserved system event types (`RECORD_REDACTED`, `RECORDS_ARCHIVED`, `COMPLIANCE_REPORT_GENERATED`)
  are rejected on the public write path, so callers can't forge an authorization or a report.
* The access report is a **POST**: generating it writes a chained event, so it must not be a GET
  (crawlers, prefetch and retries would write to the log).
* Every POST requires `application/json`, which a cross-site form can't send (CSRF defence for a
  stateless API).
* `Idempotency-Key` on writes: a retry returns the original record (200); the same key with a
  different body is 409.
* Errors (RFC 7807 problem details): 400 validation or policy · 401 credentials · 403 role ·
  404 unknown seq · 409 invalid state · 413 body too large · 415 not JSON · 429 rate limit ·
  503 database busy (retryable) · 500 generic, logged, never a stack trace.
* No `/v1` prefix yet: there is one consumer. Versioning would be a path prefix once external
  clients exist.

## 5b. Security design

| Control | Implementation |
|---|---|
| Framework | Spring Security filter chain, **deny by default** (`anyRequest().denyAll()`) |
| Authentication | Stateless HTTP Basic; users from config with `{bcrypt}` hashes only. No users, plaintext passwords or unknown roles → **the app won't start** |
| Authorisation | WRITER: append · READER: query, verify (masked) · COMPLIANCE: unmasked query, export, reports · ADMIN: redaction, retention, query, verify, metrics. Export is COMPLIANCE only (least privilege) |
| Attribution | `recordedBy` = authenticated name, in the hash. `requestedBy` is never read from a body |
| Sensitive data | Configurable fields (`ssn`, `accountNumber`, …) masked for READER; display only, hashes unchanged |
| Abuse limits | Per-IP rate limit (429) and 64 KB body limit (413), both **before** authentication, so password guessing is throttled too |
| Integrity key | `AUDIT_HMAC_KEY` ≥ 32 bytes, required at startup |
| Headers | Spring Security defaults: `X-Content-Type-Options`, `X-Frame-Options: DENY`, `Cache-Control: no-store`; HSTS over HTTPS |
| Logging | `audit.security` log: auth failures, access denied, tamper detected (ERROR), redactions, retention runs, rate limiting. Caller text is sanitized (no log injection) |
| Exposure | Swagger and the API schema are off unless the `dev` profile is active; `/actuator/health` shows status only |
| Supply chain | SpotBugs + FindSecBugs in the build; Dependabot weekly |

Upgrading to OAuth2/OIDC tokens or mTLS changes only `SecurityConfig`; the chain package doesn't
know about identity at all.

## 6. Threat model

| Threat | Detected? | How |
|---|---|---|
| Edit any field of a past record in the DB | ✅ | `HASH_MISMATCH` / `PAYLOAD_TAMPERED` at that seq |
| Edit and rehash one record | ✅ | Next record's `prevHash` → `CHAIN_LINK_BROKEN` |
| Delete / insert / reorder records | ✅ | `SEQUENCE_GAP` / `CHAIN_LINK_BROKEN` |
| Fake redaction or archival in the DB | ✅ | `UNAUTHORIZED_REDACTION` / `UNAUTHORIZED_ARCHIVE` |
| Forge system events via the API | ✅ | Rejected (400) |
| Full chain rewrite by someone with DB access (the hash algorithm is public) | ✅ | Per-record MAC with the server key → `MAC_MISMATCH` |
| Truncate the newest records | ✅ with an anchor | `verify?anchorSeq=&anchorHash=` against a head stored externally → `ANCHOR_MISMATCH` |
| Archive records younger than the legal minimum | ✅ | Refused (400); verify flags `RETENTION_POLICY_VIOLATION` |
| Anonymous or wrong-role access, forged submitter | ✅ | Spring Security roles; `recordedBy` from the login |
| Corrupt or unparseable row | ✅ | `CORRUPT_RECORD` at that seq; reads keep working |
| **Attacker who also steals the HMAC key** | ⚠️ | Keep the key in a KMS/HSM, outside the DB host; anchor heads externally |

**Failure scenarios handled (each tested):** concurrent writers (serialized; 80 writes from an
8-thread pool), clock stepping backwards (timestamp clamped monotonic), an insert failing
mid-redaction or mid-archive (one transaction, rolled back by fault injection), database locked by
another process (503 + Retry-After, pool stays healthy), corrupt rows (`CORRUPT_RECORD`), oversized
bodies (413 before parsing) and payloads (32 KB cap), duplicate retries (idempotency key).

## 7. Production evolution

Postgres (only `AuditStore` changes), key rotation and KMS-held HMAC keys, signed periodic
checkpoints written to WORM storage automatically (incremental verify from the last checkpoint
instead of O(n)), Merkle proofs and per-filter commitments for complete exports, OIDC tokens
instead of Basic, field-level encryption of PII at rest, and a distributed rate limiter.
