# 02 — Architecture

## 1. Components

```
            ┌────────────── api/AuditController (Spring MVC, @RestController) ─────────────┐
 HTTP ───▶  │ POST /audit/events   GET /audit/events   GET /audit/verify   GET /audit/export │
            │ POST …/redactions 🔒  POST /audit/retention/run 🔒  GET …/account-access 🔒     │
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
core small (~280 lines), easy to review and easy to unit-test.

## 2. Data model (single table `events`)

| Column | Notes |
|---|---|
| `seq` INTEGER PK | Dense 1..n. Gaps mean deletion. Part of the hash, so re-ordering is detected |
| `timestamp` | Server-assigned UTC `YYYY-MM-DDTHH:MM:SS.ffffffZ`, monotonic (fixed width, so lexical = chronological) |
| `event_type, actor_id, resource_type, resource_id` | Indexed with `seq` for keyset queries |
| `payload` JSON | Event detail. Redacted fields hold `"[REDACTED]"` |
| `salts` JSON | `{field: 128-bit random salt}`. **A missing salt marks a redacted field** |
| `field_hashes` JSON | `{field: SHA-256(salt ‖ canonical([field, value]))}`: the payload commitments |
| `prev_hash`, `hash` | The chain |
| `archived` | 1 = retention tombstone (content NULLed, chain columns kept) |

DB triggers reject `DELETE` and updates to `seq/timestamp/prev_hash/hash`. These are **guardrails
against application bugs**. Someone with DB admin rights can drop them, which is why detection
relies on the hash chain, not on the triggers.

## 3. Hash chain design

```
fieldHashes[k] = SHA256( salt_k ‖ canonical([k, payload[k]]) )
hash_n         = SHA256( canonical({seq, timestamp, eventType, actorId, resourceType,
                                    resourceId, fieldHashes, prevHash = hash_{n-1}}) )
hash_0 (genesis prevHash) = "000…0" (64 hex)
```

* **Canonical JSON** (sorted keys, no whitespace, UTF-8) makes hashing deterministic across
  languages, so a Java or Go verifier can reproduce it.
* **`prevHash` is inside the hashed content.** If the content hash excluded `prevHash`, an
  attacker could edit record *k*, recompute *its* hash, patch `prevHash` of record *k+1*, and
  stop there. With it inside, any edit cascades to the head.
* **`seq` is inside the hash**, so swapping two records is detected even if their links are
  re-pointed.

### Hash algorithm choice: SHA-256

| Option | Verdict |
|---|---|
| **SHA-256** ✅ | FIPS 180-4 approved (matters in a regulated broker-dealer), built into the JDK and every HSM, 128-bit collision resistance, ~0.03 ms per record here |
| SHA-3 / BLAKE2/3 | Equally secure; BLAKE3 is faster, but neither is a plain JDK/FIPS default everywhere. No benefit at this scale |
| MD5 / SHA-1 | Broken collision resistance. Rejected |
| HMAC-SHA-256 (keyed) | Stops a DB admin from **recomputing** the chain, but key management (KMS/HSM, rotation) is out of scope. Listed as the first production hardening step (§6) |

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
* Reserved system event types (`RECORD_REDACTED`, `RECORDS_ARCHIVED`) are rejected on the public
  write path, so callers can't forge an authorization.
* Errors (RFC 7807 problem details): 400 validation, 404 unknown seq, 409 invalid state (e.g. already redacted), 401 bad admin key.

## 6. Threat model

| Threat | Detected? | How |
|---|---|---|
| Edit any field of a past record in the DB | ✅ | `HASH_MISMATCH` / `PAYLOAD_TAMPERED` at that seq |
| Edit and rehash one record | ✅ | Next record's `prevHash` → `CHAIN_LINK_BROKEN` |
| Delete / insert / reorder records | ✅ | `SEQUENCE_GAP` / `CHAIN_LINK_BROKEN` |
| Fake redaction or archival in the DB | ✅ | `UNAUTHORIZED_REDACTION` / `UNAUTHORIZED_ARCHIVE` |
| Forge system events via the API | ✅ | Rejected (400) |
| **Truncate the newest records** | ⚠️ only with an anchor | Compare `headSeq/headHash` with an external checkpoint |
| **Full chain rewrite by someone with DB access** (the algorithm is public) | ⚠️ only with an anchor or key | Production: HMAC/signing key in KMS, plus periodic head anchoring to WORM storage or a separate system |

**Failure scenarios handled:** concurrent writers (serialized; tested with 8 threads), clock
stepping backwards (timestamp clamped monotonic), crash mid-redaction or mid-archive (one
transaction, so the redaction and its audit event commit atomically), oversized payloads (32 KB cap).

## 7. Production evolution

Postgres (only `AuditStore` changes), HMAC/Ed25519 signing via KMS, signed periodic checkpoints
(incremental verify from the last checkpoint instead of O(n)), Merkle proofs for exports, authN
(OIDC/mTLS) with RBAC, structured logging and metrics.
