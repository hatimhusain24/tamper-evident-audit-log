# 01 — Requirement Analysis & Task Decomposition

Written **before any code**, so that implementation follows from an agreed problem statement.

## 1. Normalized problem statement

Build an HTTP service that keeps an **append-only, ordered log of audit events**. Anyone who can
reach the service can prove whether stored history has been **modified, deleted, re-ordered, or
inserted** since it was written. The guarantee must still hold after two legitimate destructive
operations: **retention archival** and **field-level redaction**. It must also support
**regulator-facing access reporting**.

## 2. Requirements → engineering interpretation

| # | Source requirement | Interpretation / decision |
|---|---|---|
| A1 | Write API with eventType, actorId, resourceType, resourceId, payload, timestamp | `POST /audit/events`. Strict validation: eventType `UPPER_SNAKE`, bounded string lengths, payload is a JSON object ≤ 32 KB. |
| A2 | Timestamp caller- or server-assigned | **Server-assigned**, UTC, microsecond precision, forced monotonic. Callers can't backdate, and log order = time order (time-range queries and retention depend on this). A caller's own "occurred at" can go in `payload`. |
| A3 | Append-only | The API has no update or delete routes. The storage layer has one insert path. Archival and redaction are separate, explicit admin operations that **append** their own audit event. |
| A4 | Query by actor / resource / type / time, paginated | `GET /audit/events` with any combination of filters. **Keyset pagination** on `seq` (stable under concurrent appends, O(log n) per page, unlike OFFSET). |
| A5 | Hash chain | Each record stores `prevHash` and `hash = SHA-256(canonical(content + prevHash))`. Genesis `prevHash` = 64 zeros. |
| A6 | `GET /audit/verify` | Streams the full chain in O(n) time and O(1) memory (plus redaction bookkeeping). Reports `valid`, first bad `seq`, and a typed `violation`. |
| B1 | Retention: archive/soft-delete old records without false positives | Archival turns old records into **tombstones**: content is purged but `seq/prevHash/hash` stay, so the chain links still verify. A chained `RECORDS_ARCHIVED` event authorizes the range. |
| B2 | Redaction without breaking the chain | **Per-field salted commitments**: the record hash covers `H(salt‖field)`, not the raw value. Redaction deletes the value and salt and keeps the commitment. A chained `RECORD_REDACTED` event authorizes it. |
| B3 | Verifiable export bundle | `GET /audit/export` returns the records plus the chain segment that links them. An **offline verifier** (`java -jar audit-log.jar verify-bundle`) needs no access to the service. |
| C | "Regulators need to audit access to client account data" | Ambiguous. Clarified in [04_SCENARIO_C_COMPLIANCE.md](04_SCENARIO_C_COMPLIANCE.md) before any code was written. |

## 3. Ambiguities identified & assumptions

1. **Who may write?** Assumed: trusted internal services. AuthN is out of scope for the prototype.
   Admin operations (redact, archive) can be protected by an `X-Admin-Key` header.
2. **Threat model.** Detect tampering by someone with *write access to the data store* who does
   **not** control the service's code or an external anchor of the chain head. A full chain rewrite
   by a DB admin can't be detected by an unkeyed hash chain alone. This is documented, with
   mitigations, in [02_ARCHITECTURE.md](02_ARCHITECTURE.md#threat-model).
3. **Deleting the newest records (truncation)** can't be detected from the chain alone. Mitigation:
   `verify` returns `headSeq/headHash` so it can be anchored externally.
4. **Redaction granularity** = top-level payload keys. Core event fields (actorId, etc.) are not
   redactable. They are identifiers needed for querying, so they should not carry PII values.
5. **Scale**: prototype on SQLite (one file, zero setup). The storage module is the only part that
   would change for Postgres.

## 4. Task decomposition (sequenced, with acceptance criteria)

| ID | Task | Depends on | Acceptance criteria |
|----|------|-----------|---------------------|
| T1 | Requirements, assumptions, plan (this doc) | — | Reviewed by engineer before coding |
| T2 | Scaffold: deps, lint/security config, CI | T1 | `mvn verify` (compile, tests, SpotBugs) runs green |
| T3 | Hash-chain core (pure functions) | T2 | Unit tests: deterministic canonical hashing; every tamper type detected |
| T4 | SQLite store + Write/Query/Verify API (Scenario A) | T3 | API tests; direct DB edit → `verify` reports the first bad seq and its violation type |
| T5 | Redaction (Scenario B) | T4 | Redacted record still verifies; forged "redaction" is flagged |
| T6 | Retention archival (Scenario B) | T4 | Archived prefix verifies; tombstone outside policy is flagged |
| T7 | Export bundle + offline verifier (Scenario B) | T5, T6 | Bundle verifies offline; edited bundle fails |
| T8 | Scenario C clarification → access report | T4 | Clarified requirement doc; report endpoint + tests |
| T9 | Architecture, testing, AI log, summary docs | all | Every deliverable in §7 of the brief is present |
