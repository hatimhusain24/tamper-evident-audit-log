# 03 — Scenarios A & B: Decomposition → Execution → Validation

Each task was defined (intent, constraints, acceptance criteria), implemented, then validated by
`mvn verify` (compile with warnings as errors, tests, SpotBugs) before its commit.

## Scenario A: core audit log service

| Task | Intent & constraints | Execution | Validation (tests) |
|---|---|---|---|
| A1 Hash-chain core | Deterministic hashing; every tamper type distinguishable | `chain/HashChain`, streaming `ChainVerifier` | `HashChainTest`: 23 tests, one per violation type, rehash attack, swap, unicode/null/nested payloads, literal `[REDACTED]` text, uncheckable records |
| A2 Write API | Append-only; strict schema; caller can't set time, submitter or system types | `POST /audit/events` (WRITER), `EventRequest` (Bean Validation, unknown fields rejected, 32 KB cap), monotonic server time, `recordedBy` from the login, optional `Idempotency-Key` | `invalidEventsAreRejected` (8 cases), `malformedJsonIsRejected`, `noUpdateOrDeleteRoutes`, `payloadIsOptional`, `BoundaryTest`, `IdempotencyTest` |
| A3 Query API | Any filter combination, time range, scalable pagination | `AuditStore.query`: whitelisted filters, `[from,to)`, keyset on `seq`, composite indexes | `filtersCombine`, `timeRangeIsFromInclusiveToExclusive` (incl. inverted range), `keysetPaginationWalksAllPagesOnce`, `paginationLimitsAreEnforced` |
| A4 Verify endpoint | Full walk, first inconsistency, typed violation; never crash on bad data | `GET /audit/verify` streams rows through `ChainVerifier`: hashes, MACs, retention policy, optional anchor | `verifyIntactChain`, **direct-DB tampering** (6 edits, delete with the trigger dropped, forged insert), `CorruptRecordTest`, `IntegrityKeyTest` (full rewrite, truncation) |
| A5 Concurrency, faults & clock | Chain must never fork; failures leave no partial state; time never goes backwards | In-process lock + SQLite write lock taken inside each transaction; busy DB → 503; timestamp clamped to the last one | `concurrentWritersNeverForkTheChain` (80 writes, 8-thread pool), `FaultInjectionTest`, `AuditStoreTest.timestampsStayMonotonicWhenTheClockStepsBack` |
| A6 Access control | Only the right role reaches each endpoint; attribution can't be forged | Spring Security, deny by default, bcrypt users, roles WRITER/READER/COMPLIANCE/ADMIN, masking for READER | `SecurityTest` (48): role matrix, anonymous 401s, spoofing, masking, headers, CSRF, fail-closed config |

The brief's validation flow (write → query → verify → modify in DB → verify) is automated in
`ScenarioAApiTest`, and the README shows how to do it by hand.

## Scenario B: retention, redaction, export

| Task | Intent & constraints | Execution | Validation (tests) |
|---|---|---|---|
| B1 Redaction | Remove PII, keep chain verifiable, keep accountability, no guessing | Salted per-field commitments; value and salt dropped; `RECORD_REDACTED` appended; `secure_delete` + WAL checkpoint | `RedactionTest`: chain valid, multi-field + duplicates, value gone from **raw DB/WAL bytes**, forged redaction, edited redaction event, 400/404/409 paths |
| B2 Retention | Configurable window with a legal minimum; no false positives; can't destroy evidence | Tombstones keep chain columns; prefix only; `RECORDS_ARCHIVED.throughSeq`; floor of 6 years enforced on the server and checked by verify | `RetentionTest` (12): default window, floor rejected, young records kept, empty log, repeated runs, tombstone edits, out-of-policy tombstones; `AuditStoreTest.verifyFlagsAnArchiveRunBelowTheFloor` |
| B3 Export | Self-contained bundle a recipient can verify independently | `GET /audit/export` (COMPLIANCE), one streaming pass; `java -jar audit-log.jar verify-bundle` | `ExportTest`: filters, empty log, 5 tamper variants, bundle spanning redacted + archived history, CLI exit codes incl. a bundle with no head |

## Problems caught during development

1. **Redacted value stayed in the SQLite WAL file.** Found by the raw-bytes test. Fixed with a WAL
   checkpoint and `secure_delete`. Re-checked after the Java port: removing the checkpoint makes
   the test fail.
2. **Wrong expectation in a retention test.** A third archive run also archives the previous
   archive event, so the count is 1, not 0. The code was right; the test was fixed.
3. **Hiding the authorizing archive event.** Verify can't then prove any tombstone legitimate, so
   it reports from seq 1. This is intended, conservative behavior.
4. **Spring proxy vs `final` class.** `@Repository` adds a proxy that can't subclass a final class,
   so the store uses `@Component`.
5. **Found by the evaluation (fixed, each with a regression test):** unauthenticated access and a
   fail-open admin key; whole-log purge via `olderThanDays: 0`; corrupt rows returning HTTP 500;
   forgeable `actorId` / `requestedBy`; a side-effecting GET for reports. See `05_AI_USAGE_LOG.md` §6.
6. **Pool poisoning on lock timeout** (found by the new lock-timeout test): the driver's lazy
   `BEGIN IMMEDIATE` left a pooled connection marked as in a transaction after a timeout, breaking
   later writes. The write lock is now taken by the first statement inside a normal transaction.
7. **Role matrix vs config:** the matrix test showed ADMIN could export raw PII, which contradicted
   the intended least-privilege policy; export is now COMPLIANCE only.
