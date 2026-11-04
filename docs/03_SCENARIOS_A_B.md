# 03 — Scenarios A & B: Decomposition → Execution → Validation

Each task was defined (intent, constraints, acceptance criteria), implemented, then validated by
`mvn verify` (compile with warnings as errors, tests, SpotBugs) before its commit.

## Scenario A: core audit log service

| Task | Intent & constraints | Execution | Validation (tests) |
|---|---|---|---|
| A1 Hash-chain core | Deterministic hashing; every tamper type distinguishable | `chain/HashChain`, streaming `ChainVerifier` | `HashChainTest`: 19 tests, one per violation type, rehash attack, swap, unicode/null/nested payloads, literal `[REDACTED]` text |
| A2 Write API | Append-only; strict schema; caller can't set time or system types | `POST /audit/events`, `EventRequest` (Bean Validation, unknown fields rejected, 32 KB cap), monotonic server time | `invalidEventsAreRejected` (8 cases), `malformedJsonIsRejected`, `noUpdateOrDeleteRoutes`, `payloadIsOptional` |
| A3 Query API | Any filter combination, time range, scalable pagination | `AuditStore.query`: whitelisted filters, `[from,to)`, keyset on `seq`, composite indexes | `filtersCombine`, `timeRangeIsFromInclusiveToExclusive` (incl. inverted range), `keysetPaginationWalksAllPagesOnce`, `paginationLimitsAreEnforced` |
| A4 Verify endpoint | Full walk, first inconsistency, typed violation | `GET /audit/verify` streams rows through `ChainVerifier` | `verifyIntactChain` and **direct-DB tampering** (6 edits, delete with the trigger dropped, forged insert) |
| A5 Concurrency & clock | Chain must never fork; time must never go backwards | Lock + `BEGIN IMMEDIATE`; timestamp clamped to the last one | `concurrentWritersNeverForkTheChain` (8 threads × 80), `AuditStoreTest.timestampsStayMonotonicWhenTheClockStepsBack` |

The brief's validation flow (write → query → verify → modify in DB → verify) is automated in
`ScenarioAApiTest`, and the README shows how to do it by hand.

## Scenario B: retention, redaction, export

| Task | Intent & constraints | Execution | Validation (tests) |
|---|---|---|---|
| B1 Redaction | Remove PII, keep chain verifiable, keep accountability, no guessing | Salted per-field commitments; value and salt dropped; `RECORD_REDACTED` appended; `secure_delete` + WAL checkpoint | `RedactionTest`: chain valid, multi-field + duplicates, value gone from **raw DB/WAL bytes**, forged redaction, edited redaction event, 400/404/409 paths |
| B2 Retention | Configurable window; no false positives; can't hide tampering | Tombstones keep chain columns; prefix only; `RECORDS_ARCHIVED.throughSeq` | `RetentionTest`: default window, empty log, repeated runs, archived record not redactable, negative window, tombstone edits, out-of-policy tombstones |
| B3 Export | Self-contained bundle a recipient can verify independently | `GET /audit/export`, one streaming pass; `java -jar audit-log.jar verify-bundle` | `ExportTest`: filters, empty log, 5 tamper variants, bundle spanning redacted + archived history, CLI exit codes |

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
