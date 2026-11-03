# 03 — Scenarios A & B: Decomposition → Execution → Validation

Each task was defined (intent, constraints, acceptance criteria), implemented, then validated with
lint and tests **before** its commit. The git history follows this table one-to-one.

## Scenario A: core audit log service

| Task | Intent & constraints | Execution | Validation (tests) |
|---|---|---|---|
| A1 Hash-chain core | Deterministic, language-portable hashing. Every tamper type must be distinguishable | `app/chain.py`: canonical JSON, `record_hash`, `check_record`, streaming `verify_chain` | `test_chain.py`: 12 tests, one per violation type, rehash attack, swap, empty chain |
| A2 Write API | Append-only; strict schema; caller can't set the timestamp or system types | `POST /audit/events`, `EventIn` (`extra=forbid`, patterns, 32 KB cap), monotonic server time | `test_write_validation` (6 bad inputs), `test_no_update_or_delete_routes` |
| A3 Query API | Any filter combination, time range, scalable pagination | `store.query`: whitelisted filters, `[from,to)`, keyset on `seq`, composite indexes | `test_query_filters_combine`, `test_query_time_range`, `test_keyset_pagination_walks_all_pages` |
| A4 Verify endpoint | Full walk, first inconsistency, typed violation | `GET /audit/verify` streams a snapshot read connection in O(1) memory | `test_verify_intact_chain` and **direct-DB tamper tests** (UPDATE actor, payload, type; DELETE after dropping the guardrail trigger) |
| A5 Concurrency | Chain head must never fork | Process lock + `BEGIN IMMEDIATE` | `test_concurrent_writers_never_fork_the_chain` (8 threads × 80 writes) |

**Brief's validation flow** (write → query → verify → modify in DB → verify): automated in
`tests/test_api.py` and reproducible by hand with `scripts/demo.py`.

## Scenario B: retention, redaction, export

| Task | Intent & constraints | Execution | Validation (tests) |
|---|---|---|---|
| B1 Redaction | Remove PII, keep chain verifiable, keep accountability, no brute-forcing | Salted per-field commitments. Redaction drops value + salt and appends `RECORD_REDACTED`. `secure_delete` + WAL checkpoint | `test_redaction.py`: chain stays valid, value gone from **raw DB/WAL bytes**, forged redaction → `UNAUTHORIZED_REDACTION`, 404/409/422 paths, admin key |
| B2 Retention | Configurable window; no false positives; can't be abused to hide tampering | Tombstones keep chain columns; prefix-only; `RECORDS_ARCHIVED` authorizes `throughSeq` | `test_retention.py`: default window no-op, archived chain valid, repeated runs, tombstone hash edit detected, out-of-policy tombstones detected |
| B3 Export | Self-contained bundle a recipient can verify independently | `GET /audit/export`, one streaming pass. `python -m app.verify_bundle` (stdlib only) | `test_export.py`: filters, 5 tamper variants, bundle spanning redacted + archived history, CLI exit codes and `--expected-head` |

## Bugs and gaps caught by this process (kept honest)

1. **Redacted value survived in the SQLite WAL file.** Found while writing the raw-bytes test.
   I confirmed it by disabling the fix (the value was present in `audit.db-wal`). Fixed with a WAL
   checkpoint plus `secure_delete`.
2. **Wrong expectation in my own retention test.** I expected seq 3, the verifier reported seq 4.
   The verifier was right (seq 3 was the legitimate archive event), so I fixed the test, not the code.
3. **Edge case: destroying the authorizing archive event.** The verifier can't prove *any*
   tombstone legitimate, so it reports from seq 1. I documented this as intended, conservative
   behavior.
