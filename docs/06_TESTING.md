# 06 — Testing Approach, Limitations & Trade-offs

## Strategy

| Layer | What | Where |
|---|---|---|
| **Unit** | Pure hash-chain logic, every violation type, attacker rehash, swap | `tests/test_chain.py` |
| **Integration (API + real SQLite)** | Each endpoint through FastAPI `TestClient` on a temp DB file | `tests/test_api.py`, `test_redaction.py`, `test_retention.py`, `test_export.py`, `test_compliance.py` |
| **Adversarial** | Raw SQL against the DB, bypassing the API (and the guardrail triggers) to simulate a malicious admin | `tamper` fixture in `tests/conftest.py` |
| **Concurrency** | 8 threads × 80 writes, then full verify | `test_concurrent_writers_never_fork_the_chain` |
| **Privacy** | Scan raw DB + WAL bytes after redaction | `test_redacted_value_is_gone_from_raw_database_files` |
| **End-to-end** | Live uvicorn server, scripted brief flow | `scripts/demo.py` |

**60 tests, ~2.5 s.** Tests check **behavior and exact violation location** (`violation`,
`firstInvalidSeq`), not only `valid == false`. A verifier that just says "broken" is far less
useful to an investigator.

I checked that the tests actually discriminate: the privacy test **fails** when the WAL
checkpoint is removed (confirmed manually).

## Quality gates

| Gate | Tool | Enforced |
|---|---|---|
| Lint / static analysis | `ruff` (pyflakes, pycodestyle, bugbear, pyupgrade, isort) | CI + before every commit |
| Security static analysis | `ruff` `S` rules (bandit). Remaining `noqa: S608` lines are reviewed: SQL is built only from constant, whitelisted column names, and values are always bound parameters | CI |
| Tests | `pytest` | CI + before every commit |
| Performance | Measured (below) | Manual |

## Performance (laptop-class container, SQLite, WAL)

| Operation | Result |
|---|---|
| Append (each a durable transaction) | ~3,400 events/s |
| Full verify, 10,000 records | 0.29 s (streaming, O(1) memory) |
| Query page at depth 9,000 (keyset) | ~1 ms |

## Not covered, and why

| Gap | Reason / mitigation |
|---|---|
| Multi-process writers against one file | Design handles it (`BEGIN IMMEDIATE`) but the tests only cover threads. Production target is Postgres |
| Load / soak testing | Out of scope for a prototype; numbers above are indicative only |
| Property-based / fuzz testing of canonical JSON | Would add a dependency (Hypothesis). Parametrized cases cover the key properties |
| Cross-language verifier | The algorithm is specified in `chain.py` and `02_ARCHITECTURE.md`; not implemented in a second language |
| AuthN/AuthZ | Only the admin-key gate exists and is tested; real IAM is out of scope |
| Truncation / full rewrite | Undetectable without an external anchor (documented in the threat model). `headHash` is exposed for anchoring |
