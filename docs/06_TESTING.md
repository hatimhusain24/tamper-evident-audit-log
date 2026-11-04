# 06 — Testing Approach, Limitations & Trade-offs

## Strategy

| Layer | What | Where |
|---|---|---|
| **Unit** | Pure hash-chain logic, every violation type, edge-case payloads | `chain/HashChainTest` |
| **Store** | Clock stepping backwards, retention window | `store/AuditStoreTest` |
| **Integration (Spring + real SQLite)** | Each endpoint through MockMvc on a real database file | `ScenarioAApiTest`, `RedactionTest`, `RetentionTest`, `ExportTest`, `ComplianceReportTest`, `AdminKeyTest` |
| **Adversarial** | Raw SQL against the DB, bypassing the API and the guardrail triggers | `tamper(...)` in `ApiTestBase` |
| **Concurrency** | 8 threads × 80 writes, then full verify | `concurrentWritersNeverForkTheChain` |
| **Privacy** | Scan raw DB + WAL bytes after redaction | `redactedValueIsGoneFromRawDatabaseFiles` |

**85 tests, about 10 s.** Tests check the **exact violation and location** (`violation`,
`firstInvalidSeq`), not only `valid == false`. The privacy test was confirmed to fail when the
WAL checkpoint is removed.

## Edge cases covered

Empty log (verify, export, retention) · unicode, null, nested and decimal payload values · literal
`"[REDACTED]"` text in a payload · payload missing · oversized payload · unknown JSON fields ·
malformed JSON · reserved system event types · pagination limits and cursor past the end ·
inverted time range · duplicate and multiple redaction fields · double redaction · redacting
system events or archived records · repeated archive runs · negative retention window · wrong or
missing admin key · clock stepping backwards · concurrent writers.

## Quality gates (`mvn verify`, run by CI on every push)

| Gate | Tool |
|---|---|
| Static analysis | `javac -Xlint:all -Werror` |
| Bugs + security | SpotBugs + FindSecBugs. Suppressions are listed and justified in `spotbugs-exclude.xml` (record/DTO exposure, public-hash comparison, whitelisted SQL) |
| Tests | JUnit 5, AssertJ, Spring MockMvc |
| Performance | Measured (below) |

## Performance (cloud container, SQLite WAL, Hikari pool)

| Operation | Result |
|---|---|
| Append (each a durable transaction) | ~2,700 events/s |
| Full verify, 10,500 records | 0.34 s (streaming) |
| Query page at depth 9,000 (keyset) | ~3 ms |

## Not covered, and why

| Gap | Reason / mitigation |
|---|---|
| Multi-process writers on one file | Handled by `BEGIN IMMEDIATE` but only threads are tested. Production target is Postgres |
| Load / soak testing | Out of scope for a prototype; numbers above are indicative |
| Property-based fuzzing of canonical JSON | Would add a dependency (jqwik); parametrized cases cover key properties |
| Cross-language verifier | Algorithm specified in `HashChain` and `02_ARCHITECTURE.md`; not built in a second language |
| AuthN/AuthZ | Only the admin-key gate exists and is tested |
| Truncation / full rewrite | Undetectable without an external anchor (threat model); `headHash` is exposed for anchoring |
