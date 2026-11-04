# 06 — Testing Approach, Coverage & Limitations

## Strategy

| Layer | What | Where |
|---|---|---|
| **Unit (pure)** | Hash chain, every violation type, edge-case payloads, malformed bundles | `chain/HashChainTest` (23) |
| **Unit (store, filter)** | Clock stepping back, retention window and floor; chunked-body cut-off, log sanitizing | `store/AuditStoreTest` (4), `security/RequestGuardFilterTest` (3) |
| **Integration (Spring + real SQLite + real auth)** | Every endpoint through MockMvc with HTTP Basic users on a real database file | `ScenarioAApiTest` (28), `RedactionTest` (8), `RetentionTest` (12), `ExportTest` (11), `ComplianceReportTest` (7) |
| **Security** | Endpoint × role × outcome matrix, anonymous access, wrong passwords, spoofing, masking, headers, CSRF, fail-closed config | `SecurityTest` (48) |
| **Adversarial integrity** | Raw SQL bypassing the API and triggers; full chain rewrite; tail truncation | `tamper(...)` in `ApiTestBase`, `IntegrityKeyTest` (7) |
| **Corrupt data** | Unreadable JSON, NULL columns, non-hex salts, un-archived tombstones → `CORRUPT_RECORD`, reads keep working | `CorruptRecordTest` (8) |
| **Fault injection** | Insert failure mid-redaction / mid-archive rolls back; no lost seq; DB lock held by another process → 503 | `FaultInjectionTest` (4) |
| **Abuse limits** | Body-size 413, rate limit 429 (also before auth), idempotent retries, concurrent duplicates | `RequestGuardTest` (5), `IdempotencyTest` (6) |
| **Boundaries** | Last allowed value passes, one more fails (32 KB payload, 128-char ids, 64-char type, 50 fields, 500-char reason, page 500) | `BoundaryTest` (6) |
| **Concurrency** | 80 writes from an 8-thread pool, then full verify; 16 concurrent retries with one key | `concurrentWritersNeverForkTheChain`, `concurrentRetriesWriteExactlyOnce` |

**180 tests, 0 skipped, about 1 minute.** No mocks: tests use the real database, real Spring
Security and real HTTP Basic. Tests assert the **exact violation and location** (`violation`,
`firstInvalidSeq`), not only `valid == false`. Time-dependent behaviour (6-year retention, rate
windows, clock corrections) runs on a movable `TestClock`, so the real legal floor is tested
rather than switched off.

Tests were checked to discriminate: removing the WAL checkpoint fails the privacy test, and
verifying a rewritten chain without the key passes while the keyed verify fails it.

## Coverage (JaCoCo, enforced in `mvn verify`)

| Counter | Covered | Gate |
|---|---|---|
| Line | **96.1%** | ≥ 90% |
| Branch | **92.0%** | ≥ 85% |
| Method | **97.5%** | — |

Report: `target/site/jacoco/index.html` locally; the `reports` artifact of each CI run.
Uncovered lines are mostly `AuditLogApplication.main` and defensive branches for JVM-guaranteed
algorithms (`NoSuchAlgorithmException` for SHA-256 / HmacSHA256).

**Risk-based coverage** (what line coverage alone would hide):

| Risk | Covered by |
|---|---|
| Anonymous or wrong-role access to any endpoint | `SecurityTest` matrix (7 endpoints × 4 roles + anonymous) |
| Forged attribution | `recordedByIsTheAuthenticatedUserAndCannotBeSpoofed`, `systemEventTypesCannotBeWrittenByCallers` |
| Evidence destruction through retention | `windowBelowTheLegalMinimumIsRejected`, `verifyFlagsAnArchiveRunBelowTheFloor` |
| DB admin rewrites or truncates the chain | `fullRewriteFoolsAPlainHashChainButNotTheMac`, `tailTruncationIsCaughtByAnExternalAnchor` |
| Corrupt row crashes verification | `CorruptRecordTest` |
| Partial writes after a failure | `FaultInjectionTest` |

## Quality gates (`mvn verify`, run by CI on every push)

| Gate | Tool |
|---|---|
| Static analysis | `javac -Xlint:all -Werror` |
| Bugs + security (SAST) | SpotBugs + FindSecBugs. Suppressions listed and justified in `spotbugs-exclude.xml` |
| Dependencies (SCA) | Dependabot weekly updates (`.github/dependabot.yml`) |
| Tests + coverage | JUnit 5, AssertJ, Spring MockMvc, spring-security-test; JaCoCo gate |
| Performance | `PerfBenchmarkTest` (opt-in, tag `perf`) |

## Performance (cloud container, SQLite WAL, Hikari pool, MACs on)

Reproduce with `mvn test -Dtest=PerfBenchmarkTest -Dperf.excluded=none`.

| Operation | Result |
|---|---|
| Append (each a durable transaction) | ~2,100 events/s |
| Full verify, 10,500 records (hashes + MACs) | ~0.5 s |
| Query page at depth 9,000 (keyset) | ~4 ms |

## Not covered, and why

| Gap | Reason / mitigation |
|---|---|
| Multi-process writers on one file | The lock is taken inside each transaction and a timeout returns 503 (tested with a second connection), but only one service process is tested. Production target is Postgres |
| Load / soak testing | Out of scope for a prototype; the benchmark is indicative |
| Property-based fuzzing of canonical JSON | Would add a dependency (jqwik); parametrized cases cover key properties |
| Cross-language verifier | Algorithm specified in `HashChain` and `02_ARCHITECTURE.md`; not built in a second language |
| OAuth2 / OIDC tokens | HTTP Basic with bcrypt users is implemented and tested; tokens would replace only `SecurityConfig` |
| Export completeness | A recipient can't prove no matching record was left out of a bundle (needs per-filter commitments) |
