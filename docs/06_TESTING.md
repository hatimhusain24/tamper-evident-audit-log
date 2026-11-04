# 06 — Testing Approach, Coverage & Limitations

## Strategy

| Layer | What | Where |
|---|---|---|
| **Unit (pure)** | Hash chain, every violation type, edge-case payloads, malformed bundles | `chain/HashChainTest` (23) |
| **Unit (store, filter)** | Clock stepping back, retention window and floor, HMAC key rotation; chunked-body cut-off, trusted-proxy client IP, log sanitizing | `store/AuditStoreTest` (5), `security/RequestGuardFilterTest` (6) |
| **Integration (Spring + real SQLite + real auth)** | Every endpoint through MockMvc with HTTP Basic users on a real database file | `ScenarioAApiTest` (28), `RedactionTest` (8), `RetentionTest` (12), `ExportTest` (15), `ComplianceReportTest` (7) |
| **Security** | Endpoint × role × outcome matrix, anonymous access, wrong passwords, spoofing, masking, headers incl. HSTS, CSRF, versioned paths, fail-closed config | `SecurityTest` (50) |
| **Adversarial integrity** | Raw SQL bypassing the API and triggers; full chain rewrite; tail truncation; key validation | `tamper(...)` in `ApiTestBase`, `IntegrityKeyTest` (9) |
| **OAuth2 / JWT** | Valid token and `sub` → recordedBy; roles and scopes from claims; expired, not-yet-valid, wrong issuer/audience, too long, no exp, other key, HS256 confusion, `alg:none`; password expiry; dev token tool; fail-closed config | `OAuth2JwtTest` (11) |
| **Incremental verify** | Only post-checkpoint records, agreement with full verify, tampering after the checkpoint, changed or truncated anchor, redactions and tombstones, fallback | `IncrementalVerifyTest` (6) |
| **Multi-instance** | Two independent stores on one database (100 concurrent writes, no fork); shared database rate limiter | `MultiInstanceTest` (4) |
| **Object-level authorization** | Scoped reader sees only its accounts, cross-account queries return nothing, scoped pagination, LIKE-wildcard escaping, scoped writer and bulk-operation denials, startup validation | `ResourceScopeTest` (8) |
| **Structured logging** | Tamper alert as a JSON line with user and request id; no password in failed-login logs; newline injection | `StructuredLoggingTest` (3) |
| **Checkpoints** | Signed checkpoints, automatic truncation detection, edited checkpoint file, no checkpoint of broken chains | `CheckpointTest` (8) |
| **Encryption at rest** | No plaintext PII in raw DB files, plaintext via API, redaction, tampered ciphertext, wrong key | `EncryptionAtRestTest` (7) |
| **Corrupt data** | Unreadable JSON, NULL columns, non-hex salts, un-archived tombstones → `CORRUPT_RECORD`, reads keep working | `CorruptRecordTest` (8) |
| **Fault injection** | Insert failure mid-redaction / mid-archive rolls back; no lost seq; DB lock held by another process → 503 | `FaultInjectionTest` (4) |
| **Abuse limits** | Body-size 413, rate limit 429 (also before auth), idempotent retries, concurrent duplicates | `RequestGuardTest` (5), `IdempotencyTest` (6) |
| **Boundaries** | Last allowed value passes, one more fails (32 KB payload, 128-char ids, 64-char type, 50 fields, 500-char reason, page 500) | `BoundaryTest` (6) |
| **Concurrency** | 80 writes from an 8-thread pool, then full verify; 16 concurrent retries with one key | `concurrentWritersNeverForkTheChain`, `concurrentRetriesWriteExactlyOnce` |

**239 tests, 0 skipped, about 1.5 minutes.** No mocks: tests use the real database, real Spring
Security and real HTTP Basic. Tests assert the **exact violation and location** (`violation`,
`firstInvalidSeq`), not only `valid == false`. Time-dependent behaviour (6-year retention, rate
windows, clock corrections) runs on a movable `TestClock`, so the real legal floor is tested
rather than switched off.

Tests were checked to discriminate: removing the WAL checkpoint fails the privacy test (re-checked
after encryption was added, using a non-encrypted field), verifying a rewritten chain without the
key passes while the keyed verify fails it, and a bundle with a dropped record passes hash checks
but fails the signature.

## Coverage (JaCoCo, enforced in `mvn verify`)

| Counter | Covered | Gate |
|---|---|---|
| Line | **95.6%** | ≥ 90% |
| Branch | **88.6%** | ≥ 85% |
| Method | **97.2%** | — |

Report: `target/site/jacoco/index.html` locally; the `reports` artifact of each CI run.
Uncovered lines are mostly `AuditLogApplication.main` and defensive branches for JVM-guaranteed
algorithms (`NoSuchAlgorithmException` for SHA-256 / HmacSHA256).

**Risk-based coverage** (what line coverage alone would hide):

| Risk | Covered by |
|---|---|
| Anonymous or wrong-role access to any endpoint | `SecurityTest` matrix (7 endpoints × 4 roles + anonymous) |
| Reading or writing another client's records (IDOR / BOLA) | `ResourceScopeTest` |
| Forged attribution | `recordedByIsTheAuthenticatedUserAndCannotBeSpoofed`, `systemEventTypesCannotBeWrittenByCallers` |
| Evidence destruction through retention | `windowBelowTheLegalMinimumIsRejected`, `verifyFlagsAnArchiveRunBelowTheFloor` |
| DB admin rewrites or truncates the chain | `fullRewriteFoolsAPlainHashChainButNotTheMac`, `truncationAfterACheckpointIsCaughtByAPlainVerify` |
| Records dropped from an export | `droppedRecordIsInvisibleToHashesButBreaksTheSignature` |
| PII readable from the database file | `sensitiveValuesNeverReachTheDiskInPlaintext` |
| Key rotation breaks old records | `keyRotationKeepsOldRecordsVerifiable` |
| Rate limit evaded or shared behind a proxy | `clientsBehindATrustedProxyGetTheirOwnLimit`, `forwardedForFromAnUntrustedCallerIsIgnored` |
| Corrupt row crashes verification | `CorruptRecordTest` |
| Partial writes after a failure | `FaultInjectionTest` |

## Quality gates (`mvn verify`, run by CI on every push)

| Gate | Tool |
|---|---|
| Static analysis | `javac -Xlint:all -Werror` |
| Bugs + security (SAST) | SpotBugs + FindSecBugs. Suppressions listed and justified in `spotbugs-exclude.xml` |
| Dependencies (SCA) | Dependabot weekly updates; OWASP dependency-check weekly (`security-scan.yml`, fails on CVSS ≥ 7) |
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
| Live identity provider | JWT validation is tested with locally signed tokens and a configured public key; the JWKS fetch from a real IdP is not exercised in tests |
| Multi-host deployment | Two instances on one database file are tested; SQLite can't span hosts (Postgres would) |
| Real TLS handshake | The `tls` profile is configuration only; HSTS is tested with MockMvc `secure(true)`, not with a live certificate |
| OWASP scan locally | Needs the NVD database download and an API key; runs weekly in CI instead of on every build |
