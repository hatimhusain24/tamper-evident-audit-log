# 05 — AI Usage Log & Traceability

## Tooling and governance

| | |
|---|---|
| **AI tool** | Claude Code (Anthropic), agentic coding assistant |
| **Mode of use** | The engineer gave the brief and constraints. The AI drafted the plan, code, tests and docs task by task. Each step went through automated quality gates before commit (first ruff + pytest, after the Java port `mvn verify`: compile with warnings as errors, tests, SpotBugs). Engineer review and sign-off are tracked in §4 and §5 |
| **Traceability** | Each commit = one task from [01_REQUIREMENTS_AND_PLAN.md](01_REQUIREMENTS_AND_PLAN.md) §4. AI use is disclosed here rather than in commit messages. This file records what was accepted, modified or rejected, and why |
| **Secure AI usage** | Only the assignment brief and generic requirements were shared with the AI. No credentials, production code, client data or internal hostnames. No secrets in the repo (admin key comes from an env var). AI-generated code passes security static analysis (SpotBugs + FindSecBugs). Raw SQL uses only fixed column names; values are always bound parameters |

## 1. Prompts

The engineer gave **one main instruction** and then a few follow-ups. The AI split the work into
tasks and ran them on its own. There were no separate prompts per task.

**P0, main instruction (summary):** build the audit log service exactly as the brief specifies
(Scenarios A, B, C and every §7 deliverable). Constraints: *efficient, simple, minimal code, easy
to explain in a live defense; periodic commits, not one; private repo; attestation and AI log
required.*

From P0 the AI wrote the task plan (T1–T9 in [01](01_REQUIREMENTS_AND_PLAN.md) §4). It then used
each row (intent, constraints, acceptance criteria) as its own task definition. For example, T3:

> Hash-chain core as pure functions with no I/O. Deterministic across languages; redaction must
> later be possible without breaking the chain; report the *first* bad seq with a typed violation.
> Acceptance: a unit test per tamper type, including an attacker who rehashes the edited record.

**Follow-up prompts from the engineer:**

| # | Prompt (summary) | Result |
|---|------------------|--------|
| P1 | Use my personal email for commits | Git identity changed |
| P2 | Keep commit messages short and simple | Messages rewritten; AI use is disclosed in this log instead |
| P3 | Sign-off boxes can't be clicked | Changed to a `- [ ]` checklist (§4) |
| P4 | Check the work against the brief and run the app in a browser | Ran the full tamper flow in Swagger UI; listed the steps that are still open |
| P5 | Make this log accurate | Prompts and decision log reworded |
| P6 | Should this have been Java Spring Boot? | The brief names no stack; the AI first recommended keeping Python because of the deadline |
| P7 | Switch to Java Spring Boot and test all scenarios, including edge cases | Ported to Java 17 + Spring Boot with 85 tests; Python version removed |
| P8 | Fix everything in the lead's evaluation scorecard step by step, with unit tests and coverage; commit as each part is done, not all at once | Remediation in §6: 8 tasks, 180 tests, coverage gate |
| P9 | List what is still missing from the scorecard, then complete every small and medium item precisely | Second round in §6: versioning, proxy-aware rate limit, signed bundles and checkpoints, key rotation, encryption at rest, dependency scan, TLS profile; 207 tests |
| P10 | Merge the pending dependency PRs | All 7 Dependabot PRs tested and merged, incl. Spring Boot 4.1 (see below) |
| P11 | Do per-resource access (IDOR/BOLA) and JSON logs | Resource scopes and ECS logs with user + request id; 218 tests |
| P12 | Add OAuth2 with Spring Security, and remove the single-instance and full-verify limits, following the brief and the evaluation | JWT resource server, password expiry, incremental verify, shared rate limits, two-instance test; 239 tests |

## 2. Decision log: generated / modified / rejected

Most of these decisions were made **by the AI while generating the code**: options it considered
and rejected, and problems its own tests or lint caught. They are recorded so the engineer can
review and challenge them (§4). They are not a record of the engineer's own review.
Decisions 1–18 come from the first (Python) version and carried over unchanged to Java; 19+ come
from the port.

| # | Area | Option considered | Outcome | Rationale |
|---|------|-------------|---------|-----------|
| 1 | Chain design | Store `contentHash` (fields only) and `prevHash` separately | **Rejected** | Security flaw: an attacker could edit record *k*, rehash it, patch *k+1*'s `prevHash` and stop. `prevHash` must be *inside* the hashed content. Test `HashChainTest.rehashingAnEditedRecordBreaksTheNextLink` guards this |
| 2 | Hash algorithm | SHA-256 | **Accepted** | FIPS-approved, stdlib, ample margin. BLAKE3 rejected (non-stdlib, no benefit at this scale) |
| 3 | Redaction | Hash payload values directly, unsalted | **Rejected** | Low-entropy PII (account numbers) is brute-forceable from an unsalted hash |
| 4 | Redaction | Re-compute the chain after redaction | **Rejected** | Makes legitimate rewrites indistinguishable from attacks |
| 5 | Redaction | Salted per-field commitments + chained `RECORD_REDACTED` | **Accepted** | Keeps tamper evidence and privacy; the redaction itself is accountable |
| 6 | Redaction | (initial version) UPDATE only | **Modified** | A raw-bytes test showed the old value persisted in `audit.db-wal`. Added WAL checkpoint + `secure_delete`. Confirmed the test fails without the fix |
| 7 | Retention | Move rows to an archive table with a new genesis | **Rejected** | Needs signed checkpoints to bridge the chains. Tombstones keep a single chain with less code |
| 8 | Retention | Tombstones without authorization | **Modified** | A DB admin could hide tampering by "archiving" a record. Added the chained `RECORDS_ARCHIVED` event and prefix/through-seq checks |
| 9 | Pagination | OFFSET/LIMIT | **Rejected** | O(n) deep pages, and rows skip or duplicate under concurrent appends. Keyset on `seq` instead |
| 10 | Timestamp | Accept a caller timestamp | **Rejected** | Allows backdating and breaks the ordering retention depends on. Server-assigned, monotonic |
| 11 | Persistence | SQLAlchemy ORM + Postgres | **Rejected for prototype** | Extra dependencies and setup with no benefit for the evaluation. The storage boundary is isolated in `store.py` |
| 12 | Export | Merkle inclusion proofs | **Deferred** | O(log n) proofs, but far more code. A linear skeleton is enough and easy to verify. Listed as future work |
| 13 | Security | Allow callers to write any eventType | **Modified** | Callers could forge `RECORD_REDACTED` / `RECORDS_ARCHIVED` authorizations. Reserved types are now rejected (400) |
| 14 | Lint | Generated code had long lines and an unused variable | **Modified** | Fixed when the ruff gate failed |
| 15 | Lint | `S608` (SQL built from strings) flagged | **Accepted with justification** | Only constant, whitelisted column names are interpolated; values are bound. `noqa` comments state why |
| 16 | Tests | Retention test expected `firstInvalidSeq == 3` | **Modified (test, not code)** | The verifier's answer (4) was correct: seq 3 was the legitimate archive event |
| 17 | Tests | Placeholder assertion `... or True` in the first draft of the privacy test | **Rejected** | It asserted nothing. Rewritten to scan the raw DB/WAL bytes |
| 18 | Scenario C | Start with the endpoint | **Rejected** | The requirement was clarified and committed first (`15c4754`), then implemented |
| 19 | Stack | Python + FastAPI (first version) | **Changed** to Java 17 + Spring Boot | The brief leaves the stack open; Java is the team's stack and the engineer's strongest language, which matters for the live change. Same design and tests |
| 20 | Persistence | JPA / Hibernate | **Rejected** | The chain needs exact control of SQL, triggers and pragmas; `JdbcTemplate` is smaller and clearer |
| 21 | Spring wiring | `@Repository` on a `final` store class | **Modified** | Spring's exception-translation proxy can't subclass a final class; `@Component` needs no proxy |
| 22 | Static analysis | SpotBugs reported 27 findings | **Triaged** | 24 record/DTO exposure warnings, 1 timing warning on public hashes, 2 SQL warnings on whitelisted SQL: all suppressed with reasons in `spotbugs-exclude.xml`. The admin key already used a constant-time compare |
| 23 | Tests | Third archive run expected to archive 0 records | **Modified (test)** | The previous archive event is also old enough, so 1 is correct and verify stays valid |
| 24 | Performance | First measurement: 458 appends/s | **Rejected** | The harness opened a new DB connection per write; with the app's Hikari pool it is ~2,700/s |
| 25 | API docs | Swagger showed placeholder `"string"` bodies | **Modified** | Added `@Schema` examples so the write call can be tried as is |

### Commit cadence (how the history was produced)

The first build (2026-11-03) and the Java port were generated by the AI agent working through the
planned tasks, committing as each task's quality gates passed. So those commits are minutes apart:
they show AI-paced generation, not hours of manual coding. The evaluation rework (§6) was done one
finding at a time, each fix committed and pushed when its tests passed. The engineer's own review
and edits appear as separate commits from the GitHub web UI.

## 3. Where AI was used

| Activity | AI role | Engineer role |
|---|---|---|
| Requirement analysis | Drafted interpretations, ambiguities, plan | Review and approve assumptions |
| Implementation | Generated the code task by task | Review design decisions (§2), own correctness |
| Debugging | Diagnosed the lint and test failures above | Confirm each fix |
| Test generation | Generated unit, integration and adversarial tests | Check tests actually discriminate (e.g. #6) |
| Documentation | Drafted all docs | Edit to own voice; must be able to defend every line |
| Review prep | Threat model, trade-off tables | Rehearse the live defense |

## 4. Human sign-off: high-impact changes (completed by the engineer)

High-impact changes are those that affect integrity guarantees, privacy or the API contract.

Tick a box by editing this file on GitHub (pencil icon) or locally: change `[ ]` to `[x]`, then commit.

- [x] Hash/chain format (`chain/HashChain`, `ChainVerifier`), commit `9a6bd6e`
- [x] Write path, timestamps, concurrency (`store/AuditStore`), commit `6a0dc2a`
- [x] Redaction scheme and physical erasure, commits `6a0dc2a`, `2a34015`
- [x] Retention tombstones and authorization, commits `6a0dc2a`, `2a34015`
- [x] Export bundle format and offline verifier, commits `6a0dc2a`, `2a34015`
- [x] Scenario C assumptions and scope, commits `15c4754`, `09d65b9`

Evaluation rework (to be reviewed and ticked by the engineer):

- [x] Access control: roles, fail-closed users, recordedBy, masking (`security/`), commit `fe973c1`
- [x] Record MACs and anchor verification (`IntegrityKey`, `ChainVerifier`), commit `ff96746`
- [x] Retention floor (`AuditStore.archive`, `ChainVerifier`), commit `613371e`
- [x] Corrupt-record handling and error mapping, commits `0e63b9c`, `66d2f94`
- [x] Request limits and idempotency (`RequestGuardFilter`, `appendOnce`), commit `343ee50`
- [x] Signed bundles and checkpoints (`SigningKey`, `CheckpointService`), commits `914eb0d`, `9812903`
- [x] HMAC key rotation and encryption at rest (`IntegrityKey`, `FieldCipher`), commits `38c7da9`, `ef638a9`
- [x] Per-resource authorization (`ResourceScopes`, scoped query), commit `0457009`
- [x] OAuth2 resource server and password expiry (`JwtSupport`, `SecurityConfig`), commit `422ad7e`
- [x] Incremental verify and multi-instance support (`verifyFrom`, `RateLimiter`), commits `963f1e6`, `ce929cf`

## 5. Engineer review log (engineer appends entries during review / rework)

| Date | What I reviewed or changed | AI involved? | Notes |
|------|----------------------------|--------------|-------|
| 2026-11-04 | Hash chain (Java): prevHash is inside each record's hash, so editing one record breaks all later ones | Yes (asked Claude to explain) | Approved |
| 2026-11-04 | Write path: server sets timestamp, never goes backwards; lock + BEGIN IMMEDIATE so the chain can't fork | Yes (asked Claude to explain) | Approved |
| 2026-11-04 | Redaction: value and salt removed, hash kept; logged as its own event; RedactionTest passes | No | Approved |
| 2026-11-04 | Retention: archived records keep their hashes, no false alarms; RetentionTest passes | No | Approved |
| 2026-11-04 | Export: bundle verifies offline with verify-bundle; tampered bundle fails; ExportTest passes | No | Approved |
| 2026-11-04 | Scenario C: agree with assumptions (reads count as access, no regulator login, payload hidden); tests pass | No | Approved |
| 2026-11-04 | Correction to my write-path row: the lock is now taken by a no-op write inside the transaction, not BEGIN IMMEDIATE (lock-timeout test found pooled connections breaking) | Yes (asked Claude to explain) | Approved the change |
| 2026-11-04 | Access control: deny-by-default, 4 roles, app won't start without users; export is COMPLIANCE only; SecurityTest passes | No | Approved |
| 2026-11-04 | Record MACs: a DB admin can recompute hashes but not MACs; full-rewrite test fails without the key | Yes (asked Claude to explain) | Approved; in production the key belongs in a KMS |
| 2026-11-04 | Retention floor: archiving below 6 years refused; verify flags violations; tests pass | No | Approved |
| 2026-11-04 | Corrupt rows give CORRUPT_RECORD instead of 500; failed writes roll back fully; tests pass | No | Approved |
| 2026-11-04 | Rate limit and body limit run before login; idempotency key prevents duplicate writes on retry; tests pass | No | Approved |
| 2026-11-04 | Signed bundles: a dropped record passes hash checks but fails the signature; checkpoints catch truncation; tests pass | Yes (asked Claude to explain) | Approved |
| 2026-11-04 | Key rotation keeps old records verifiable; SSN/account number encrypted on disk, plaintext via API; tests pass | No | Approved; would add rotation for the encryption key next |
| 2026-11-04 | Per-resource access: reader limited to acc-1* sees only those accounts; checked live in Swagger | No | Approved |
| 2026-11-04 | OAuth2: expired, wrong-issuer, wrong-key, HS256 and alg=none tokens all rejected; made a dev token and called the API | Yes (asked Claude to explain) | Approved; would test against a real Keycloak in CI |
| 2026-11-04 | Incremental verify only checks records after the last checkpoint (full verify still runs before each checkpoint); two instances writing to one DB never fork | Yes (asked Claude to explain) | Approved; understood the trade-off |

## 6. Evaluation remediation (scorecard of 2026-11-04, reviewed commit 2cffa62)

The lead's evaluation scored 64.10/100 with all three guardrails failed. Each finding below was
fixed with a regression test. The AI implemented the fixes. The engineer chose to fix all of them
(P8), which reverses the earlier AI-plan decision to leave authentication out of scope.

| Finding (scorecard ID) | Fix | Regression test | Commit |
|---|---|---|---|
| Corrupt row → HTTP 500, no seq (ARC-11, TEST-05, REQ-04) | `CORRUPT_RECORD` violation; queries tolerate bad rows; catch-all 500 without stack trace | `CorruptRecordTest`, `HashChainTest` | `0e63b9c` |
| `olderThanDays: 1e300` → 500 (SEC-05, P4) | `@Max(36500)` | `hugeRetentionWindowIsA400NotA500` | `0e63b9c` |
| CLI crashes on bundle without head (ARC-07) | `MALFORMED_BUNDLE` result | `bundleWithoutHeadIsMalformedNotACrash`, CLI test | `0e63b9c` |
| Retention can purge the whole log (ARC-06, P10) | 6-year floor enforced in the store; startup check; verify flags `RETENTION_POLICY_VIOLATION` | `windowBelowTheLegalMinimumIsRejected`, `verifyFlagsAnArchiveRunBelowTheFloor` | `613371e` |
| No security framework; key fails open (SEC-01, SEC-02) | Spring Security, deny by default; app won't start without bcrypt users | `SecurityTest` (fail-closed config, anonymous 401s) | `fe973c1` |
| No authorisation; spoofable actor (SEC-03, SEC-04) | Roles WRITER/READER/COMPLIANCE/ADMIN; `recordedBy` from login, in the hash; reserved report type | `SecurityTest` role matrix, spoofing tests | `fe973c1` |
| Raw PII to anyone (SEC-04, P1, P2) | Masking for READER; export COMPLIANCE only | `readersSeeSensitiveFieldsMaskedComplianceSeesThem` | `fe973c1` |
| Side-effecting GET (ARC-02, P5) | Report is a POST; typed `AccessReport` (CQ-02) | `reportIsNotAvailableAsAGet` | `fe973c1` |
| No keyed integrity or anchoring (ARC-08, SEC-07) | Per-record HMAC; `anchorSeq/anchorHash` on verify | `IntegrityKeyTest` (full rewrite, truncation) | `ff96746` |
| No logging, metrics, Actuator (SEC-08, CQ-04) | Security event log, `audit.verify.failures` metric, health with DB check | `tamperDetectionIsCountedForAlerting`, health tests | `da05f63` |
| Swagger always on; no SCA (SEC-09) | Swagger off unless `dev`; Dependabot | `swaggerIsOffByDefault` | `da05f63` |
| No rate limit, body limit, replay protection (SEC-06, P7) | Per-IP rate limit and 64 KB limit before auth; `Idempotency-Key` | `RequestGuardTest`, `IdempotencyTest`, `RequestGuardFilterTest` | `343ee50` |
| No rollback or lock tests (TEST-06) | Fault injection; lock timeout → 503. **Found and fixed pool poisoning** | `FaultInjectionTest` | `66d2f94` |
| No exact-boundary tests (TEST-03) | Boundary suite | `BoundaryTest` | `66d2f94` |
| Coverage not measured or reported (TEST-09) | JaCoCo gate (90/85), CI artifact; 96.1% line, 92.0% branch | build fails below the gate | `4afaae0` |
| Performance not reproducible | Benchmark in the repo (opt-in) | `PerfBenchmarkTest` | `4afaae0` |
| Doc drift from the Python version (ATT-05) | 422→400, thread count, line counts, test names, stale review note | — | docs commits |
| Attestation names no revision (ATT-01, ATT-02) | Repository, branch, tag and scope added | — | docs commits |

Decisions made during the rework:

| # | Decision | Alternatives rejected | Why |
|---|---|---|---|
| 26 | HTTP Basic with bcrypt users | OAuth2 resource server; mTLS | No identity provider in a local demo. Only `SecurityConfig` changes when moving to tokens |
| 27 | Keep `actorId`, add `recordedBy` | Force `actorId` = login | Services legitimately record actions by end users; regulators get both, and the submitter is unforgeable |
| 28 | MAC next to the hash, not instead of it | HMAC as the chain hash | Offline bundle recipients must verify without the server key |
| 29 | Export COMPLIANCE only | COMPLIANCE + ADMIN | Least privilege; the role-matrix test exposed that the first config allowed ADMIN |
| 30 | Take the SQLite lock with a no-op write | Driver's `transaction_mode=IMMEDIATE` | A failed lazy BEGIN poisoned pooled connections (found by the lock-timeout test) |
| 31 | 6-year default retention floor | Configurable with no floor | SEC 17a-4 broker-dealer records; anything shorter must be an explicit config change |

### Second round (P9): remaining small and medium items

| Remaining gap (scorecard ID) | Fix | Regression test | Commit |
|---|---|---|---|
| No API versioning (ARC-02) | All endpoints under `/v1`; old paths denied | `unversionedPathsNoLongerExist` | `0fdfd66` |
| Rate limit shared by every client behind a load balancer (SEC-06) | `X-Forwarded-For` trusted only from `audit.trusted-proxies`; rightmost untrusted hop is the client | `RequestGuardFilterTest` (3 new) | `a57a502` |
| Export can't prove nothing was dropped (ARC-07) | Ed25519-signed bundles; public key at `/v1/audit/signing-key`; CLI `--public-key` | `droppedRecordIsInvisibleToHashesButBreaksTheSignature` and 3 more | `914eb0d` |
| Anchoring was manual (ARC-08) | Scheduled signed checkpoints; verify anchors to the latest automatically; edited file → `CHECKPOINT_INVALID` | `CheckpointTest` (8) | `9812903` |
| No HMAC key rotation (SEC-07) | MACs stored as `keyId:hex`; retired keys verify only; constant-time compare | `keyRotationKeepsOldRecordsVerifiable`, `macMatchingRejectsUnknownKeysAndMalformedValues` | `38c7da9` |
| PII plaintext at rest (SEC-07) | AES-256-GCM for sensitive fields; hashes over plaintext; reserved prefix refused | `EncryptionAtRestTest` (7) | `ef638a9` |
| No OWASP dependency check; no TLS config (SEC-09) | Weekly dependency-check workflow (CVSS ≥ 7 fails); `tls` profile | `httpsResponsesCarryHsts` | `c00b17f` |
| First-person lines in docs (ATT-05) | Rephrased neutrally | — | `fbe56bf` |

Still open by choice (large effort): OIDC/mTLS instead of Basic, multi-instance scaling (shared rate
limiter, Postgres), incremental verify, encryption-key rotation.

| # | Decision | Alternatives rejected | Why |
|---|---|---|---|
| 32 | Ed25519 for bundles and checkpoints | HMAC (needs the secret to verify); RSA | Recipients verify with a public key; small fast signatures in the JDK |
| 33 | Trusted-proxy list for `X-Forwarded-For` | Always trust the header; Tomcat `RemoteIpValve` | Always trusting lets clients dodge the limit; an explicit list is testable with MockMvc |
| 34 | Store `keyId:hex` in the existing `mac` column | A separate key-id column | No schema change; the MAC is self-describing |
| 35 | Encrypt only configured sensitive fields | Encrypt whole payloads | Non-sensitive fields stay queryable and readable in the DB; hashes stay over plaintext |
| 36 | Checkpoint file instead of a DB table | Same database | A checkpoint in the same DB can be deleted by the same attacker; a separate WORM location can't |
| 37 | Move the WAL privacy test to a non-encrypted field | Keep `accountNumber` | Once encrypted, `accountNumber` passed even without the WAL fix, so the test stopped proving anything (mutation-checked) |

### Dependency updates (Dependabot PRs #1-#7)

All seven were tested on an integration branch and merged only with the full gate green
(207 tests, coverage, SpotBugs).

| PR | Update | Follow-up needed |
|---|---|---|
| #1, #4 | `actions/checkout` v7, `actions/setup-java` v6 | Adjacent-line conflict in `ci.yml` resolved; `security-scan.yml` aligned |
| #2 | sqlite-jdbc 3.54.1.0 | None |
| #3, #7 | FindSecBugs 1.14.0, SpotBugs plugin 4.10.5.0 | New `XSS_SERVLET` finding: the filter's error body is now serialized with Jackson instead of hand-built JSON |
| #6, #5 | **Spring Boot 4.1.2**, springdoc 3.2.0 | `HttpStatus.PAYLOAD_TOO_LARGE` renamed `CONTENT_TOO_LARGE`; test starter `spring-boot-starter-webmvc-test` and the new `AutoConfigureMockMvc` package; null-safe role check (Spring Security 7 marks `getAuthority()` nullable). The jar was started and probed live |

### Third round (P11): object-level authorization and structured logs

| Gap (scorecard ID) | Fix | Regression test | Commit |
|---|---|---|---|
| Any reader could read any client's records: IDOR / BOLA (SEC-03, TEST-04) | Per-user resource scopes; READERs must declare them; SQL-level filtering; scoped writes; bulk operations need an unscoped user | `ResourceScopeTest` (8) | `0457009` |
| Logs not machine-readable or correlated (CQ-04, SEC-08) | ECS JSON logs; user and request id on every line; `X-Request-Id` | `StructuredLoggingTest` (3) | `1d1c7d3` |

| # | Decision | Alternatives rejected | Why |
|---|---|---|---|
| 38 | Filter scopes inside the SQL query | Filter results after the query | Post-filtering breaks page sizes and still reads other clients' rows |
| 39 | Out-of-scope query returns an empty list, out-of-scope write returns 403 | 403 for reads too | An empty result doesn't reveal whether another client's account exists |
| 40 | READER must have scopes; other roles default to unrestricted | Scopes optional for everyone | Readers are the broad, many-user role; compliance and admin need the whole log by design |

### Fourth round (P12): OAuth2 and scaling

| Gap (scorecard ID) | Fix | Regression test | Commit |
|---|---|---|---|
| Basic auth only; no OAuth2/OIDC (SEC-01) | OAuth2 resource server (JWT): RS256, issuer, audience, expiry, max lifetime; roles and scopes from claims; dev token tool | `OAuth2JwtTest` (11) | `422ad7e` |
| No credential expiry (SEC-02) | Short-lived tokens; `password-expires-at` for Basic users | `expiredPasswordIsRejectedAndExpiryFollowsTheClock` | `422ad7e` |
| Missing `iat` let a long-lived token through | Expiry also capped relative to now (found by the token tests) | `invalidTokensAreRejected` | `422ad7e` |
| O(n) verify on every call (ARC-10) | Incremental verify from the signed checkpoint; checkpoint refuses a broken chain | `IncrementalVerifyTest` (6) | `963f1e6` |
| JVM-local lock and in-memory rate limiter (ARC-09, SEC-06) | Database-level serialization proven with two instances; database-backed shared rate limiter | `MultiInstanceTest` (4) | `ce929cf` |

| # | Decision | Alternatives rejected | Why |
|---|---|---|---|
| 41 | OAuth2 resource server with JWT; Basic kept as a mode | mTLS; dropping Basic | Matches the evaluation's suggestion; Basic stays useful for local demos and small deployments |
| 42 | RS256 only, JWKS from the issuer | Accept any algorithm | Blocks `alg:none` and HS256 key-confusion attacks (both tested) |
| 43 | Cap `exp` against now as well as `iat` | Trust `iat` | Spring fills a missing `iat` with `exp - 1s`; a test showed the bypass |
| 44 | Incremental verify as an option, full verify by default and before each checkpoint | Incremental by default | Redaction changes old records, so only a full walk proves them; the trade-off is documented |
| 45 | Database-backed rate limiter as an option | Redis | No extra infrastructure; the same database already serializes writes |

