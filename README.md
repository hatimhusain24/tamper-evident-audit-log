# Tamper-Evident Audit Log Service

An append-only audit log. Every record is hash-chained and MAC-signed, so changing, deleting,
re-ordering, inserting or rewriting history in the data store is **detected** by
`GET /v1/audit/verify`. Redaction, retention archival, verifiable export and a regulator access
report all work **without breaking the chain**. Every endpoint is behind Spring Security with
role-based access.

**Stack:** Java 17, Spring Boot 3.5, Spring Security, SQLite (JDBC), SHA-256 and HMAC-SHA256 (JDK).

## Quick start (local demo)

Prerequisites: **JDK 17+** and **Maven 3.9+**.

```bash
mvn verify                                                   # build, 180 tests, coverage gate, SpotBugs
java -jar target/audit-log.jar --spring.profiles.active=dev  # http://localhost:8080
```

The `dev` profile adds four demo users, a demo HMAC key and Swagger UI. Without it the service
**refuses to start**, because no users or key are configured (fail closed).

| User | Password | Role | Can |
|---|---|---|---|
| `writer` | `writer-pass` | WRITER | append events |
| `reader` | `reader-pass` | READER | query and verify (sensitive fields masked) |
| `compliance` | `compliance-pass` | COMPLIANCE | query unmasked, export, access reports |
| `admin` | `admin-pass` | ADMIN | redaction, retention, query, verify, metrics |

Open **http://localhost:8080/docs**, click **Authorize**, and log in as one of the users above.

## Validate end-to-end (the flow from the brief)

1. As `writer`, `POST /v1/audit/events` (the example body is prefilled) two or three times.
2. As `reader`, `GET /v1/audit/events?resourceId=acc-1001`: `ssn` and `accountNumber` show as `***`.
3. As `reader`, `GET /v1/audit/verify` → `"valid": true`. Note `headSeq` and `headHash`.
4. **Tamper** directly in `audit.db`, bypassing the API, with
   [DB Browser for SQLite](https://sqlitebrowser.org) or `sqlite3`:
   ```sql
   UPDATE events SET actor_id = 'mallory' WHERE seq = 2;
   ```
5. `GET /v1/audit/verify` again → `"valid": false, "firstInvalidSeq": 2, "violation": "HASH_MISMATCH"`.

All of this, plus a full chain rewrite and tail truncation, runs automatically in the test suite.

## API

| Method | Path | Role | Purpose |
|---|---|---|---|
| `POST` | `/v1/audit/events` | WRITER | Append an event. Optional `Idempotency-Key` header makes retries safe |
| `GET` | `/v1/audit/events` | READER, COMPLIANCE, ADMIN | Filter by `actorId`, `resourceType`, `resourceId`, `eventType`, `from`/`to`; keyset pagination (`limit`, `cursor`) |
| `GET` | `/v1/audit/verify` | READER, COMPLIANCE, ADMIN | Walk the chain: `valid`, `firstInvalidSeq`, `violation`, `headHash`. Optional `anchorSeq` + `anchorHash` |
| `POST` | `/v1/audit/events/{seq}/redactions` | ADMIN | Redact payload fields without breaking the chain |
| `POST` | `/v1/audit/retention/run` | ADMIN | Archive records older than the window (never below the legal minimum) |
| `GET` | `/v1/audit/export?actorId=` or `?resourceId=` | COMPLIANCE | Self-verifiable bundle |
| `POST` | `/v1/audit/reports/account-access` | COMPLIANCE | Scenario C regulator access report |
| `GET` | `/actuator/health` | public | Status only (includes a database check) |
| `GET` | `/actuator/metrics` | ADMIN | Micrometer metrics, e.g. `audit.verify.failures` |

There is **no update or delete endpoint**. Anything not listed is denied.
Errors use RFC 7807 problem details: 400 validation · 401 no or bad credentials · 403 wrong role ·
404 unknown seq · 409 invalid state or reused idempotency key · 413 body too large ·
415 not JSON · 429 rate limit · 503 database busy (retry).

The submitter of every record is the **authenticated user** (`recordedBy`, sealed into the hash).
`actorId` is who the event is about, as asserted by that submitter.

Verify an exported bundle **offline** (no server or database needed):

```bash
curl -s -u compliance:compliance-pass "http://localhost:8080/audit/export?resourceId=acc-1001" -o bundle.json
java -jar target/audit-log.jar verify-bundle bundle.json [trusted-head-hash]
```

## Configuration (production)

| Env var | Default | Meaning |
|---|---|---|
| `AUDIT_DB_PATH` | `audit.db` | SQLite file |
| `AUDIT_HMAC_KEY` | _none: required_ | Record MAC secret, ≥ 32 bytes, from a secret manager / KMS |
| `audit.security.users[n].*` | _none: required_ | `name`, `password-hash` (`{bcrypt}…` only), `roles` |
| `AUDIT_RETENTION_MIN_DAYS` | `2190` (6 years) | Legal minimum; nothing younger can ever be archived |
| `AUDIT_RETENTION_DAYS` | `2190` | Default retention window (must be ≥ the minimum) |
| `AUDIT_SENSITIVE_FIELDS` | `ssn,accountNumber,taxId,dateOfBirth` | Masked for READER |
| `AUDIT_MAX_REQUEST_BYTES` | `65536` | Larger bodies get 413 |
| `AUDIT_RATE_LIMIT_PER_MINUTE` | `600` | Per client IP, before authentication |

TLS: terminate at the load balancer, or set `server.ssl.*` with a keystore. Spring Security then
adds HSTS automatically. Swagger UI is off unless the `dev` profile is active.

## Quality gates (`mvn verify`, also run by CI on every push)

* Compiler with `-Xlint:all -Werror`: any warning fails the build
* 180 JUnit 5 tests: unit, API integration, security matrix, direct-database tampering,
  fault injection, concurrency, privacy
* JaCoCo coverage gate: line ≥ 90%, branch ≥ 85% (currently 96.1% / 92.0%); CI publishes the report
* SpotBugs + FindSecBugs: each suppression is explained in `spotbugs-exclude.xml`
* Dependabot: weekly dependency vulnerability updates
* Benchmark (opt-in): `mvn test -Dtest=PerfBenchmarkTest -Dperf.excluded=none`

## Project layout

```
src/main/java/com/audit/
  chain/       HashChain, ChainVerifier, IntegrityKey, records, offline CLI: pure, no I/O
  store/       AuditStore: the only class that touches the database
  security/    SecurityConfig (roles, fail-closed users), RequestGuardFilter (size + rate), LogSafe
  api/         AuditController, request/response DTOs, error mapping
  compliance/  AccessReportService + typed AccessReport (Scenario C)
src/test/java/com/audit/   unit, integration, security, fault-injection and benchmark tests
```

## Documentation

1. [Requirements & task plan](docs/01_REQUIREMENTS_AND_PLAN.md)
2. [Architecture, security, threat model, trade-offs](docs/02_ARCHITECTURE.md)
3. [Scenarios A & B: decomposition, execution, validation](docs/03_SCENARIOS_A_B.md)
4. [Scenario C: compliance requirement clarification](docs/04_SCENARIO_C_COMPLIANCE.md)
5. [AI usage log](docs/05_AI_USAGE_LOG.md)
6. [Testing approach, coverage & limitations](docs/06_TESTING.md)
7. [Final engineering summary](docs/07_ENGINEERING_SUMMARY.md)
8. [Attestation](ATTESTATION.md)
