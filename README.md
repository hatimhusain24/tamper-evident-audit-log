# Tamper-Evident Audit Log Service

An append-only audit log. Every record is hash-chained and MAC-signed, the head is checkpointed
with a signature, and sensitive fields are encrypted at rest. Changing, deleting, re-ordering,
inserting, rewriting or truncating history in the data store is **detected** by
`GET /v1/audit/verify`. Redaction, retention archival, verifiable export and a regulator access
report all work **without breaking the chain**. Every endpoint is behind Spring Security (OAuth2
access tokens and/or Basic) with
role-based access.

**Stack:** Java 17, Spring Boot 4.1, Spring Security 7, SQLite (JDBC); SHA-256, HMAC-SHA256, Ed25519 and
AES-256-GCM from the JDK.

## Quick start (local demo)

Prerequisites: **JDK 17+** and **Maven 3.9+**.

```bash
mvn verify                                                   # build, 239 tests, coverage gate, SpotBugs
java -jar target/audit-log.jar --spring.profiles.active=dev  # http://localhost:8080
```

The `dev` profile adds four demo users, demo keys, a dev token issuer and Swagger UI. Without it the
service **refuses to start**, because no identity provider, users or keys are configured (fail closed).

### Authentication modes

| `AUDIT_AUTH_MODE` | Callers send | Use |
|---|---|---|
| `jwt` (default) | `Authorization: Bearer <access token>` from your OIDC provider (Keycloak, Okta, Entra ID…) | Production |
| `basic` | HTTP Basic with configured users | Small/internal deployments |
| `both` | Either | Local development (dev profile), tests |

Tokens must be RS256-signed by `AUDIT_JWT_ISSUER` (keys from `AUDIT_JWT_JWK_SET_URI`), have audience
`audit-log`, and expire within 60 minutes. Claims: `sub` → `recordedBy`, `roles` → role,
`resource_scopes` → allowed resources (required for READER).

Try a token locally (dev profile running):

```bash
java -jar target/audit-log.jar issue-dev-token --key config/dev-jwt/private-key.pem --sub alice --roles READER --scopes "CLIENT_ACCOUNT:acc-1*"
curl -H "Authorization: Bearer <token>" http://localhost:8080/v1/audit/events
```

`config/dev-jwt/` holds a **dev-only** key pair standing in for an identity provider.

| User | Password | Role | Can |
|---|---|---|---|
| `writer` | `writer-pass` | WRITER | append events |
| `reader` | `reader-pass` | READER | query and verify, **only accounts `acc-1*`** (sensitive fields masked) |
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
| `GET` | `/v1/audit/verify` | READER, COMPLIANCE, ADMIN | Walk the chain: `valid`, `firstInvalidSeq`, `violation`, `headHash`. Checks against the latest signed checkpoint automatically; or pass `anchorSeq` + `anchorHash`. `mode=incremental` checks only records after the last checkpoint |
| `POST` | `/v1/audit/events/{seq}/redactions` | ADMIN | Redact payload fields without breaking the chain |
| `POST` | `/v1/audit/retention/run` | ADMIN | Archive records older than the window (never below the legal minimum) |
| `GET` | `/v1/audit/export?actorId=` or `?resourceId=` | COMPLIANCE | Self-verifiable bundle |
| `POST` | `/v1/audit/reports/account-access` | COMPLIANCE | Scenario C regulator access report |
| `POST` | `/v1/audit/checkpoints` | ADMIN | Write a signed head checkpoint now (also runs hourly) |
| `GET` | `/v1/audit/signing-key` | public | Ed25519 public key for checking bundles and checkpoints offline |
| `GET` | `/actuator/health` | public | Status only (includes a database check) |
| `GET` | `/actuator/metrics` | ADMIN | Micrometer metrics, e.g. `audit.verify.failures` |

There is **no update or delete endpoint**. Anything not listed is denied.
Errors use RFC 7807 problem details: 400 validation · 401 no or bad credentials · 403 wrong role ·
404 unknown seq · 409 invalid state or reused idempotency key · 413 body too large ·
415 not JSON · 429 rate limit · 503 database busy (retry).

The submitter of every record is the **authenticated user** (`recordedBy`, sealed into the hash).
`actorId` is who the event is about, as asserted by that submitter.

**Object-level access (resource scopes):** a user can be limited to resources, e.g.
`audit.security.users[n].resource-scopes=CLIENT_ACCOUNT:acc-1*`. READER users must have scopes;
queries return only in-scope records, scoped writers can only write their own resources, and bulk
operations (export, reports, redaction, retention, checkpoints) need an unscoped user.

Verify an exported bundle **offline** (no server or database needed):

```bash
curl -s -u compliance:compliance-pass "http://localhost:8080/audit/export?resourceId=acc-1001" -o bundle.json
curl -s "http://localhost:8080/v1/audit/signing-key"        # copy publicKey
java -jar target/audit-log.jar verify-bundle bundle.json --public-key <publicKey> [--head <trusted head hash>]
```

With `--public-key`, a record added, removed or edited after export fails as `SIGNATURE_INVALID`.

## Configuration (production)

| Env var | Default | Meaning |
|---|---|---|
| `AUDIT_DB_PATH` | `audit.db` | SQLite file |
| `AUDIT_HMAC_KEY` | _none: required_ | Record MAC secret, ≥ 32 bytes, from a secret manager / KMS |
| `AUDIT_HMAC_KEY_ID` / `AUDIT_HMAC_RETIRED_KEYS` | `k1` / _empty_ | Key rotation: new id for the new key; old keys as `id=secret,...` (verify only) |
| `AUDIT_SIGNING_PRIVATE_KEY` / `AUDIT_SIGNING_PUBLIC_KEY` | _none: required_ | Ed25519 key pair (base64 PKCS#8 / X.509) for bundles and checkpoints |
| `AUDIT_ENCRYPTION_KEY` | _none: required_ | AES-256 key (base64, 32 bytes) for sensitive fields at rest |
| `AUDIT_CHECKPOINT_FILE` / `AUDIT_CHECKPOINT_INTERVAL_MS` | `audit-checkpoints.jsonl` / 1 h | Signed checkpoints; put the file on WORM storage |
| `AUDIT_TRUSTED_PROXIES` | _empty_ | Load balancer IPs whose `X-Forwarded-For` is trusted for rate limiting |
| `AUDIT_RATE_LIMIT_STORE` | `memory` | `database` = one shared limit across several instances |

**Running more than one instance:** point them at the same database, set
`AUDIT_RATE_LIMIT_STORE=database` and share the checkpoint file location. Writes are serialized by the
database lock, not the JVM (tested with two instances). SQLite needs a local filesystem shared by the
instances; across hosts, move `AuditStore` to Postgres.
| `AUDIT_AUTH_MODE` | `jwt` | `jwt`, `basic` or `both` |
| `AUDIT_JWT_ISSUER` / `AUDIT_JWT_JWK_SET_URI` | _none: required for jwt_ | Trusted token issuer and its JWKS endpoint |
| `AUDIT_JWT_AUDIENCE` / `AUDIT_JWT_MAX_LIFETIME_MINUTES` | `audit-log` / `60` | Required audience; longest token lifetime accepted |
| `audit.security.users[n].*` | _none: required for basic_ | `name`, `password-hash` (`{bcrypt}…` only), `roles`, `resource-scopes` (required for READER), `password-expires-at` |
| `AUDIT_RETENTION_MIN_DAYS` | `2190` (6 years) | Legal minimum; nothing younger can ever be archived |
| `AUDIT_RETENTION_DAYS` | `2190` | Default retention window (must be ≥ the minimum) |
| `AUDIT_SENSITIVE_FIELDS` | `ssn,accountNumber,taxId,dateOfBirth` | Encrypted at rest and masked for READER |
| `AUDIT_MAX_REQUEST_BYTES` | `65536` | Larger bodies get 413 |
| `AUDIT_RATE_LIMIT_PER_MINUTE` | `600` | Per client IP, before authentication |

Logs: JSON (Elastic Common Schema) by default, with `user.name` and `request.id` on every line;
each response carries `X-Request-Id`. The dev profile prints readable text.

TLS: terminate at the load balancer (set `AUDIT_TRUSTED_PROXIES`), or run with the `tls` profile and
`AUDIT_TLS_KEYSTORE` / `AUDIT_TLS_KEYSTORE_PASSWORD` (PKCS12, TLS 1.3/1.2). Spring Security adds HSTS on
HTTPS. Swagger UI is off unless the `dev` profile is active.

## Quality gates (`mvn verify`, also run by CI on every push)

* Compiler with `-Xlint:all -Werror`: any warning fails the build
* 239 JUnit 5 tests: unit, API integration, OAuth2 token attacks, role matrix, object-level
  authorization, direct-database tampering, fault injection, encryption, checkpoints, incremental
  verify, multi-instance, logging, concurrency, privacy
* JaCoCo coverage gate: line ≥ 90%, branch ≥ 85% (currently 95.6% / 88.6%); CI publishes the report
* SpotBugs + FindSecBugs: each suppression is explained in `spotbugs-exclude.xml`
* Dependency scanning: Dependabot weekly, plus OWASP dependency-check weekly in CI (fails on CVSS ≥ 7;
  needs an `NVD_API_KEY` secret). Locally: `mvn -P security-scan verify -DnvdApiKey=...`
* Benchmark (opt-in): `mvn test -Dtest=PerfBenchmarkTest -Dperf.excluded=none`

## Project layout

```
src/main/java/com/audit/
  chain/       HashChain, ChainVerifier, IntegrityKey (MAC keys), SigningKey (Ed25519), records, offline CLI
  store/       AuditStore (the only class that touches the database), FieldCipher, CheckpointService
  security/    SecurityConfig (JWT/Basic, roles, fail closed), JwtSupport, DevTokenCli, ResourceScopes,
               RateLimiter (memory/database), RequestGuardFilter (size + rate),
               LogContextFilter (user + request id in logs), LogSafe
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
