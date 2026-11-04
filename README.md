# Tamper-Evident Audit Log Service

An append-only audit log. Every record is hash-chained, so changing, deleting, re-ordering or
inserting history in the data store is **detected** by `GET /audit/verify`. Redaction,
retention archival, verifiable export and a regulator access report all work **without breaking
the chain**.

**Stack:** Java 17, Spring Boot 3.5, SQLite (JDBC), SHA-256 (JDK). Swagger UI included.

## Quick start

Prerequisites: **JDK 17+** and **Maven 3.9+**.

```bash
mvn verify                       # compile, 85 tests, SpotBugs security checks
java -jar target/audit-log.jar   # starts on http://localhost:8080
```

Open **http://localhost:8080/docs** for Swagger UI. All endpoints can be tried from the browser.

## Validate end-to-end (the flow from the brief)

1. **Write** three events with `POST /audit/events` (example body is prefilled in Swagger), e.g.
   ```json
   {"eventType":"ACCOUNT_VIEWED","actorId":"emp-1","resourceType":"CLIENT_ACCOUNT",
    "resourceId":"acc-1001","payload":{"purpose":"client call","accountNumber":"9876543210"}}
   ```
2. **Query** with `GET /audit/events?resourceId=acc-1001`.
3. **Verify** with `GET /audit/verify` → `"valid": true`.
4. **Tamper** directly in the database file `audit.db`, bypassing the API. Use
   [DB Browser for SQLite](https://sqlitebrowser.org) or the `sqlite3` CLI:
   ```sql
   UPDATE events SET actor_id = 'mallory' WHERE seq = 2;
   ```
5. **Verify again** → `"valid": false, "firstInvalidSeq": 2, "violation": "HASH_MISMATCH"`.

The same flow runs automatically in `ScenarioAApiTest`.

## API

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/audit/events` | Append an event (server assigns `seq`, `timestamp`, hashes) |
| `GET` | `/audit/events` | Filter by `actorId`, `resourceType`, `resourceId`, `eventType`, `from`/`to`; `limit` + `cursor` keyset pagination |
| `GET` | `/audit/verify` | Walk the chain → `valid`, `firstInvalidSeq`, `violation`, `headHash` |
| `POST` | `/audit/events/{seq}/redactions` 🔒 | Redact payload fields without breaking the chain |
| `POST` | `/audit/retention/run` 🔒 | Archive (tombstone) records older than the retention window |
| `GET` | `/audit/export?actorId=` or `?resourceId=` | Self-verifiable bundle |
| `GET` | `/audit/reports/account-access` 🔒 | Scenario C regulator access report |

There is **no update or delete endpoint**. 🔒 = requires the `X-Admin-Key` header when `AUDIT_ADMIN_KEY` is set.
Errors use RFC 7807 problem details: 400 validation, 401 admin key, 404 unknown seq, 409 invalid state.

Verify an exported bundle **offline** (no server or database needed):

```bash
curl -s "http://localhost:8080/audit/export?resourceId=acc-1001" -o bundle.json
java -jar target/audit-log.jar verify-bundle bundle.json [trusted-head-hash]
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `AUDIT_DB_PATH` | `audit.db` | SQLite file |
| `AUDIT_RETENTION_DAYS` | `365` | Retention window used by `/audit/retention/run` |
| `AUDIT_ADMIN_KEY` | _unset_ | If set, required for 🔒 endpoints |

## Quality gates (`mvn verify`, also run by CI on every push)

* Compiler with `-Xlint:all -Werror`: any warning fails the build
* 85 JUnit 5 tests: unit, API integration, direct-database tampering, concurrency, privacy
* SpotBugs + FindSecBugs: each suppression is explained in `spotbugs-exclude.xml`

## Project layout

```
src/main/java/com/audit/
  chain/       HashChain (hashing, verify, bundle verify), ChainVerifier, records: pure, no I/O
  store/       AuditStore: the only class that touches the database
  api/         AuditController, request/response DTOs, error mapping
  compliance/  AccessReportService (Scenario C)
src/test/java/com/audit/   unit + integration tests per scenario
```

## Documentation

1. [Requirements & task plan](docs/01_REQUIREMENTS_AND_PLAN.md)
2. [Architecture, data model, threat model, trade-offs](docs/02_ARCHITECTURE.md)
3. [Scenarios A & B: decomposition, execution, validation](docs/03_SCENARIOS_A_B.md)
4. [Scenario C: compliance requirement clarification](docs/04_SCENARIO_C_COMPLIANCE.md)
5. [AI usage log](docs/05_AI_USAGE_LOG.md)
6. [Testing approach & limitations](docs/06_TESTING.md)
7. [Final engineering summary](docs/07_ENGINEERING_SUMMARY.md)
8. [Attestation](ATTESTATION.md)
