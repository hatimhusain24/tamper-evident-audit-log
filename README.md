# Tamper-Evident Audit Log Service

An append-only audit log. Every record is hash-chained, so changing, deleting, re-ordering or
inserting history in the data store is **detected** by `GET /audit/verify`. Redaction,
retention archival, verifiable export and a regulator access report all work **without breaking
the chain**.

**Stack:** Python 3.11+, FastAPI, SQLite (stdlib), SHA-256 (stdlib). Three runtime dependencies.

## Quick start

```powershell
# Windows (PowerShell)
python -m venv .venv; .venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt
uvicorn app.main:create_app --factory --reload
```

```bash
# macOS / Linux
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:create_app --factory --reload
```

Open **http://127.0.0.1:8000/docs** for interactive Swagger UI (the OpenAPI schema is generated
from `app/models.py`).

## Validate end-to-end (the flow from the brief)

With the server running, in a second terminal:

```bash
python scripts/demo.py
```

The script writes events, queries them, verifies the chain, **edits a row directly in SQLite**,
verifies again (`HASH_MISMATCH` at that seq), then exercises redaction, export and the compliance
report. To tamper by hand:

```bash
python -c "import sqlite3; c=sqlite3.connect('audit.db'); c.execute(\"UPDATE events SET actor_id='mallory' WHERE seq=1\"); c.commit()"
curl http://127.0.0.1:8000/audit/verify
```

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

Verify an exported bundle **offline** (stdlib only, no server needed):

```bash
curl -s "http://127.0.0.1:8000/audit/export?resourceId=acc-1" -o bundle.json
python -m app.verify_bundle bundle.json --expected-head <headHash from a trusted checkpoint>
```

## Configuration

| Env var | Default | Meaning |
|---|---|---|
| `AUDIT_DB_PATH` | `audit.db` | SQLite file |
| `AUDIT_RETENTION_DAYS` | `365` | Retention window used by `/audit/retention/run` |
| `AUDIT_ADMIN_KEY` | _unset_ | If set, required for 🔒 endpoints |

## Quality gates

```bash
ruff check .     # lint + bandit security rules
pytest -q        # 60 unit + integration tests
```

CI runs both on every push (`.github/workflows/ci.yml`).

## Project layout

```
app/chain.py          hash chain core: pure functions, no I/O (hashing, verify, bundle verify)
app/store.py          SQLite persistence: the only module that touches the DB
app/models.py         API schemas and validation
app/main.py           HTTP routes
app/compliance.py     Scenario C report
app/verify_bundle.py  offline bundle verifier CLI
scripts/demo.py       end-to-end demo
tests/                unit (chain) + integration (API, tamper, redaction, retention, export, compliance)
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
