import sqlite3

import pytest
from fastapi.testclient import TestClient

from app.main import create_app


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "audit.db")


@pytest.fixture
def client(db_path):
    return TestClient(create_app(db_path))


@pytest.fixture
def tamper(db_path):
    """Run raw SQL against the data store, bypassing the API (simulates a malicious DB admin)."""
    def run(sql: str, params=()):
        with sqlite3.connect(db_path) as conn:
            conn.execute(sql, params)
    return run


def event(i: int = 1, **overrides) -> dict:
    return {"eventType": "RECORD_UPDATED", "actorId": f"user-{i % 2}", "resourceType": "ACCOUNT",
            "resourceId": f"acc-{i % 3}", "payload": {"n": i, "accountNumber": f"99{i:04d}"}
            } | overrides
