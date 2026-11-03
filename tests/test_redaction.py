"""Scenario B: structured redaction keeps the chain verifiable and is itself audited."""

import pathlib

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from tests.conftest import event

REDACT = {"fields": ["accountNumber"], "reason": "GDPR erasure request #77", "requestedBy": "dpo-1"}


@pytest.fixture
def seeded(client):
    for i in range(1, 4):
        client.post("/audit/events", json=event(i))
    return client


def test_redaction_removes_value_but_chain_still_verifies(seeded):
    res = seeded.post("/audit/events/2/redactions", json=REDACT)
    assert res.status_code == 201
    audit = res.json()
    assert audit["eventType"] == "RECORD_REDACTED" and audit["actorId"] == "dpo-1"
    assert audit["payload"] == {"targetSeq": 2, "fields": ["accountNumber"],
                                "reason": REDACT["reason"]}

    record = seeded.get("/audit/events", params={"limit": 2, "cursor": 1}).json()["items"][0]
    assert record["payload"]["accountNumber"] == "[REDACTED]"
    assert record["payload"]["n"] == 2  # other fields untouched
    assert seeded.get("/audit/verify").json()["valid"]


def test_redacted_value_is_gone_from_raw_database_files(seeded, db_path):
    seeded.post("/audit/events/2/redactions", json=REDACT)
    for path in pathlib.Path(db_path).parent.glob("audit.db*"):  # main file + WAL/SHM
        assert b"990002" not in path.read_bytes(), path


@pytest.mark.parametrize("seq, body, status", [
    (99, REDACT, 404),
    (2, REDACT | {"fields": ["nope"]}, 409),
    (2, REDACT | {"fields": []}, 422),
])
def test_redaction_errors(seeded, seq, body, status):
    assert seeded.post(f"/audit/events/{seq}/redactions", json=body).status_code == status


def test_double_redaction_and_system_events_rejected(seeded):
    seeded.post("/audit/events/2/redactions", json=REDACT)
    assert seeded.post("/audit/events/2/redactions", json=REDACT).status_code == 409
    assert seeded.post("/audit/events/4/redactions",  # seq 4 is the RECORD_REDACTED event
                       json=REDACT | {"fields": ["reason"]}).status_code == 409


def test_forged_redaction_in_db_is_detected(seeded, tamper):
    tamper("""UPDATE events SET payload = json_set(payload, '$.accountNumber', '[REDACTED]'),
              salts = json_remove(salts, '$.accountNumber') WHERE seq = 2""")
    result = seeded.get("/audit/verify").json()
    assert (result["violation"], result["firstInvalidSeq"]) == ("UNAUTHORIZED_REDACTION", 2)


def test_admin_key_required_when_configured(db_path):
    client = TestClient(create_app(db_path, admin_key="s3cret"))
    client.post("/audit/events", json=event())
    assert client.post("/audit/events/1/redactions", json=REDACT).status_code == 401
    ok = client.post("/audit/events/1/redactions", json=REDACT, headers={"X-Admin-Key": "s3cret"})
    assert ok.status_code == 201
