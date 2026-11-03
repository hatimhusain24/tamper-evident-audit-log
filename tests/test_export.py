"""Scenario B: export bundles are independently verifiable offline."""

import copy
import json

import pytest

from app.chain import record_hash, verify_bundle
from app.verify_bundle import main as cli
from tests.conftest import event


@pytest.fixture
def bundle(client):
    for i in range(1, 7):
        client.post("/audit/events", json=event(i))  # actor user-1 owns seq 1, 3, 5
    return client.get("/audit/export", params={"actorId": "user-1"}).json()


def test_bundle_contains_only_requested_records_and_verifies(bundle):
    assert [r["seq"] for r in bundle["records"]] == [1, 3, 5]
    assert [link["seq"] for link in bundle["chain"]] == list(range(1, 7))
    result = verify_bundle(bundle)
    assert result["valid"] and result["recordsVerified"] == 3 and result["headSeq"] == 6


def test_export_by_resource_and_empty_result(client, bundle):
    by_resource = client.get("/audit/export", params={"resourceId": "acc-0"}).json()
    assert [r["seq"] for r in by_resource["records"]] == [3, 6]
    empty = client.get("/audit/export", params={"actorId": "nobody"}).json()
    assert empty["records"] == [] and empty["chain"] == [] and verify_bundle(empty)["valid"]


@pytest.mark.parametrize("params", [{}, {"actorId": "a", "resourceId": "b"}])
def test_export_requires_exactly_one_filter(client, params):
    assert client.get("/audit/export", params=params).status_code == 422


def rehash(b):
    b["records"][1]["actorId"] = "mallory"
    b["records"][1]["hash"] = record_hash(b["records"][1])


@pytest.mark.parametrize("mutate, violation", [
    (lambda b: b["records"][1]["payload"].update(n=999), "PAYLOAD_TAMPERED"),
    (lambda b: b["records"][1].update(actorId="mallory"), "HASH_MISMATCH"),
    (rehash, "NOT_IN_CHAIN"),
    (lambda b: b["chain"].pop(2), "CHAIN_LINK_BROKEN"),
    (lambda b: b["head"].update(hash="0" * 64), "HEAD_MISMATCH"),
])
def test_altered_bundle_fails(bundle, mutate, violation):
    tampered = copy.deepcopy(bundle)
    mutate(tampered)
    assert verify_bundle(tampered)["violation"] == violation


def test_bundle_with_redacted_and_archived_records_verifies(client):
    for i in range(1, 5):
        client.post("/audit/events", json=event(i))
    client.post("/audit/events/3/redactions",
                json={"fields": ["accountNumber"], "reason": "erasure", "requestedBy": "dpo"})
    client.post("/audit/retention/run", json={"olderThanDays": 0})
    client.post("/audit/events", json=event(7))
    b = client.get("/audit/export", params={"actorId": "user-1"}).json()
    assert [r["seq"] for r in b["records"]] == [7] and verify_bundle(b)["valid"]


def test_offline_cli(bundle, tmp_path, capsys):
    path = tmp_path / "bundle.json"
    path.write_text(json.dumps(bundle))
    assert cli([str(path)]) == 0
    assert cli([str(path), "--expected-head", bundle["head"]["hash"]]) == 0
    assert cli([str(path), "--expected-head", "f" * 64]) == 1
    assert '"HEAD_MISMATCH"' in capsys.readouterr().out
