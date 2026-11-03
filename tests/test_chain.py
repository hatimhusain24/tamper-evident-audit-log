"""Unit tests for the pure hash-chain core: every tamper type must be detected."""

import copy

import pytest

from app.chain import (
    GENESIS_HASH,
    REDACTED,
    build_record,
    canonical,
    record_hash,
    verify_chain,
)


def make_chain(n: int) -> list[dict]:
    chain, prev = [], GENESIS_HASH
    for i in range(1, n + 1):
        r = build_record(i, prev, f"2026-01-01T00:00:0{i}.000000Z", {
            "eventType": "RECORD_UPDATED", "actorId": f"user-{i}", "resourceType": "ACCOUNT",
            "resourceId": "acc-1", "payload": {"field": "email", "accountNumber": f"12345{i}"}})
        chain.append(r)
        prev = r["hash"]
    return chain


def test_canonical_json_is_key_order_independent():
    a = {"b": 1, "a": [1, {"y": 2, "x": 1}]}
    b = {"a": [1, {"x": 1, "y": 2}], "b": 1}
    assert canonical(a) == canonical(b)


def test_intact_chain_verifies():
    chain = make_chain(5)
    result = verify_chain(chain)
    assert result["valid"] and result["recordsChecked"] == 5
    assert result["headSeq"] == 5 and result["headHash"] == chain[-1]["hash"]


def test_empty_chain_is_valid():
    assert verify_chain([])["valid"]


@pytest.mark.parametrize("mutate, violation", [
    (lambda c: c[2].update(actorId="mallory"), "HASH_MISMATCH"),
    (lambda c: c[2]["payload"].update(field="password"), "PAYLOAD_TAMPERED"),
    (lambda c: c[2]["payload"].update(extra="x"), "PAYLOAD_TAMPERED"),
    (lambda c: c.pop(2), "SEQUENCE_GAP"),
    (lambda c: c[2].update(prevHash="f" * 64), "CHAIN_LINK_BROKEN"),
])
def test_tampering_is_detected_at_first_bad_record(mutate, violation):
    chain = make_chain(5)
    mutate(chain)
    result = verify_chain(chain)
    assert not result["valid"]
    assert result["violation"] == violation
    assert result["firstInvalidSeq"] in (3, 4)  # 4 only for deletion of seq 3


def test_rehashing_a_tampered_record_breaks_the_next_link():
    chain = make_chain(4)
    chain[1]["actorId"] = "mallory"
    chain[1]["hash"] = record_hash(chain[1])  # attacker recomputes the edited record's hash
    result = verify_chain(chain)
    assert result["violation"] == "CHAIN_LINK_BROKEN" and result["firstInvalidSeq"] == 3


def test_swapping_records_is_detected():
    chain = make_chain(4)
    chain[1], chain[2] = chain[2], chain[1]
    assert verify_chain(chain)["violation"] == "SEQUENCE_GAP"


def test_redaction_without_authorizing_event_is_flagged():
    chain = copy.deepcopy(make_chain(3))
    chain[0]["payload"]["accountNumber"] = REDACTED
    del chain[0]["salts"]["accountNumber"]
    result = verify_chain(chain)
    assert result["violation"] == "UNAUTHORIZED_REDACTION" and result["firstInvalidSeq"] == 1


def test_tombstone_without_policy_event_is_flagged():
    chain = make_chain(3)
    chain[0].update(archived=True, payload=None, actorId=None)
    result = verify_chain(chain)
    assert result["violation"] == "UNAUTHORIZED_ARCHIVE"
