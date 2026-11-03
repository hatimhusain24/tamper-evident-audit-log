"""Scenario A integration tests: write -> query -> verify -> tamper in DB -> verify again."""

import pytest

from tests.conftest import event


def seed(client, n=6):
    return [client.post("/audit/events", json=event(i)).json() for i in range(1, n + 1)]


def test_write_returns_chained_record(client):
    first, second = seed(client, 2)
    assert first["seq"] == 1 and first["prevHash"] == "0" * 64
    assert second["prevHash"] == first["hash"]
    assert first["timestamp"] <= second["timestamp"]
    assert "salts" not in first  # internal commitment salts are not part of the read model


@pytest.mark.parametrize("bad", [
    {"eventType": "lowercase"},
    {"actorId": ""},
    {"payload": "not-an-object"},
    {"payload": {"big": "x" * 40_000}},
    {"timestamp": "2020-01-01T00:00:00Z"},     # server assigns time: unknown field rejected
    {"eventType": "RECORD_REDACTED"},           # reserved system event cannot be forged
])
def test_write_validation(client, bad):
    assert client.post("/audit/events", json=event() | bad).status_code == 422


def test_no_update_or_delete_routes(client):
    seed(client, 1)
    for method in ("put", "patch", "delete"):
        assert getattr(client, method)("/audit/events/1").status_code in (404, 405)


def test_query_filters_combine(client):
    seed(client)
    items = client.get("/audit/events", params={"actorId": "user-1", "resourceType": "ACCOUNT",
                                                "resourceId": "acc-1"}).json()["items"]
    assert [e["seq"] for e in items] == [1]
    assert len(client.get("/audit/events", params={"eventType": "USER_LOGIN"}).json()["items"]) == 0


def test_query_time_range(client):
    records = seed(client, 4)
    params = {"from": records[1]["timestamp"], "to": records[3]["timestamp"]}  # [from, to)
    assert [e["seq"] for e in client.get("/audit/events", params=params).json()["items"]] == [2, 3]


def test_keyset_pagination_walks_all_pages(client):
    seed(client, 7)
    seen, cursor = [], 0
    while cursor is not None:
        page = client.get("/audit/events", params={"limit": 3, "cursor": cursor}).json()
        seen += [e["seq"] for e in page["items"]]
        cursor = page["nextCursor"]
    assert seen == list(range(1, 8))


def test_verify_intact_chain(client):
    records = seed(client)
    result = client.get("/audit/verify").json()
    assert result["valid"] and result["recordsChecked"] == 6
    assert result["headHash"] == records[-1]["hash"]


@pytest.mark.parametrize("sql, violation, seq", [
    ("UPDATE events SET actor_id = 'mallory' WHERE seq = 3", "HASH_MISMATCH", 3),
    ("UPDATE events SET payload = json_set(payload, '$.n', 999) WHERE seq = 3",
     "PAYLOAD_TAMPERED", 3),
    ("UPDATE events SET event_type = 'USER_LOGIN' WHERE seq = 5", "HASH_MISMATCH", 5),
])
def test_direct_db_modification_is_detected(client, tamper, sql, violation, seq):
    seed(client)
    tamper(sql)
    result = client.get("/audit/verify").json()
    assert not result["valid"]
    assert (result["violation"], result["firstInvalidSeq"]) == (violation, seq)


def test_db_guardrails_block_naive_delete_and_chain_edits(client, tamper):
    seed(client, 2)
    for sql in ("DELETE FROM events WHERE seq = 1", "UPDATE events SET hash = 'x' WHERE seq = 1"):
        with pytest.raises(Exception, match="append-only|immutable"):
            tamper(sql)


def test_deletion_detected_even_if_guardrail_bypassed(client, tamper):
    seed(client)
    tamper("DROP TRIGGER events_no_delete")
    tamper("DELETE FROM events WHERE seq = 2")
    result = client.get("/audit/verify").json()
    assert (result["violation"], result["firstInvalidSeq"]) == ("SEQUENCE_GAP", 3)


def test_concurrent_writers_never_fork_the_chain(client):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(lambda i: client.post("/audit/events", json=event(i)), range(80)))
    result = client.get("/audit/verify").json()
    assert result["valid"] and result["recordsChecked"] == 80
