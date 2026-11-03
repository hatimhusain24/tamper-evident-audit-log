"""Scenario B: retention archival never causes a false positive, and is itself audited."""

from tests.conftest import event


def seed(client, n=3):
    for i in range(1, n + 1):
        client.post("/audit/events", json=event(i))


def archive_all(client):
    return client.post("/audit/retention/run", json={"olderThanDays": 0, "requestedBy": "ops-1"})


def test_default_window_keeps_recent_records(client):
    seed(client)
    assert client.post("/audit/retention/run").json()["archivedCount"] == 0  # 365-day default


def test_archived_records_verify_and_disappear_from_queries(client):
    seed(client)
    res = archive_all(client).json()
    assert res["archivedCount"] == 3 and res["throughSeq"] == 3
    assert res["event"]["eventType"] == "RECORDS_ARCHIVED" and res["event"]["seq"] == 4

    items = client.get("/audit/events").json()["items"]
    assert [e["seq"] for e in items] == [4]  # only the authorizing event remains visible
    client.post("/audit/events", json=event(9))  # chain continues past tombstones
    result = client.get("/audit/verify").json()
    assert result["valid"] and result["recordsChecked"] == 5


def test_repeated_runs_and_redacted_records(client):
    seed(client)
    client.post("/audit/events/1/redactions",
                json={"fields": ["accountNumber"], "reason": "erasure", "requestedBy": "dpo"})
    archive_all(client)
    seed(client, 2)
    archive_all(client)
    assert client.get("/audit/verify").json()["valid"]


def test_tampering_with_a_tombstone_is_detected(client, tamper):
    seed(client)
    archive_all(client)
    tamper("DROP TRIGGER events_chain_immutable")
    tamper("UPDATE events SET hash = ? WHERE seq = 2", ("a" * 64,))
    result = client.get("/audit/verify").json()
    assert (result["violation"], result["firstInvalidSeq"]) == ("CHAIN_LINK_BROKEN", 3)


def test_tombstone_outside_policy_is_detected(client, tamper):
    seed(client, 2)
    archive_all(client)                       # authorizes seq 1-2
    seed(client, 2)                           # seq 4-5
    tamper("UPDATE events SET archived = 1, payload = NULL WHERE seq IN (4, 5)")
    result = client.get("/audit/verify").json()
    assert (result["violation"], result["firstInvalidSeq"]) == ("UNAUTHORIZED_ARCHIVE", 4)


def test_prefix_tombstones_beyond_policy_are_detected(client, tamper):
    seed(client, 2)
    archive_all(client)                       # authorizes seq 1-2; seq 3 = RECORDS_ARCHIVED
    tamper("UPDATE events SET archived = 1, payload = NULL WHERE seq = 3")  # hide the authorizer
    result = client.get("/audit/verify").json()
    # The authorizing event itself was destroyed, so no tombstone can be proven legitimate:
    # the verifier conservatively reports the whole prefix from seq 1.
    assert (result["violation"], result["firstInvalidSeq"]) == ("UNAUTHORIZED_ARCHIVE", 1)
