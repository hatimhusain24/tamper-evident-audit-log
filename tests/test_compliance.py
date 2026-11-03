"""Scenario C acceptance criteria (docs/04_SCENARIO_C_COMPLIANCE.md section 2)."""

from app.chain import canonical, sha256


def access(client, action, actor, account, purpose="client call"):
    payload = {"channel": "portal", "ssn": "123-45-6789"}
    if purpose:
        payload["purpose"] = purpose
    return client.post("/audit/events", json={
        "eventType": action, "actorId": actor, "resourceType": "CLIENT_ACCOUNT",
        "resourceId": account, "payload": payload}).json()


def report(client, **params):
    return client.get("/audit/reports/account-access",
                      params={"requestedBy": "compliance-1"} | params).json()


def seed(client):
    access(client, "ACCOUNT_VIEWED", "emp-1", "acc-1")
    access(client, "ACCOUNT_UPDATED", "emp-2", "acc-1")
    access(client, "ACCOUNT_VIEWED", "emp-1", "acc-2")
    access(client, "ACCOUNT_EXPORTED", "emp-3", "acc-1", purpose=None)
    client.post("/audit/events", json={"eventType": "USER_LOGIN", "actorId": "emp-1",
                                       "resourceType": "SESSION", "resourceId": "s1"})


def test_report_scope_summary_and_exceptions(client):
    seed(client)
    r = report(client, accountId="acc-1")
    assert [a["seq"] for a in r["accesses"]] == [1, 2, 4]          # AC1 + AC2 (reads & writes)
    assert r["summary"] == {"totalAccesses": 3, "distinctActors": 3,
                            "byAction": {"ACCOUNT_VIEWED": 1, "ACCOUNT_UPDATED": 1,
                                         "ACCOUNT_EXPORTED": 1},
                            "byActor": {"emp-1": 1, "emp-2": 1, "emp-3": 1}}
    assert r["exceptions"] == [4]                                   # AC3
    assert "123-45-6789" not in str(r)                              # AC2 data minimization
    assert r["integrity"]["valid"]                                  # AC4


def test_all_accounts_and_time_range(client):
    seed(client)
    assert report(client)["summary"]["totalAccesses"] == 4
    events = client.get("/audit/events", params={"resourceType": "CLIENT_ACCOUNT"}).json()["items"]
    r = report(client, **{"from": events[1]["timestamp"], "to": events[3]["timestamp"]})
    assert [a["seq"] for a in r["accesses"]] == [2, 3]


def test_report_generation_is_chained_with_digest(client):
    seed(client)
    r = report(client, accountId="acc-1")
    body = {k: v for k, v in r.items() if k not in ("reportDigest", "reportEvent")}
    assert r["reportDigest"] == sha256(canonical(body))            # AC5
    logged = client.get("/audit/events",
                        params={"eventType": "COMPLIANCE_REPORT_GENERATED"}).json()["items"]
    assert logged[0]["actorId"] == "compliance-1"
    assert logged[0]["payload"]["reportDigest"] == r["reportDigest"]
    assert client.get("/audit/verify").json()["valid"]


def test_report_flags_tampered_log(client, tamper):
    seed(client)
    tamper("UPDATE events SET actor_id = 'someone-else' WHERE seq = 2")
    integrity = report(client, accountId="acc-1")["integrity"]
    assert not integrity["valid"] and integrity["firstInvalidSeq"] == 2


def test_requested_by_is_mandatory(client):
    assert client.get("/audit/reports/account-access").status_code == 422
