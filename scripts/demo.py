"""End-to-end demo against a running server (stdlib only).

1) uvicorn app.main:create_app --factory      (AUDIT_DB_PATH defaults to ./audit.db)
2) python scripts/demo.py [base_url] [db_path]
"""

import json
import sqlite3
import sys
import urllib.request

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8000"
DB = sys.argv[2] if len(sys.argv) > 2 else "audit.db"


def call(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(BASE + path, method=method,  # noqa: S310 - local demo URL
                                 data=json.dumps(body).encode() if body else None,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:  # noqa: S310
        return json.load(resp)


def step(title: str, result) -> None:
    print(f"\n== {title}\n{json.dumps(result, indent=2)[:900]}")


for i, (etype, actor, acct) in enumerate([("ACCOUNT_VIEWED", "emp-1", "acc-1"),
                                          ("ACCOUNT_UPDATED", "emp-2", "acc-1"),
                                          ("PERMISSION_GRANTED", "admin-1", "acc-2")]):
    rec = call("POST", "/audit/events", {"eventType": etype, "actorId": actor,
                                         "resourceType": "CLIENT_ACCOUNT", "resourceId": acct,
                                         "payload": {"purpose": f"ticket-{i}",
                                                     "accountNumber": f"98765{i}"}})
last = rec["seq"]
step("Query actorId=emp-1", call("GET", "/audit/events?actorId=emp-1"))
step("Verify (expect valid)", call("GET", "/audit/verify"))

with sqlite3.connect(DB) as conn:  # tamper directly in the data store, bypassing the API
    conn.execute("UPDATE events SET actor_id = 'mallory' WHERE seq = ?", (last - 1,))
step(f"Verify after editing seq {last - 1} in SQLite (expect HASH_MISMATCH)",
     call("GET", "/audit/verify"))
with sqlite3.connect(DB) as conn:  # undo so the remaining steps run on a clean chain
    conn.execute("UPDATE events SET actor_id = 'emp-2' WHERE seq = ?", (last - 1,))

step("Redact accountNumber", call("POST", f"/audit/events/{last}/redactions", {
    "fields": ["accountNumber"], "reason": "privacy request", "requestedBy": "dpo-1"}))
step("Verify after redaction (expect valid)", call("GET", "/audit/verify"))
step("Export bundle for acc-1", call("GET", "/audit/export?resourceId=acc-1"))
step("Compliance report for acc-1",
     call("GET", "/audit/reports/account-access?accountId=acc-1&requestedBy=compliance-1"))
