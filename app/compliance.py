"""Scenario C: regulator-facing access report (see docs/04_SCENARIO_C_COMPLIANCE.md)."""

from collections import Counter
from datetime import UTC, datetime

from app.chain import canonical, sha256, verify_chain
from app.store import AuditStore, iso

ACCOUNT_RESOURCE = "CLIENT_ACCOUNT"
REPORT_EVENT = "COMPLIANCE_REPORT_GENERATED"


def access_report(store: AuditStore, account_id: str | None, start: datetime | None,
                  end: datetime | None, requested_by: str) -> dict:
    integrity = verify_chain(store.iter_chain())

    accesses, cursor = [], 0
    filters = {"resourceType": ACCOUNT_RESOURCE, "resourceId": account_id}
    while cursor is not None:  # reuse indexed keyset queries page by page
        page, cursor = store.query(filters, start, end, limit=500, cursor=cursor)
        accesses += [{  # data minimization: access metadata only, never payload contents
            "seq": e["seq"], "timestamp": e["timestamp"], "actorId": e["actorId"],
            "action": e["eventType"], "accountId": e["resourceId"],
            "purpose": e["payload"].get("purpose"), "channel": e["payload"].get("channel"),
            "hash": e["hash"]} for e in page]

    report = {
        "scope": {"resourceType": ACCOUNT_RESOURCE, "accountId": account_id,
                  "from": iso(start) if start else None, "to": iso(end) if end else None},
        "generatedAt": iso(datetime.now(UTC)),
        "generatedBy": requested_by,
        "integrity": integrity,
        "summary": {"totalAccesses": len(accesses),
                    "distinctActors": len({a["actorId"] for a in accesses}),
                    "byAction": dict(Counter(a["action"] for a in accesses)),
                    "byActor": dict(Counter(a["actorId"] for a in accesses))},
        "exceptions": [a["seq"] for a in accesses if not a["purpose"]],
        "accesses": accesses,
    }
    digest = sha256(canonical(report))
    event = store.append({  # auditing the auditors: report generation is itself chained
        "eventType": REPORT_EVENT, "actorId": requested_by, "resourceType": "COMPLIANCE_REPORT",
        "resourceId": account_id or "*",
        "payload": {"scope": report["scope"], "accessCount": len(accesses),
                    "reportDigest": digest}})
    return report | {"reportDigest": digest, "reportEvent": {"seq": event["seq"],
                                                              "hash": event["hash"]}}
