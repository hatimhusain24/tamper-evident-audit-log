"""Hash-chain core: pure functions with no I/O.

The service (store.py) and the offline bundle verifier (verify_bundle.py) both use this module.

Record hash:
    hash = SHA-256( canonical_json({seq, timestamp, eventType, actorId, resourceType,
                                    resourceId, fieldHashes, prevHash}) )
    fieldHashes[k] = SHA-256( salt_k || canonical_json([k, payload[k]]) )

The record hash commits to a per-field *salted commitment* of the payload, not to the raw value.
A payload value can therefore be redacted (value and salt deleted, commitment kept) and the chain
still verifies. The random salt stops anyone brute-forcing a low-entropy redacted value
(e.g. an account number) from its commitment.
"""

import hashlib
import json
import secrets
from collections.abc import Iterable

GENESIS_HASH = "0" * 64
REDACTED = "[REDACTED]"
EVENT_FIELDS = ("eventType", "actorId", "resourceType", "resourceId", "payload")
_HASHED = ("seq", "timestamp", "eventType", "actorId", "resourceType", "resourceId")

# System events that authorize destructive maintenance. They are part of the chain themselves.
REDACTION_EVENT = "RECORD_REDACTED"
ARCHIVE_EVENT = "RECORDS_ARCHIVED"


def canonical(obj) -> bytes:
    """Deterministic JSON: sorted keys, no whitespace, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def field_hash(salt: str, key: str, value) -> str:
    return sha256(bytes.fromhex(salt) + canonical([key, value]))


def record_hash(r: dict) -> str:
    body = {f: r[f] for f in _HASHED} | {"fieldHashes": r["fieldHashes"], "prevHash": r["prevHash"]}
    return sha256(canonical(body))


def build_record(seq: int, prev_hash: str, timestamp: str, event: dict) -> dict:
    """Create a fully hashed record from validated event fields."""
    payload = event["payload"]
    salts = {k: secrets.token_hex(16) for k in payload}
    r = {"seq": seq, "timestamp": timestamp, **{f: event[f] for f in EVENT_FIELDS},
         "salts": salts, "fieldHashes": {k: field_hash(salts[k], k, v) for k, v in payload.items()},
         "prevHash": prev_hash, "archived": False}
    r["hash"] = record_hash(r)
    return r


def check_record(r: dict, prev_hash: str, expected_seq: int) -> tuple[str, str] | None:
    """Return (violation, detail) for the first problem found in one record, else None."""
    if r["seq"] != expected_seq:
        return "SEQUENCE_GAP", f"expected seq {expected_seq}, found {r['seq']} (deleted/inserted)"
    if r["prevHash"] != prev_hash:
        return "CHAIN_LINK_BROKEN", "prevHash does not equal the previous record's hash"
    if r.get("archived"):
        return None  # tombstone: content purged by retention; the link above is still enforced
    payload, salts, hashes = r["payload"], r["salts"], r["fieldHashes"]
    if payload.keys() != hashes.keys():
        return "PAYLOAD_TAMPERED", "payload fields were added or removed"
    for k, v in payload.items():
        if k in salts:
            if field_hash(salts[k], k, v) != hashes[k]:
                return "PAYLOAD_TAMPERED", f"payload field '{k}' was altered"
        elif v != REDACTED:
            return "PAYLOAD_TAMPERED", f"payload field '{k}' has no salt but is not redacted"
    if record_hash(r) != r["hash"]:
        return "HASH_MISMATCH", "record content does not match its stored hash"
    return None


def _result(valid: bool, checked: int, head: dict | None, bad_seq=None, violation=None) -> dict:
    return {"valid": valid, "recordsChecked": checked,
            "headSeq": head["seq"] if head else 0,
            "headHash": head["hash"] if head else GENESIS_HASH,
            "firstInvalidSeq": bad_seq,
            "violation": violation[0] if violation else None,
            "detail": violation[1] if violation else None}


def verify_chain(records: Iterable[dict]) -> dict:
    """Walk the chain in seq order. O(n) time; memory O(#redacted fields)."""
    prev, checked = None, 0
    last_archived, archived_through = 0, 0
    redacted, authorized = set(), set()
    for r in records:
        v = check_record(r, prev["hash"] if prev else GENESIS_HASH, checked + 1)
        if v is None and r.get("archived") and r["seq"] != last_archived + 1:
            v = ("UNAUTHORIZED_ARCHIVE", "tombstones must form a contiguous prefix of the chain")
        if v:
            return _result(False, checked, prev, r["seq"], v)
        if r.get("archived"):
            last_archived = r["seq"]
        else:
            p = r["payload"]
            redacted |= {(r["seq"], k) for k in p if k not in r["salts"]}
            if r["eventType"] == REDACTION_EVENT:
                authorized |= {(p["targetSeq"], f) for f in p["fields"]}
            elif r["eventType"] == ARCHIVE_EVENT:
                archived_through = max(archived_through, p["throughSeq"])
        prev, checked = r, checked + 1

    # Destructive operations are legitimate only if a later chained event authorized them.
    if unauthorized := sorted(redacted - authorized):
        seq, field = unauthorized[0]
        return _result(False, checked, prev, seq, (
            "UNAUTHORIZED_REDACTION",
            f"field '{field}' redacted without a {REDACTION_EVENT} event"))
    if last_archived > archived_through:
        return _result(False, checked, prev, archived_through + 1, (
            "UNAUTHORIZED_ARCHIVE", f"records up to seq {last_archived} purged, "
                                    f"policy authorized only up to {archived_through}"))
    return _result(True, checked, prev)
