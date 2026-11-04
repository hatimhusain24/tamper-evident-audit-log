# 07 — Final Engineering Summary

## Plan & rationale

1. **Clarify first.** Requirements were normalized, assumptions written down and tasks sequenced
   before any code ([01](01_REQUIREMENTS_AND_PLAN.md)). Scenario C's clarification was committed
   on its own before its implementation.
2. **Put the security core in one small pure module.** The `chain` package (~280 lines) holds all
   hashing and verification. The service, the tests and the offline verifier share it, so there
   is one thing to audit.
3. **Use one principle for every destructive operation.** Redaction and archival are allowed, but
   each must be *authorized by an event inside the chain*, and `verify` checks for that
   authorization. This one idea solves both Scenario B problems and keeps them explainable.
4. **Keep it small.** Spring Boot plus SQLite JDBC, about 1,050 lines of application code, 85 tests, no
   ORM, no framework magic.

## Artifacts

| Deliverable (§7) | Location |
|---|---|
| Attestation | [ATTESTATION.md](../ATTESTATION.md) |
| Working prototype + setup | `src/main/java`, [README](../README.md) |
| Architecture, data model, API, hash & chain choice | [02_ARCHITECTURE.md](02_ARCHITECTURE.md), OpenAPI at `/docs` |
| Scenarios A, B (decomposition / execution / validation) | [03_SCENARIOS_A_B.md](03_SCENARIOS_A_B.md) |
| Scenario C (clarified requirement, design, scope) | [04_SCENARIO_C_COMPLIANCE.md](04_SCENARIO_C_COMPLIANCE.md) |
| AI usage log | [05_AI_USAGE_LOG.md](05_AI_USAGE_LOG.md) |
| Testing approach, limitations | [06_TESTING.md](06_TESTING.md) |
| Development history | `git log`: one commit per task |

## Risks, trade-offs & validation

| Risk | Trade-off / mitigation | Validated by |
|---|---|---|
| DB admin rewrites the whole chain | Unkeyed chain can't stop this. `headHash` exposed for external anchoring; HMAC/KMS signing is the next step | Documented threat model |
| Truncation of the newest records | Same: anchor `headSeq/headHash` | Documented |
| Redaction misuse (evidence destruction) | Every redacted field must have a chained `RECORD_REDACTED` | `RedactionTest.forgedRedactionInDatabaseIsDetected` |
| Retention misuse | Prefix-only + `RECORDS_ARCHIVED.throughSeq` | `RetentionTest.tombstoneOutsidePolicyIsDetected` |
| PII lingering on disk after redaction | `secure_delete` + WAL checkpoint | Raw-bytes test |
| Chain fork under concurrency | Serialized writes | 8-thread test |
| O(n) verify at scale | 10.5k records in 0.34 s now. Signed checkpoints for incremental verify later | Measured |
| Export bundle size grows with the distance to head | Linear skeleton (hashes only). Merkle proofs later | `ExportTest` |

## Assumptions

Server-assigned timestamps · trusted internal producers (no end-user authN) · admin key as a
stand-in for RBAC · top-level payload keys as redaction unit · core identifiers are pseudonymous
· SQLite for the prototype, Postgres in production · Scenario C assumptions in
[04](04_SCENARIO_C_COMPLIANCE.md) §1.

## Limitations

* No protection against an all-powerful DB admin without an external anchor or signing key.
* Single SQLite file: vertical scale only. Multi-process writers rely on SQLite locking.
* Nested-field redaction not supported (redact the parent key).
* Export bundles prove integrity relative to a head hash. Authenticity needs a trusted checkpoint
  (no signatures yet).
* The compliance report is JSON only; no entitlement (was-the-access-allowed) check.

## What I would do next (in order)

1. HMAC-SHA-256 or Ed25519 signing of the head with a KMS-held key, plus periodic anchoring.
2. Signed checkpoints → incremental verification.
3. Postgres store + OIDC/RBAC.
4. Merkle inclusion proofs for compact exports.
