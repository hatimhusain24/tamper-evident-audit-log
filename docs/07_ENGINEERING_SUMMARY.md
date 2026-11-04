# 07 — Final Engineering Summary

## Plan & rationale

1. **Clarify first.** Requirements were normalized, assumptions written down and tasks sequenced
   before any code ([01](01_REQUIREMENTS_AND_PLAN.md)). Scenario C's clarification was committed
   on its own before its implementation.
2. **Put the integrity core in one small pure package.** `chain/` (~490 lines with records and the
   CLI) holds all hashing, MAC checks and verification. The service, the tests and the offline
   verifier share it, so there is one thing to audit.
3. **Use one principle for every destructive operation.** Redaction and archival are allowed, but
   each must be *authorized by an event inside the chain*, and `verify` checks for that
   authorization and for the legal retention floor.
4. **The audit log controls access to itself.** Deny-by-default Spring Security, least-privilege
   roles, the submitter sealed into every record, PII masked for readers and encrypted at rest, and
   a service that won't start without credentials and keys. This was added after the evaluation showed the
   original "trusted callers" assumption was not acceptable for client-data audit.
5. **Keep it small and tested.** Spring Boot plus SQLite JDBC, about 2,200 lines of application
   code, 218 tests, no ORM, no mocks, coverage gated at 90% line / 85% branch.

## Artifacts

| Deliverable (§7) | Location |
|---|---|
| Attestation | [ATTESTATION.md](../ATTESTATION.md) |
| Working prototype + setup | `src/main/java`, [README](../README.md) |
| Architecture, data model, API, security, hash & chain choice | [02_ARCHITECTURE.md](02_ARCHITECTURE.md), OpenAPI at `/docs` (dev profile) |
| Scenarios A, B (decomposition / execution / validation) | [03_SCENARIOS_A_B.md](03_SCENARIOS_A_B.md) |
| Scenario C (clarified requirement, design, scope) | [04_SCENARIO_C_COMPLIANCE.md](04_SCENARIO_C_COMPLIANCE.md) |
| AI usage log and evaluation remediation | [05_AI_USAGE_LOG.md](05_AI_USAGE_LOG.md) |
| Testing approach, coverage, limitations | [06_TESTING.md](06_TESTING.md) |
| Development history | `git log`: one commit per task |

## Risks, trade-offs & validation

| Risk | Mitigation | Validated by |
|---|---|---|
| Anonymous or wrong-role access to client data | Spring Security, deny by default, roles, masking, export COMPLIANCE only | `SecurityTest` role matrix |
| A reader opening another client's records | Per-user resource scopes, enforced in SQL | `ResourceScopeTest` |
| Forged attribution | `recordedBy` from the login, inside the hash; reserved system event types | spoofing tests |
| Evidence destruction through retention | 6-year floor in the store; verify flags violations | `RetentionTest`, `AuditStoreTest` |
| DB admin rewrites the chain | Per-record HMAC with a server key | `fullRewriteFoolsAPlainHashChainButNotTheMac` |
| Truncation of the newest records | Signed checkpoints used automatically by verify | `CheckpointTest` |
| Records dropped from an export | Ed25519-signed bundles | `droppedRecordIsInvisibleToHashesButBreaksTheSignature` |
| PII read from the database file | AES-256-GCM encryption of sensitive fields | `EncryptionAtRestTest` |
| Corrupt rows break verification | `CORRUPT_RECORD` at the seq, reads keep working | `CorruptRecordTest` |
| Partial writes on failure | One transaction per operation | `FaultInjectionTest` |
| PII lingering on disk after redaction | `secure_delete` + WAL checkpoint | raw-bytes test |
| Floods, password guessing, huge bodies | Per-client rate limit (proxy-aware) and body limit before auth | `RequestGuardTest`, `RequestGuardFilterTest` |
| O(n) verify at scale | 10.5k records in ~0.5 s now; signed checkpoints later | `PerfBenchmarkTest` |

## Assumptions

Server-assigned timestamps · HTTP Basic over TLS as the prototype identity mechanism · users and
the HMAC key provided by deployment config (secret manager) · top-level payload keys as the
redaction unit · core identifiers are pseudonymous · SQLite for the prototype, Postgres in
production · Scenario C assumptions in [04](04_SCENARIO_C_COMPLIANCE.md) §1.

## Limitations

* An attacker holding DB access **and** the keys could rewrite the chain and checkpoints; keep keys
  in a KMS/HSM and the checkpoint file on separate WORM storage.
* Authentication is HTTP Basic with configured users: no OIDC, password expiry or rotation.
* The AES field-encryption key can't be rotated yet (the HMAC key can).
* Single SQLite file and an in-memory rate limiter: one service instance; verify is O(n).
* Nested-field redaction is not supported (redact the parent key).

## Next steps (in order)

1. OIDC tokens instead of Basic, and all keys held in a KMS/HSM.
2. Incremental verify from the last signed checkpoint instead of walking the whole chain.
3. Postgres store and a shared rate limiter for horizontal scaling.
4. Rotation for the field-encryption key.
