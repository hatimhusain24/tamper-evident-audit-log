# 05 — AI Usage Log & Traceability

## Tooling and governance

| | |
|---|---|
| **AI tool** | Claude Code (Anthropic), agentic coding assistant |
| **Mode of use** | The engineer gave the brief and constraints. The AI drafted the plan, code, tests and docs task by task. Each step went through automated quality gates (ruff + pytest) before commit. The engineer reviews and signs off (§4) |
| **Traceability** | Each commit = one task from [01_REQUIREMENTS_AND_PLAN.md](01_REQUIREMENTS_AND_PLAN.md) §4. AI use is disclosed here rather than in commit messages. This file records what was accepted, modified or rejected, and why |
| **Secure AI usage** | Only the assignment brief and generic requirements were shared with the AI. No credentials, production code, client data or internal hostnames. No secrets in the repo (admin key comes from an env var). AI-generated code passes the bandit (`S`) security rules. Raw SQL was reviewed so that values are always bound parameters |

## 1. Prompts (intent → constraints → acceptance criteria)

**P0, engineer's initial instruction (summary):** build the audit log service exactly as the
brief specifies (Scenarios A, B, C and every §7 deliverable). Constraints: *efficient, simple,
minimal line count, easy to explain in a live defense; periodic commits, not one; private repo;
ATTESTATION and AI log required.*

From P0 the AI produced the task plan (T1–T9). Each task then ran as a sub-prompt with the
intent, constraints and acceptance criteria listed in the plan table. For example:

> **T3:** "Implement the hash-chain core as pure functions with no I/O. Constraints: deterministic
> across languages, redaction must later be possible without breaking the chain, report the
> *first* bad seq with a typed violation. Acceptance: a unit test per tamper type, including an
> attacker who rehashes the edited record."

## 2. Decision log: generated / modified / rejected

| # | Area | AI proposal | Outcome | Rationale |
|---|------|-------------|---------|-----------|
| 1 | Chain design | Store `contentHash` (fields only) and `prevHash` separately | **Rejected** | Flaw found in review: an attacker could edit record *k*, rehash it, patch *k+1*'s `prevHash` and stop. `prevHash` must be *inside* the hashed content. Test `test_rehashing_a_tampered_record_breaks_the_next_link` guards this |
| 2 | Hash algorithm | SHA-256 | **Accepted** | FIPS-approved, stdlib, ample margin. BLAKE3 rejected (non-stdlib, no benefit at this scale) |
| 3 | Redaction | Hash payload values directly, unsalted | **Rejected** | Low-entropy PII (account numbers) is brute-forceable from an unsalted hash |
| 4 | Redaction | Re-compute the chain after redaction | **Rejected** | Makes legitimate rewrites indistinguishable from attacks |
| 5 | Redaction | Salted per-field commitments + chained `RECORD_REDACTED` | **Accepted** | Keeps tamper evidence and privacy; the redaction itself is accountable |
| 6 | Redaction | (initial version) UPDATE only | **Modified** | A raw-bytes test showed the old value persisted in `audit.db-wal`. Added WAL checkpoint + `secure_delete`. Confirmed the test fails without the fix |
| 7 | Retention | Move rows to an archive table with a new genesis | **Rejected** | Needs signed checkpoints to bridge the chains. Tombstones keep a single chain with less code |
| 8 | Retention | Tombstones without authorization | **Modified** | A DB admin could hide tampering by "archiving" a record. Added the chained `RECORDS_ARCHIVED` event and prefix/through-seq checks |
| 9 | Pagination | OFFSET/LIMIT | **Rejected** | O(n) deep pages, and rows skip or duplicate under concurrent appends. Keyset on `seq` instead |
| 10 | Timestamp | Accept a caller timestamp | **Rejected** | Allows backdating and breaks the ordering retention depends on. Server-assigned, monotonic |
| 11 | Persistence | SQLAlchemy ORM + Postgres | **Rejected for prototype** | Extra dependencies and setup with no benefit for the evaluation. The storage boundary is isolated in `store.py` |
| 12 | Export | Merkle inclusion proofs | **Deferred** | O(log n) proofs, but far more code. A linear skeleton is enough and easy to verify. Listed as future work |
| 13 | Security | Allow callers to write any eventType | **Modified** | Callers could forge `RECORD_REDACTED` / `RECORDS_ARCHIVED` authorizations. Reserved types are now rejected (422) |
| 14 | Lint | Generated code had long lines and an unused variable | **Modified** | Fixed when the ruff gate failed |
| 15 | Lint | `S608` (SQL built from strings) flagged | **Accepted with justification** | Only constant, whitelisted column names are interpolated; values are bound. `noqa` comments state why |
| 16 | Tests | Retention test expected `firstInvalidSeq == 3` | **Modified (test, not code)** | The verifier's answer (4) was correct: seq 3 was the legitimate archive event |
| 17 | Tests | Placeholder assertion `... or True` in the first draft of the privacy test | **Rejected** | It asserted nothing. Rewritten to scan the raw DB/WAL bytes |
| 18 | Scenario C | Start with the endpoint | **Rejected** | The requirement was clarified and committed first (`15c4754`), then implemented |

## 3. Where AI was used

| Activity | AI role | Engineer role |
|---|---|---|
| Requirement analysis | Drafted interpretations, ambiguities, plan | Review and approve assumptions |
| Implementation | Generated the code task by task | Review design decisions (§2), own correctness |
| Debugging | Diagnosed the lint and test failures above | Confirm each fix |
| Test generation | Generated unit, integration and adversarial tests | Check tests actually discriminate (e.g. #6) |
| Documentation | Drafted all docs | Edit to own voice; must be able to defend every line |
| Review prep | Threat model, trade-off tables | Rehearse the live defense |

## 4. Human sign-off: high-impact changes (completed by the engineer)

High-impact changes are those that affect integrity guarantees, privacy or the API contract.

Tick a box by editing this file on GitHub (pencil icon) or locally: change `[ ]` to `[x]`, then commit.

- [ ] Hash/chain format (`app/chain.py`), commit `c528719`
- [ ] Write path, timestamps, concurrency (`app/store.py`), commit `1f05c80`
- [ ] Redaction scheme and physical erasure, commit `93eb621`
- [ ] Retention tombstones and authorization, commit `f4ef1a1`
- [ ] Export bundle format and offline verifier, commit `3632929`
- [ ] Scenario C assumptions and scope, commits `15c4754`, `463eaac`

## 5. Engineer review log (engineer appends entries during review / rework)

| Date | What I reviewed or changed | AI involved? | Notes |
|------|----------------------------|--------------|-------|
| | | | |
