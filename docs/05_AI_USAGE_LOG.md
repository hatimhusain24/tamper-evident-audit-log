# 05 — AI Usage Log & Traceability

## Tooling and governance

| | |
|---|---|
| **AI tool** | Claude Code (Anthropic), agentic coding assistant |
| **Mode of use** | The engineer gave the brief and constraints. The AI drafted the plan, code, tests and docs task by task. Each step went through automated quality gates before commit (first ruff + pytest, after the Java port `mvn verify`: compile with warnings as errors, tests, SpotBugs). Engineer review and sign-off are tracked in §4 and §5 |
| **Traceability** | Each commit = one task from [01_REQUIREMENTS_AND_PLAN.md](01_REQUIREMENTS_AND_PLAN.md) §4. AI use is disclosed here rather than in commit messages. This file records what was accepted, modified or rejected, and why |
| **Secure AI usage** | Only the assignment brief and generic requirements were shared with the AI. No credentials, production code, client data or internal hostnames. No secrets in the repo (admin key comes from an env var). AI-generated code passes security static analysis (SpotBugs + FindSecBugs). Raw SQL uses only fixed column names; values are always bound parameters |

## 1. Prompts

The engineer gave **one main instruction** and then a few follow-ups. The AI split the work into
tasks and ran them on its own. There were no separate prompts per task.

**P0, main instruction (summary):** build the audit log service exactly as the brief specifies
(Scenarios A, B, C and every §7 deliverable). Constraints: *efficient, simple, minimal code, easy
to explain in a live defense; periodic commits, not one; private repo; attestation and AI log
required.*

From P0 the AI wrote the task plan (T1–T9 in [01](01_REQUIREMENTS_AND_PLAN.md) §4). It then used
each row (intent, constraints, acceptance criteria) as its own task definition. For example, T3:

> Hash-chain core as pure functions with no I/O. Deterministic across languages; redaction must
> later be possible without breaking the chain; report the *first* bad seq with a typed violation.
> Acceptance: a unit test per tamper type, including an attacker who rehashes the edited record.

**Follow-up prompts from the engineer:**

| # | Prompt (summary) | Result |
|---|------------------|--------|
| P1 | Use my personal email for commits | Git identity changed |
| P2 | Keep commit messages short and simple | Messages rewritten; AI use is disclosed in this log instead |
| P3 | Sign-off boxes can't be clicked | Changed to a `- [ ]` checklist (§4) |
| P4 | Check the work against the brief and run the app in a browser | Ran the full tamper flow in Swagger UI; listed the steps that are still open |
| P5 | Make this log accurate | Prompts and decision log reworded |
| P6 | Should this have been Java Spring Boot? | The brief names no stack; the AI first recommended keeping Python because of the deadline |
| P7 | Switch to Java Spring Boot and test all scenarios, including edge cases | Ported to Java 17 + Spring Boot with 85 tests; Python version removed |

## 2. Decision log: generated / modified / rejected

Most of these decisions were made **by the AI while generating the code**: options it considered
and rejected, and problems its own tests or lint caught. They are recorded so the engineer can
review and challenge them (§4). They are not a record of the engineer's own review.
Decisions 1–18 come from the first (Python) version and carried over unchanged to Java; 19+ come
from the port.

| # | Area | Option considered | Outcome | Rationale |
|---|------|-------------|---------|-----------|
| 1 | Chain design | Store `contentHash` (fields only) and `prevHash` separately | **Rejected** | Security flaw: an attacker could edit record *k*, rehash it, patch *k+1*'s `prevHash` and stop. `prevHash` must be *inside* the hashed content. Test `test_rehashing_a_tampered_record_breaks_the_next_link` guards this |
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
| 19 | Stack | Python + FastAPI (first version) | **Changed** to Java 17 + Spring Boot | The brief leaves the stack open; Java is the team's stack and the engineer's strongest language, which matters for the live change. Same design and tests |
| 20 | Persistence | JPA / Hibernate | **Rejected** | The chain needs exact control of SQL, triggers and pragmas; `JdbcTemplate` is smaller and clearer |
| 21 | Spring wiring | `@Repository` on a `final` store class | **Modified** | Spring's exception-translation proxy can't subclass a final class; `@Component` needs no proxy |
| 22 | Static analysis | SpotBugs reported 27 findings | **Triaged** | 24 record/DTO exposure warnings, 1 timing warning on public hashes, 2 SQL warnings on whitelisted SQL: all suppressed with reasons in `spotbugs-exclude.xml`. The admin key already used a constant-time compare |
| 23 | Tests | Third archive run expected to archive 0 records | **Modified (test)** | The previous archive event is also old enough, so 1 is correct and verify stays valid |
| 24 | Performance | First measurement: 458 appends/s | **Rejected** | The harness opened a new DB connection per write; with the app's Hikari pool it is ~2,700/s |
| 25 | API docs | Swagger showed placeholder `"string"` bodies | **Modified** | Added `@Schema` examples so the write call can be tried as is |

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

Re-review needed: the earlier ticks applied to the Python version, which has been replaced.

- [x] Hash/chain format (`chain/HashChain`, `ChainVerifier`), commit `9a6bd6e`
- [x] Write path, timestamps, concurrency (`store/AuditStore`), commit `6a0dc2a`
- [x] Redaction scheme and physical erasure, commits `6a0dc2a`, `2a34015`
- [x] Retention tombstones and authorization, commits `6a0dc2a`, `2a34015`
- [x] Export bundle format and offline verifier, commits `6a0dc2a`, `2a34015`
- [x] Scenario C assumptions and scope, commits `15c4754`, `09d65b9`

## 5. Engineer review log (engineer appends entries during review / rework)

| Date | What I reviewed or changed | AI involved? | Notes |
|------|----------------------------|--------------|-------|
| 2026-11-04 | Hash chain (Java): prevHash is inside each record's hash, so editing one record breaks all later ones | Yes (asked Claude to explain) | Approved |
| 2026-11-04 | Write path: server sets timestamp, never goes backwards; lock + BEGIN IMMEDIATE so the chain can't fork | Yes (asked Claude to explain) | Approved |
| 2026-11-04 | Redaction: value and salt removed, hash kept; logged as its own event; RedactionTest passes | No | Approved |
| 2026-11-04 | Retention: archived records keep their hashes, no false alarms; RetentionTest passes | No | Approved |
| 2026-11-04 | Export: bundle verifies offline with verify-bundle; tampered bundle fails; ExportTest passes | No | Approved |
| 2026-11-04 | Scenario C: agree with assumptions (reads count as access, no regulator login, payload hidden); tests pass | No | Approved |
