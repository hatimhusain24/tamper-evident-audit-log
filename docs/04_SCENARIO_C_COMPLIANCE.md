# 04 — Scenario C: Compliance Reporting (ambiguous requirement)

> **Product:** "Regulators need to be able to audit access to client account data."

## 1. Clarification process

I broke the sentence into its nouns and verbs and asked what each one has to mean for the
system to be buildable and testable:

| Phrase | Ambiguity | Question I'd ask Product / Compliance | Working assumption |
|---|---|---|---|
| "Regulators" | Direct system access for SEC/FINRA examiners, or reports produced *for* them? | Do examiners log in, or does Compliance hand them evidence? | **Compliance generates evidence for examiners.** No external login (avoids a new trust boundary). |
| "audit" | A one-off report, a continuous feed, or alerting? | Is this for periodic exams, or real-time surveillance? | **On-demand, reproducible report** for a period. Surveillance and alerting are out of scope. |
| "access" | Only changes, or reads too? | Do views, searches and exports count as access? | **Reads and writes.** Exams care about *who looked*, not only who changed. |
| "client account data" | Which resources: account master, statements, KYC docs? | What is the system-of-record list? | `resourceType = CLIENT_ACCOUNT`. Other types can map in later through configuration. |
| (implicit) "who" | Employee, service, or the client? | Should service accounts be in scope? | **All actors.** The actorId is reported as-is. |
| (implicit) "why" | Is access *justified*? | Must every access carry a business purpose? | Producers send `payload.purpose`. Accesses **without a purpose are flagged as exceptions**, not rejected (the log must never drop events). |
| (implicit) trust | Why should a regulator believe the report? | — | The report embeds the **chain verification result and head hash**. Its own digest is **chained** into the log. |
| (implicit) "audit the auditors" | Is producing the report itself an access? | — | **Yes.** Each report appends `COMPLIANCE_REPORT_GENERATED` (who, scope, digest). |
| Retention | SEC 17a-4 / FINRA 4511 typically means ≥ 6 years, WORM | Which rules apply, and is WORM storage needed? | Config only (`AUDIT_RETENTION_DAYS`). WORM media is an infra concern, out of scope. |
| Data minimization | Should the report contain account *contents*? | — | **No.** Access metadata only (who/what/when/purpose/channel), never the payload. |

## 2. Clarified requirement statement (what I built against)

> For a given client account (or all client accounts) and a time period, an authorized compliance
> user can generate a machine-readable **access report**. It lists every read and write of
> `CLIENT_ACCOUNT` data: actor, action, time, stated purpose and channel. It also includes
> per-actor and per-action totals, and **flags accesses with no stated business purpose**. The
> report carries the audit chain's **integrity status and head hash**, so an examiner can rely
> on it. Generating a report is itself recorded as a tamper-evident audit event, which includes
> a digest of the report.

**Acceptance criteria**
1. Only `CLIENT_ACCOUNT` events in scope; filters by account and `[from, to)`.
2. Reads (e.g. `ACCOUNT_VIEWED`) and writes are both included. Payload contents are not exposed.
3. Accesses missing `payload.purpose` appear in `exceptions`.
4. `integrity` reflects `GET /audit/verify`. A tampered log makes the report say so.
5. A `COMPLIANCE_REPORT_GENERATED` event is appended with requester, scope and `reportDigest`,
   and `reportDigest == sha256(canonical(report without reportEvent))`.
6. Endpoint is admin-gated (same `X-Admin-Key` control as other high-impact operations).

## 3. Producer contract (event taxonomy)

Applications that touch client account data emit:

```json
{ "eventType": "ACCOUNT_VIEWED | ACCOUNT_UPDATED | ACCOUNT_EXPORTED | PERMISSION_GRANTED",
  "actorId": "emp-1234", "resourceType": "CLIENT_ACCOUNT", "resourceId": "acc-1001",
  "payload": { "purpose": "client call #5521", "channel": "branch-portal" } }
```

## 4. Design

`GET /audit/reports/account-access?accountId=&from=&to=&requestedBy=`

1. Run full chain verification and put the result in `integrity`.
2. Page through the existing query API (`resourceType=CLIENT_ACCOUNT` plus filters), reusing the
   indexed keyset queries with no new storage code.
3. Project each event to access metadata only, and build the totals and exceptions.
4. Compute `reportDigest = sha256(canonical(report))` and append `COMPLIANCE_REPORT_GENERATED`.

## 5. Implemented vs. scoped out

| Implemented | Scoped out (and why) |
|---|---|
| Clarified requirement + producer contract | Regulator self-service login: a new external trust boundary; needs IAM/legal review |
| Access report with totals, exceptions, integrity, chained digest | PDF/CSV rendering: presentation layer, trivial on top of the JSON |
| Reads + writes, data minimization | Real-time anomaly detection/alerting: a surveillance product, not reporting |
| Admin-gated generation, audited | Entitlement checks ("was the actor *allowed*?"): needs the HR/IAM source of truth. Exceptions approximate this through missing purpose |
| | WORM storage and 6-year retention enforcement: infrastructure and config |

Verification is O(n) per report. At scale, I'd verify incrementally from a signed checkpoint
(see the architecture doc).
