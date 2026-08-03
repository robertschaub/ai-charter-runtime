<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-004 — Dialogue-response channel (browser → authorization service)

**Status:** accepted (M1, 2026-08-01). **Spec:** §5 (empathy layer; dialogue triggers), §4 (intervention contract), §3 (consoles, demo authentication), §7 beat 4.

**Amendment (M4 authority review follow-up, 2026-08-02):** `decision_and_route.substitute_roles` is the exact machine-enforced substitute set; `substitute_rule` remains explanatory text. Wrong-role and disposition-outside-set attempts append refusal events while leaving the escalation open.

**Amendment (M4 case-session handoff protocol, 2026-08-03):** ADR-002's one-time authorization-origin
handoff authenticates entry to the orchestrator-origin case console without transferring a role token. It
does not alter this dialogue channel: answers still post directly from the authorization-origin control
under the responder's own role token, and the case-session claim has no standing there.

## Context
A dialogue trigger is an ordinary escalation routed to the conversation partner — same single-use state machine, same six-field intervention contract — but two boundary rules constrain the channel. The answer posts **directly from the browser to the authorization service** under the responder's role token, from a control served by the **authorization service's own origin**, so the orchestrator neither serves the credential-bearing control nor carries the answer. And standing is **evidentiary, not managerial**: a responder answers only within their own standing; a third party's facts are resolved by cited evidence or routed to that party, never by bare assertion.

## Decision

### 1. Deep link into the governance-console origin — not an iframe
The spec permits "embedded in or linked from"; linking is chosen because it removes cross-origin embedding, framing, and CSP negotiation entirely. The case console renders one control — *Respond in the governance console* — an anchor to `{AUTHZ_ORIGIN}/console/dialogue/{world_id}/{escalation_id}`, an unauthenticated static shell under ADR-002's `GET /console/*`. The shell then fetches the escalation with the responder's role token and renders the question and the six contract fields itself.

Alongside it the case console shows, read-only, the **ruling's `reason`** — a §4 gate-ruling field the orchestrator legitimately receives — so the officer sees in the chat seat what stopped the turn. It does **not** show the question text or the contract fields: ADR-002 fixes that the orchestrator never reads an escalation or its contract fields, and those render only on the authoritative origin. This narrows the leaning ("case console shows the question text read-only") to what the frozen ACL permits, and keeps the authoritative rendering in one place.

`Content-Security-Policy: frame-ancestors 'none'` on every governance-console page makes the no-embed decision technically enforced and blocks clickjacking of the response control.

The link carries only a world id and an opaque escalation id — no token, no answer, no case content. Escalation ids are 128-bit random and URL-safe, since the link may be copied.

The case console itself is entered through ADR-002 §5.1's fixed handoff page, but that authentication
exchange and this dialogue link are deliberately separate. The handoff uses one transient, exact-window
opener and then severs it; the ordinary dialogue link below always uses `noopener` and transfers nothing.

### 2. Token custody: `localStorage` on the governance origin
ADR-002 fixes browser custody: a token-entry field on the governance origin, held in that origin's **`localStorage`**, sent as `Authorization: Bearer …`, no cookies. (The two ADRs were drafted in parallel and initially resolved this in opposite directions; review ruling 2026-08-01: `localStorage` stands — a deep link opens a fresh tab, and per-tab `sessionStorage` would demand a paste per response or a shared named tab holding an open `window.opener` handle.) The dialogue link is therefore a plain `target="_blank"` **with `rel="noopener"`** — opener isolation costs nothing once storage persists on the origin.

Costs, declared demo-grade (ADR-002 §8): the token persists on that origin until cleared, and any script on the governance origin can read it — tolerable only because that origin serves no third-party content and ships a strict CSP. The case-console origin never holds an authorization-service role token; it holds only ADR-002's short-lived, case-bound session bearer. That bearer and the orchestrator's process credential are both denied on this route.

### 3. CSRF
Covered by ADR-002's design rather than re-solved here: no cookie authenticates anything, so no ambient credential exists for a cross-site form to ride, and the authorization service emits no CORS headers at all, so a credentialed cross-origin fetch fails in the browser. The dialogue control adds nothing — same-origin form, bearer token required. No synchronizer token, stated as a deliberate POC-scale limit. An `Origin` check is *not* relied on: a non-browser client (beat 17's raw API client) forges it freely, so the bearer token plus the route ACL is the actual control.

### 4. Response endpoint and payload
`POST /w/{world_id}/dialogue/{escalation_id}/response` on the authorization service — ADR-002's route, restricted to the routed conversation partner's role token, same origin as the control. The shell's read side needs one route ADR-002's table does not yet list: `GET /w/{world_id}/escalations/{id}`, same restriction — to be added there.

```json
{
  "escalation_id": "esc_9f3c…",
  "disposition": "confirm",
  "answer_text": "Entity registered 2024-03-11, so under three years at application date.",
  "evidence_ref": { "kind": "registry_record", "id": "reg:CH-0042", "retrieved_at": "2026-08-01T09:14:02.000Z" },
  "scope": { "item_ref": "inf_7", "applies_to": "this_case_only" }
}
```

- `disposition ∈ { confirm, correct, narrow, permit, abstain, route }`.
- `escalation_id` in path and body must match (else `400`) — the body echo binds the payload to the target.
- `answer_text` is required for `correct` and `narrow`, optional otherwise; it enters the `said` store as the responder's testimony.
- `evidence_ref` is **required for `confirm` when the escalation's standing class is `third-party-fact`**, and must resolve against the mock registry read service.
- `scope` is required for `permit` (what may be remembered, revocably) and for `narrow`.

**Deviation, flagged:** the leaning's five-value set is extended with `route`. Beat 4 requires that confirmation of a third party's fact be satisfiable by "cited evidence **or** routing to the applicant", and `abstain` does not carry that obligation — it leaves nothing pending, whereas `route` opens a recorded routing obligation and a fresh escalation to the named role. Without it the refusal path has no affirmative exit.

### 5. Standing and the bare-confirm refusal
The intervention contract's route field is parameterized (policy-rule level, no new record fields) with `standing_class ∈ { own-testimony, own-interpretation, own-permission, third-party-fact }` and an exact `substitute_roles` list. The prose `substitute_rule` explains the constraint but grants nothing. Standing is derived when the escalation is raised: items the responder authored in the `said` store → own-testimony; inferences drawn from the responder's own statements → own-interpretation; entries in the `permitted` store → own-permission; anything asserting a fact about another party, or resting on another party's record, → third-party-fact. The derivation reads each item's `origin_actor` (ADR-005 §3): the responder's own items → the own-* classes; anything asserting a fact about, or resting on the items or records of, another actor → `third-party-fact`. Fixtures set `origin_actor` at the entry boundary.

Enforcement is in the **endpoint**, not the UI, because beat 17's raw API client bypasses the console:

| Condition | Result |
|---|---|
| `confirm` + `standing_class = third-party-fact` + no resolvable `evidence_ref` | `422 evidence_required` — refused, escalation stays open, refusal recorded |
| Token role ≠ the escalation's eligible role (or an unauthorized substitute) | `403 wrong_role`, recorded |
| Disposition outside this escalation's permitted set | `422 disposition_not_permitted`, recorded |
| Escalation already consumed (disposition, cancellation, or timeout) | `409` returning the terminal state — recorded no-op, never a second effect |
| Missing required contract field on the escalation itself | the escalation refuses to fire at all (raise-time check) |

The console renders only permitted dispositions enabled; the endpoint is the authority.

### 6. Next states
`confirm` / `correct` → a new proposal revision that re-runs the gates (confirmation writes to the `confirmed` store with its scope and the cited evidence; correction updates the current case only, never persistent memory). `narrow` → new proposal revision with the narrowed scope. `permit` → an entry in the revocable `permitted` store, then re-run. `abstain` → the item stays unconfirmed, uncertainty carried forward; the Stop remains unless a declared reversible fallback within existing authority exists. `route` → recorded routing obligation plus a fresh escalation to the named role; the case parks. No dialogue disposition ever issues an `allow` ruling directly.

**Timeout is decided by the authorization service**, atomically, against the contract's response bound — never by the browser or the orchestrator, so no client clock can manufacture one. Default is the declared `abstain` or `narrow`; never proceed.

### 7. How the case console learns the outcome
Two-hop polling of non-authoritative mirrors, over routes the orchestrator is actually permitted (ADR-002). The orchestrator polls `GET /w/{w}/rulings/{id}` — the status projection, which reports the escalated ruling's current status and, once a disposition mints one, its `successor_ruling_id`; it never reads the escalation, its contract fields, or the record. The case console polls `GET /w/{w}/cases/{case_id}/state` under its dynamic case-session bearer every 2 s while an escalation is open and stops at a terminal state. SSE is rejected as unnecessary at POC scale.

The mirror is display-only and carries **no evidentiary standing** — that belongs to the authenticated post and its record entry. On divergence the authorization service wins. Ruling-status polls read a status projection, not record entries, so they are deliberately **not** written to the access-log chain (record-viewer reads still are); otherwise polling would drown the access log.

### 8. Records
Every step is a `human_intervention_event` payload on the existing record fields — no new governance-semantic fields: `dialogue_trigger_raised` (contract, standing class, question), `dialogue_response_recorded` (disposition, responder role, evidence ref, answer digest), `dialogue_response_refused` (reason code), `dialogue_timeout`. The ask-rate increments the escalation-pattern counter.

## Consequences
- The orchestrator can neither read the role token nor forge a confirmation or permission; the model never sees either. Beat 4 and the wrong-role / disposition-outside-set adversarial cases test the endpoint directly.
- Three usability costs are accepted: the case officer starts a fresh handoff after session expiry, the responder leaves the chat seat for a second tab, and the authorization-service role token is pasted once per browser profile.
- Reconciled with the same-day ADR-002: its route table already lists the escalation read route (`GET /w/{w}/escalations/{id}`, orchestrator read-only via the §7 projection), token custody follows its `localStorage` decision, and the zero-CORS posture and "orchestrator never reads an escalation's contract fields" rule hold.
- Polling adds up to ~3 s of perceived latency between answer and case-console update; acceptable, and it keeps the authoritative path one-directional.
- Review rulings 2026-08-01: `route` stays dialogue-only — non-dialogue escalations already carry the general `seek review / route to remedy` dispositions (ADR-001 §7); and `standing_class` derivation reads the per-item `origin_actor` field (ADR-005 §3) rather than staying fixture-declared.
