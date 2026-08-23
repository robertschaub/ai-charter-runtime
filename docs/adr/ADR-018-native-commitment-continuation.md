<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-018 — Native commitment continuation

**Status:** definition reviewed at `d0b8cc6`, GO — both contract-accuracy findings from the initial `46b40eb`
review closed, no new findings. Implementation has not started and remains separately approval-gated. **Spec:**
§§3–7 and 10 (M6), especially the commitment boundary, criteria 1, 4, 6, and 7, beats 3 and 6–8, and the
bypass/replay/mid-flight adversarial set.
**Depends on:** ADR-001, ADR-002, ADR-007 through ADR-017, and the reviewed M6.1 implementation at `5f51caa`.

## Context

The reviewed native proposal path now freezes one authorization-owned proposal and runs the fixed
Authorize → Submit → Verify sequence, including authorization-owned screening evidence. It still stops after a
Verify allow. The existing M3/M4 headless path can demonstrate Commit and a local mock effect, but it accepts a
complete caller-carried proposal, service, action class, ruling reference, and effect intent. Reusing that path for
M6 would discard the native proposal-run, case-session, conversation, model-selection, and currentness lineage that
M5 established.

ADR-016 §4 fixes the outer M6.2 shape: one short-lived execution preparation, a second explicit browser gesture,
Commit consumption by the services host, and one local mock effect. This ADR freezes the remaining implementation
contract. It begins with the complete services-host route set so the new path cannot be reviewed in isolation from
the older headless, reconciliation, and synthetic-evidence routes.

This is protocol bookkeeping around governance-semantic objects already defined by the specification. It adds no
proposal field, mandate authority, verdict, disposition, or external effect type and does not move the Charter
provenance pin. Later upstream M6.5 work on authority basis and source admissibility remains separate and
unimplemented here.

## Decision

### 1. The post-M6.2 services-host route set is exactly five routes

The services host remains loopback-only, deny-by-default, and without CORS. After M6.2 it serves exactly this set:

| Method and route | Caller | Strict request | Purpose and response boundary |
|---|---|---|---|
| `GET /healthz` | open | no body | readiness metadata only |
| `POST /w/{world_id}/services/{service}/execute` | `proc:orchestrator` | `{ruling_id, intent}` | unchanged legacy M3/M4 headless synthetic-test seam; never used by a dynamic case session or M6 capture |
| `POST /w/{world_id}/execution-preparations/{execution_preparation_id}/execute` | `proc:orchestrator` | `{}` only | new M6.2 native carrier; the service resolves all action facts through authorization and returns bounded status only |
| `GET /w/{world_id}/effects/{idempotency_key}` | `proc:authz` | no body | existing read-only reconciliation probe against the local effect ledger |
| `GET /w/{world_id}/registry-records/{record_id}` | `proc:authz` | no body | existing immutable synthetic registry-evidence resolution |

No wildcard, status, token, generic tool, reversal, compensation, or browser route is added at the services origin.
The two service POSTs are the only routes allowed to `proc:orchestrator`; the two data GETs are the only routes
allowed to `proc:authz`; the credentials are mutually distinct. Each valid credential is explicitly denied on the
other credential's routes. Missing or unknown credentials receive the existing bounded 401/429 handling, valid
wrong credentials receive 403, and authenticated refusals are relayed into the authorization-owned access chain.
M6.2 adds the access-route label for the native execution route without changing the other labels or the bounded
unauthenticated-ingress aggregation.

Authenticated services routes reject a present browser `Origin`, including the configured orchestrator origin;
native server-to-server clients send no `Origin`. Static responses remain `Cache-Control: no-store`. Unknown
method/path combinations return 404 and cannot be used to infer a credential's permissions. The native response is
the exact-key object `{execution_preparation_id, state, effect_outcome, recorded_at}`. `state` is
`preparation-unavailable | commit-denied | commit-escalated | effect-recorded | no-effect | indeterminate`;
`effect_outcome` is
`success | failed | no-effect | unknown-reconciliation-required | null`; and `recorded_at` is a timestamp or null.
It contains no commit token, effect intent, proposal content, ruling internals, nonce, reservation, credential,
provider content, or handler detail.

### 2. Preparation issuance binds one exact native proposal run without issuing authority

An active dynamic case-officer session may make a strict `{}` JSON request on the orchestrator origin:

```text
POST /w/{world_id}/cases/{case_id}/proposal-runs/{proposal_run_id}/execution-preparations
```

The route requires the exact session world, case, role, expiry, authorization boot, and a present exact
orchestrator Origin. The orchestrator calls the same path on the authorization origin as `proc:orchestrator`, with
only its server-derived on-behalf session claim and the same strict `{}` body. This is the twenty-fourth orchestrator
gate/data route. It is `authorityChanging: false`, Origin-guarded, and access-recorded because it creates a bounded
protocol credential but cannot issue a ruling, reserve a counter, consume a nonce, bind a commitment, mint a
token, call a service, or create an effect.

Authorization issues an opaque `execution_preparation_id` with at least 128 bits of cryptographic entropy, bound
to its current boot and expiring no more than two minutes after issue. Under the world lock it resolves, rather
than accepts from the caller:

- the exact case-session receipt, case, proposal run, proposal id/hash, action id, and revision;
- the current conversation version, proposal-origin record, and absence of a claimed successor;
- the current model selection and requested/served model plus signed-card id, version, digest, and verification key;
- the mandate id/version, policy version/content digest/evaluator build, and current system-use decision reference;
- the issued allow rulings for Authorize, Submit, and Verify, including their exact validity windows;
- the connected service and action class; and
- the effect-intent basis: world, frozen-proposal hash, service, action class, target, exact parameters, and data to
  be disclosed.

The `EffectIntent` schema also contains the Commit ruling id, which does not exist at preparation time. M6.2 does
not fabricate or accept that future id. The preparation stores the exact semantic basis above and its ADR-007
digest under `execution-effect-intent-basis`. During consumption authorization generates the Commit ruling id,
constructs the complete `EffectIntent` from that id plus the stored basis, and verifies the basis digest again.
This is the only deferred field, and it remains server-owned protocol correlation rather than caller-supplied
semantics.

After checking for an exact same-session retry, preparation issuance requires the native proposal-run state to be
exactly `verified`, with one current issued allow at each precommit gate and no other live execution preparation,
Commit ruling, commitment, effect, or conflicting native execution state for that proposal/action. A legacy Commit
ruling against a native-origin proposal is a conflict, not reusable authority.

The durable states are `issued | consumed | expired | invalidated`; `consuming` is a transaction-local claim between
`issued` and one complete terminal transaction, never a replayable state. An exact same-session request under
byte-identical currentness returns the existing issued preparation. A different session, concurrent non-identical
request, or changed binding conflicts; it does not multiply preparations. A concurrent exact same-session request
serializes and returns that same preparation. Session close/expiry, authorization restart,
proposal succession, conversation change, model switch, card/mandate/policy/system-use change, precommit-ruling
invalidation/expiry, or TTL expiry invalidates or expires an issued preparation. No invalidation calls a service or
manufactures a replacement.

The process issue response is exactly `{kind: "execution_preparation", execution_preparation_id,
proposal_run_id, state: "issued", issued_at, expires_at}`. The orchestrator constructs the browser response
field-by-field as `{execution_preparation_id, proposal_run_id, state: "prepared", expires_at}`. Neither projection
contains the effect-intent basis, currentness bindings, case-session receipt, boot id, or authority facts.

### 3. A second gesture asks for Commit; it does not provide authority facts

The same case session uses a second, explicit orchestrator-origin request:

```text
POST /w/{world_id}/cases/{case_id}/proposal-runs/{proposal_run_id}/execute
{ "execution_preparation_id": "…" }
```

Only the opaque preparation id is accepted. The browser cannot send a proposal, intent, gate, service, action
class, target, parameters, ruling, signal, mandate, selection, system-use reference, nonce, reservation,
idempotency key, retry instruction, or token. The orchestrator authenticates the same session and Origin, consumes
its local wrapper before the dependency call, and sends a strict `{}` body to the services host's native execution
route. The preparation id appears only in the URL.

The second gesture is workflow liveness, not action authority. It cannot cure missing authority or change the
proposal. The services host, not the browser or orchestrator, then calls:

```text
POST /w/{world_id}/execution-preparations/{execution_preparation_id}/commit-verify
{ "services_host_boot_id": "…", "services_ledger_id": "…" }
```

Only `proc:services_host` may call this authorization route. The body contains exactly the two service-owned
continuity identifiers. The route is authority-changing because it may issue the Commit ruling, consume its nonce,
settle reservations, bind a commitment, and seal the pre-effect record. A present foreign `Origin` is rejected by
the existing authority-changing-route guard. The orchestrator is denied here, and the services host is denied on
preparation creation.

The services host supplies no on-behalf claim. Authorization uses the case-session receipt and authorized-agent
identity already bound into the preparation. The WAL transaction is authenticated as `proc:services_host`, while
the mandate-agent check is resolved from that stored session/proposal lineage. Neither identity is inferred from a
header carried across the executing-service boundary.

### 4. Commit ruling and `commit-verify` are one authorization transaction

Under the world lock, the native Commit route:

1. requires one exact issued, unexpired preparation and re-resolves every field and digest in §2;
2. transitions it to `consuming` in the transaction's disposable state;
3. evaluates Commit against the exact stored proposal, service/action class, current mandate, card, selection,
   policy, system-use decision, counters, and effect-intent basis;
4. appends the Commit ruling and its action record; and
5. for an allow only, immediately performs ADR-001's existing `commit-verify` transition against the newly built
   complete intent before marking the preparation `consumed`.

The ruling composer and commit verifier are factored as locked-state builders; the native route does not call one
public transaction from inside another. The one WAL transaction dry-applies and validates all operations, fsyncs
before responding, then publishes. `consuming` is therefore the internal single-use claim within that transaction,
not a recoverable half-state: replay sees either the prior issued preparation or one complete terminal transaction.

Commit deny and escalate are durable terminal results for that preparation. They return no token and start no
service effect. A Commit escalation may open the policy-owned intervention contract and retain/release its
reservation only through ADR-001's existing state machine; M6.2 does not auto-dispose it or auto-resume execution.
Disposition does not suppress ADR-001's normal re-evaluation: `allow-within-scope` may append a successor ruling,
and a revision remains successor evidence. For a native-origin Commit escalation, either successor has no execution
path in M6.2: it does not revive the consumed preparation, and even an `allow` successor is categorically refused
at the legacy consumption boundary fixed in §7. Any native continuation after escalation requires a separately
defined and reviewed protocol.

On allow, the same transaction consumes the new nonce, settles its reservations, consumes the ruling, binds the
commitment to the services host boot and persistent ledger id, and seals the commitment record before returning.
No issued Commit allow is externally observable between ruling and binding, so revocation/currentness change has
only the two ADR-001 outcomes selected by lock order: it lands first and the native use fails closed, or the atomic
Commit transaction lands first and the bound effect may discharge.

The successful authorization response contains the exact intent and short-TTL single-use commit token only on the
authenticated services-host connection. It also carries the preparation and commitment correlation needed for the
host to reject a swapped response. The token and complete `EffectIntent` never cross into an orchestrator response,
browser projection, access record, action record, WAL field, or log; the separately defined preparation basis and
existing commitment metadata remain the only durable subsets.

### 5. The services host verifies again and performs one local mock effect

The services host verifies the authorization response is for the requested preparation, recomputes the complete
effect-intent digest, verifies the token MAC, TTL, world, ruling, frozen hash, service, action class, and local
intent binding, and only then selects the exact configured local mock handler. The orchestrator cannot choose the
handler because the native services route has neither a service path parameter nor a body.

The existing effect ledger remains the terminal enforcement point. It atomically records one local synthetic
effect and its `success | failed` outcome under the authorization-minted idempotency key. A matching duplicate key
returns the existing record; a binding mismatch or malformed/expired token fails before the handler. The services
host then reports the exact outcome over the existing `proc:services_host` authorization route. Handler output is
bounded synthetic detail for the durable service/authorization record and is not returned to the browser.

M6.2 adds no network egress, real filing, notification, payment, account mutation, generic tool call, or external
effect. The acceptance path uses the local `filing:grant-filing` handler. Other existing synthetic handlers remain
available to their existing tests, but the native path cannot name one independently of the frozen proposal and
current mandate.

### 6. Ambiguity recovers status; it never retries authority or an effect automatically

The orchestrator, services host, and authorization service keep bounded in-flight deduplication keyed by the
preparation id. Concurrent native execute requests join or receive the same durable terminal result; they do not
start two Commit transactions.

No dependency failure causes an automatic POST retry, new preparation, new Commit ruling, token remint, handler
fallback, or alternate service. Recovery is evidence-driven:

- failure before authorization consumes the preparation leaves it issued or makes its state unknown to the caller;
  the caller reads proposal-run status before any new explicit action;
- a lost authorization response after commitment binding leaves a sealed commitment with no assumed effect;
  existing reconciliation determines `no-effect` or `unknown`, and the consumed preparation is never replayed;
- once the effect ledger commits, any exact duplicate is served from that ledger without invoking the handler;
- a lost outcome-report response is recovered from authorization status or by re-reporting the one existing ledger
  outcome, never by re-executing; and
- a services-host restart with the same ledger can recover the existing outcome, while absent evidence under a new
  boot follows ADR-001's same-ledger `no-effect` rule. A changed ledger id remains indeterminate and routes to the
  existing recovery owner.

For an already consumed preparation, authorization may return to the services host only the bounded commitment
correlation needed to locate and verify an existing local ledger outcome. It never returns a fresh token after the
first response. If no matching local outcome exists, the services host fails closed and waits for reconciliation;
it does not discharge the commitment after the original token window.

Authorization restart invalidates every still-issued boot-bound preparation. A consumed preparation, bound
commitment, effect, and outcome replay as their durable states; restart never rewinds them to issued. Orchestrator
restart loses local wrappers and browser sessions. A new handoff can read the durable redacted status but cannot
resume or repeat a consumed execution.

### 7. Native and headless paths cannot be mixed

The legacy orchestrator `POST /w/{world_id}/actions/execute` remains restricted to the static headless case-officer
test credential; dynamic sessions are still denied. Its downstream services route remains the caller-carried
`/services/{service}/execute` seam and is forbidden in M6 capture.

Defence in depth is added at authorization: a proposal carrying an ADR-013 native proposal-origin record may not
receive an initial Commit ruling through legacy `proposal.submit`, `ruleProposal`, or `/actions/execute`. A
disposition successor may still be appended as §4 evidence, but regardless of issuance path, verdict, policy, or
disposition, the legacy `POST /w/{world_id}/commit-verify` route and public `commitVerify` core seam refuse every
Commit ruling whose proposal has that native-origin record. Only the native preparation route's atomic locked
builder may make such a ruling consumable. Conversely, the native preparation route requires that exact origin
record and never accepts a caller-carried proposal. A headless proposal cannot be upgraded into a native run by
guessing a case, run, or preparation id; its existing Beat-17 disposition and legacy commitment path is unchanged.

The browser has no services-host credential, receives no CORS permission, and cannot call either services POST.
The orchestrator process can transport an opaque preparation id but cannot call the authorization Commit route or
obtain its token. The services host can consume a preparation and report/probe its own effect, but cannot create or
alter a preparation, proposal, session, mandate, selection, precommit ruling, or escalation disposition.

### 8. Proposal-run status is the only recovery projection

The existing authorization process `GET` for a proposal run is extended; no new status route is added. Its strict
process-only execution branch may contain the preparation id/state/expiry, Commit ruling projection, escalation id,
commitment/effect correlation, outcome, and state timestamps needed by the orchestrator to recover. It omits the
commit token, raw MAC, nonce, reservation internals, full intent, session receipt, authority bindings, service
handler detail, and recovery probe bodies.

The orchestrator constructs the browser branch field-by-field. Alongside the existing proposal and gate evidence it
may show only:

- `execution.state` as `unavailable | available | prepared | commit-denied | commit-escalated | committed |
  effect-recorded | no-effect | indeterminate`;
- the preparation id and expiry only while an explicit browser use can still consume it;
- the bounded Commit ruling projection and escalation id when one exists; and
- `effect_outcome: success | failed | no-effect | unknown-reconciliation-required | null` plus its recorded time.

The browser receives no commitment/effect/idempotency ids, effect-intent basis or digest, service boot/ledger id,
action/access record id, token, handler detail, or internal currentness binding. Full records and receipts remain on
the authorization-origin role-scoped record surfaces. A lost browser response is recovered only through this GET;
browser storage or DOM state never asserts that Commit or an effect happened.

## Implementation boundary

After a GO review and separate maintainer approval, the implementation tranche may add only:

1. strict execution-preparation, locked Commit-use, WAL/state, process/browser projection, and access-evidence
   schemas plus replay/invalidation logic in the authorization core;
2. the one orchestrator browser preparation route, one authorization preparation route, one authorization
   Commit-consume route, one orchestrator browser execute route, and one services-host native execute route fixed
   above;
3. the native-origin guards on every legacy Commit issuance seam and the legacy `commit-verify` consumption seam;
4. services-host client/route/ledger recovery plumbing and local mock-effect integration; and
5. deterministic unit, real-listener, three-process, race, crash, and exact-key tests using synthetic fixtures and
   loopback adapters only.

The implementation may refactor the existing locked Commit builder and services-host result schemas, but it may
not change a governance-semantic proposal/mandate/ruling field, weaken existing M3–M6.1 behavior, add a provider
call, create a real effect, edit generated/append-only records outside the test harness, move the Charter pin, or
start M6.3 capture work.

## Acceptance tests

The implementation is acceptable only if all of the following are proved deterministically:

1. The services host exposes exactly the five routes in §1. Method/path, credential, Origin, strict-body, 401/403/
   404/413/422, bounded unauthenticated-ingress, access-log, no-CORS, and no-store tests cover the complete matrix;
   neither valid process credential gains the other's route set.
2. The authorization adapter exposes exactly twenty-four orchestrator gate/data routes after adding the one
   non-authorizing preparation route. `proc:orchestrator` is denied on the new authority-changing Commit route;
   `proc:services_host` is denied on preparation creation and every orchestrator/browser mutation.
3. Preparation issuance requires the exact active session and a native proposal run with three current issued
   precommit allows. Empty-body, same-session idempotency, cross-session conflict, expiry, restart, successor,
   conversation, selection, card, mandate, policy, system-use, and ruling-currentness cases leave zero Commit
   ruling, reservation, nonce consumption, token, service call, or effect.
4. Exact-key and digest tests prove the preparation binds every §2 field, uses
   `execution-effect-intent-basis`, and leaves only the future authorization-generated Commit ruling id deferred.
   No caller/model field can alter the eventual complete intent.
5. The successful path proves native model evidence → frozen proposal → screened Authorize/Submit/Verify → one
   preparation → one atomic Commit allow/`commit-verify` → services-host token/intent verification → one local
   `filing:grant-filing` effect → outcome and durable record, with exact ids/digests joined across both ledgers.
6. Commit deny and Commit escalate each consume the preparation, return no token, invoke no handler, and create no
   effect. An escalation carries the full policy-owned contract; no disposition automatically resumes execution.
7. Revocation, expiry, policy reload, model/card/selection/system-use change, proposal mutation/succession, wrong
   session/case/run, stale preparation, basis mismatch, counter race, and services boot/ledger mismatch serialize
   before binding or produce only the already-bound outcome allowed by ADR-001's lock order.
8. Duplicate and concurrent preparation/use requests, a lost authorization response, a lost services response, a
   lost outcome-report response, authorization/orchestrator/services restart, token expiry, and reconciliation
   recover one durable state or fail closed. No case produces a second ruling-authority consumption or mock effect.
9. Real-listener tests prove dynamic sessions cannot use `/actions/execute`, native proposals cannot use the legacy
   Commit seam, headless proposals cannot enter the native route, browsers cannot reach services, and neither
   process can smuggle proposal, intent, authority, retry, ruling, or token fields through a strict `{}` route. A
   synthetic permissive policy that produces an `allow` disposition successor for a native-origin Commit
   escalation is still refused by legacy `commit-verify` before nonce/reservation/commitment/token/effect mutation;
   the equivalent headless Beat-17 path remains unchanged.
10. Process and browser exact-key tests prove the token and intent remain services-only; credentials, boot/ledger
    continuity, nonce/reservation internals, hidden authority bindings, raw provider bytes, and handler detail are
    absent from browser, orchestrator, access-log, and public response surfaces.
11. All M3–M6.1 tests remain green, including headless vertical-slice/reconciliation tests and the M6.1 paused
    screening path. `npm run typecheck`, `npm test`, `npm run cards:verify`, and `git diff --check` pass with signed
    cards, provenance pins, and generated records unchanged.

## Deferred and excluded

M6.2 does not add a live provider call, M6.3 runner or artifact, checkpoint operation, real or external effect,
general action API, automatic retry/fallback, post-Commit reversal/compensation, native continuation after a Commit
escalation, remedy decision, production identity, new policy semantics, authority-basis/source-admissibility work,
or an assurance claim. It does not authorize probing, key generation/rotation, card signing, record editing,
capture publication, or pushing.

## Consequences

The native case path can demonstrate the full three-process invariant without borrowing the headless seam: the
model supplies proposal evidence, authorization alone decides and binds Commit, and the services host verifies the
single-use token against the exact intent before one local effect. The explicit preparation and second gesture add
latency and state, but make proposal readiness, commitment, and effect separately observable and recoverable.

The boundary remains intentionally narrow. A compromised orchestrator holding a live session can request a
preparation for a currently eligible proposal and transport it at the wrong procedural moment, because neither
browser gesture is independently attested action authority. It still cannot make an ineligible preparation valid,
alter the authorization-owned binding or proposal, decide Commit, receive the token, or bypass the services host's
terminal verification. This POC demonstrates complete mediation and process separation, not independent operators
or production-grade user-presence attestation.
