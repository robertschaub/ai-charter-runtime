<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-001 — Transaction lifecycle (nonces, reservations, rulings, idempotency keys)

**Status:** accepted (M1, 2026-08-01). **Spec:** §4 Gate ruling / Record entry, §5 Transactional core + Escalations-are-single-use, §6 criterion 6, §10 M1 (world-id seams).

**Amendment (M3 review, 2026-08-01):** a restart probe that proves the same ledger has no effect records `no-effect`, not `failed`; only an executed effect may have a `failed` outcome. Commitments pin a persistent services-ledger id so replacement storage cannot masquerade as proof of absence.

**Amendment (M3 review follow-up, 2026-08-02):** M4's unchanged-proposal `allow within scope` successor uses a private authorization-service entry point; terminal `no-effect` remains append-only and is corrected only by linked review evidence.

**Amendment (M4 authority review follow-up, 2026-08-02):** `narrow / modify` records and consumes the human disposition without accepting a replacement proposal. The authenticated orchestrator must then submit the next frozen revision through Authorize → Submit → Verify; an authorization-core-owned callback re-performs screening over that hash, and only a later Commit allow may reserve counters.

**Amendment (M4 native-recovery review, 2026-08-02):** the services host recovers its local ledger and
exposes the authenticated read-only probe before authorization starts. Its execute path still fails closed
while authorization is absent. Authorization then replays, sweeps, probes every non-terminal commitment,
and binds its listener only after those passes; the orchestrator binds last. Maintenance repeats without
overlapping at `SWEEP_INTERVAL_MS`.

## Context

The authorization service is the single serialization point. Commitment is two-phase: `commit-verify`
(the linearization point) binds, then a single-use short-TTL commit token discharges the effect, then
`effect_outcome` reports it. A write-ahead append must be durable before any ruling or token leaves the
service, and all state is rebuilt by replay. The spec fixes those semantics; this ADR fixes the states,
the storage format, the arithmetic, and the recovery order. Everything here is per **world** (§10 seam:
the demo runs the single world `w-demo`). Canonicalization, hashing, MAC, and encoding are ADR-007's
throughout; the three chains and their heads are ADR-003's.

## Decision

### 1. Serialization — one async writer per world

All state transitions run inside `withWorldLock(world_id, fn)`: an explicit promise-chain mutex keyed by
world id. Node's single thread does **not** serialize across `await`, so the mutex is mandatory, not
decorative — the mid-flight-revocation and counter-race tests depend on it.

- The critical section contains **only** CPU work and local file I/O (WAL append + fsync). No network
  call, no model call, no `commit-verify` round trip out of the service.
- Screening signals and per-provider projections are gathered **before** the lock. This is safe because
  signals are computed over the *frozen* proposal hash, which cannot change (a changed proposal is a new
  proposal). Deterministic rule evaluation is re-run **inside** the lock against the then-current mandate
  version, policy digest, and counters; the pre-lock evaluation is discarded.
- Verdict composition is monotone: rules produce the verdict without signals, then signals may only move
  it toward `escalate` / `stop`. There is no code path from a signal to `allow` (gate invariant).
- **Ordering inside the lock:** build the op list → dry-run `apply()` on a cloned state → append + fsync
  WAL → publish the validated clone → materialize chain files (+fsync) → release → respond. Live state
  is never mutated before the WAL fsync returns. If materialization fails after durability, the writer
  is poisoned; replay on restart repairs the projection before service resumes.
- **Single writer enforced:** at startup the service creates `records/{world_id}/.writer.lock` with
  `fs.open(..., 'wx')` (atomic on Windows) holding pid + boot id. If it exists, the service refuses to
  start and prints the manual-clear instruction. A second authorization-service process is a
  fail-closed startup error, not a race.

### 2. Write-ahead log

One append-only JSONL file per world, `records/{world_id}/wal.jsonl` — the `wal` stream of ADR-003 —
opened once in append mode and held open for the process lifetime. Line 0 is a genesis header
(`wal_version`, world id, created-at). Each process start appends a **run header** carrying `run_id`,
`boot_id`, `policy_version`, `policy_content_digest`, and the full evaluator build digest that
ADR-007's short `evaluator_build_id` abbreviates. WAL v2 operations carry the complete immutable artifact
being created (not only its id), so replay from genesis reconstructs all authority state and record
projections. One line = one **transaction**, so a whole action's mutations land or none do.

```json
{"seq":412,"world_id":"w-demo","ts":"2026-08-01T09:14:22.418Z","txn":"commit_verify",
 "run_id":"run-2026-08-01-02",
 "actor":{"credential":"proc:services_host","claimed_role":null},
 "ops":[
   {"op":"nonce.consume","nonce_id":"nce_7f3a"},
   {"op":"reservation.settle","reservation_id":"rsv_amount_2c91"},
   {"op":"reservation.settle","reservation_id":"rsv_actions_4410"},
   {"op":"ruling.consume","ruling_id":"rul_88ad"},
   {"op":"commitment.bind","commitment":{"world_id":"w-demo","commitment_id":"cmt_4b10",
    "ruling_id":"rul_88ad","frozen_proposal_hash":"…","effect_id":"eff_4b10",
    "effect_request_digest":"…","idempotency_key":"…","service":"filing",
    "action_class":"grant-filing","bound_at":"2026-08-01T09:14:22.418Z",
    "token_expires_at":"2026-08-01T09:14:27.418Z","services_host_boot_id":"svc_boot_2",
    "services_ledger_id":"ledger_7f3a",
    "recovery_contract":{"…":"…"},
    "state":"bound","outcome":null,"recovery_owner_role":"principal"}},
   {"op":"record.action.append","entry":{"world_id":"w-demo","entry_id":"rec_1044","…":"…"}}
 ],
 "prev_hash":"5ee9…","entry_hash":"a41c…"}
```

- **fsync policy:** `fs.fsyncSync(fd)` after every transaction append, inside the lock, before the ruling
  or token is serialized to the response. No group commit at POC scale.
- **Hash-linked** by ADR-007's chain rule under the `wal-entry` domain: `entry_hash` over the canonical
  entry minus itself, including its `prev_hash`; genesis `prev_hash` is 64 zeros; digests are lowercase
  hex, unprefixed. The WAL therefore has a head hash — the "write-ahead state" component of ADR-003's
  composite head, and the stream ADR-003 anchors as `wal`.
- **Torn tail:** replay stops at the first line that fails JSON parse, breaks `seq` contiguity, or fails
  its hash; the file is truncated to the last good offset before new appends. A crash can lose the last
  transaction, never corrupt an earlier one.
- **Amounts are integers in minor units** (ADR-007), so counter deltas never carry a float.
- **Clock guard:** WAL timestamps must be non-decreasing. A backwards clock jump is rejected; at startup
  the service refuses to run if the wall clock is earlier than the last WAL entry's `ts`. Ruling and
  mandate expiry use this one authorization-service clock; the executing service checks only the signed
  commit token's short TTL.
- **Op vocabulary is closed and versioned.** `apply(state, op)` is the *only* mutation path in the
  service, which is what makes replay faithful by construction.

### 3. State machines

```text
nonce        issued ──consume (commit-verify)──▶ consumed
                    └─validity window elapsed──▶ expired

reservation  reserved ──commit-verify (binds)──▶ settled ──effect_outcome=unknown──▶ held_for_reconciliation
                      └─deny │ expiry │ cancel │            held_for_reconciliation ──reconciled: effect confirmed──▶ settled
                        ruling invalidated─────▶ released   held_for_reconciliation ──reconciled: no effect────────▶ released

ruling       issued ──its nonce consumed──────▶ consumed
                    ├─binding tuple changed───▶ invalidated
                    └─validity window elapsed─▶ expired

commitment   bound ──effect_outcome success│failed──▶ discharged
                   └─no outcome (crash / probe timeout)─▶ unknown ──recovery-owner disposition──▶ reconciled

escalation   open ──disposition (atomic consume)──▶ disposed
                  ├─response bound elapsed────────▶ timed_out
                  └─action cancelled──────────────▶ cancelled

idempotency  unused ──atomic effect write──▶ recorded   (terminal; re-presentation is served
key                                                      from the ledger and counted, never re-executed)
```

Deviation from the stub's arrow list, deliberate: `held_for_reconciliation` is entered from **settled**,
not from `reserved`. Binding settles the reservation atomically at `commit-verify`; the unknown outcome
can only be discovered afterwards. The three state names and the ceiling arithmetic are unchanged — only
the arc is placed where it can actually occur.

### 4. Ruling binding and invalidation

The binding tuple is §4's: frozen-proposal hash, mandate id + version, acting-model id, service + action
class, nonce, validity window — plus the policy version and policy content digest the ruling records
(§4's invalidation rule names policy version, so it is part of what is re-checked), and the card digest
and verifying `key_id` behind the acting-model entry (ADR-006).

Invalidation is **eager and lazy**, deliberately redundant:

- *Eager:* a mandate amend/revoke, a policy reload, or a model-set change marks every `issued` ruling
  bound to the superseded value `invalidated` **in the same transaction**. Because both that transaction
  and `commit-verify` need the same world mutex, they cannot interleave.
- *Lazy:* `commit-verify` re-reads every binding-tuple element from current state before consuming the
  nonce. A missed sweep therefore still fails closed.

The mid-flight-revocation test has exactly two admissible outcomes, decided by mutex acquisition order:
revocation first → the ruling is invalid, deny; `commit-verify` first → the effect stands and is recorded.
Never a third.

### 5. Ceiling arithmetic

Counters are per `(world_id, mandate_id, counter)` — `actions`, `amount`, `notification_volume`, plus the
non-ceiling `escalation_pattern` counter that drives envelope narrowing.

```text
consumed = Σ delta  where delta > 0 and state ∈ {reserved, settled, held_for_reconciliation}
         + Σ delta  where delta < 0 and state = settled
```

Positive deltas count from **reservation** (in-flight attempts count); negative deltas count only from
**settlement**. Both directions are conservative, so every rounding of the rule fails closed.

- Unbound attempts consume nothing: `released` contributes zero, so a deny, expiry, or cancellation
  returns the counter to baseline.
- A `failed` effect after binding stays counted — its reservation remains `settled`.
- A proved absence after a services-host restart is `no-effect`, not a failed effect; it releases the held reservation.
- **Compensation is a new gated action, not a counter edit.** The WAL is append-only and the machine has
  no un-settle arc; the recovery owner's compensating action runs the gates itself and carries a
  negative-delta reservation that only counts once it settles at its own `commit-verify`.
- **Two different failures, two different verdicts:** a per-action mandate limit exceeded (beat 7) is
  *defective authority* → **deny**; a cumulative ceiling that would be crossed (beat 12) is an *aggregate
  trigger* → **escalate**. Only ruling issuance can escalate.

### 6. `commit-verify` and the executing service's one local transaction

`commit-verify` has exactly **two** outcomes: a commit token, or a deny. It is a verification, not a
re-adjudication — escalating there would mean escalating an action that is already in flight. In one
transaction it re-validates the binding tuple, exact effect intent, and counters; consumes the nonce;
settles every reservation; marks the ruling `consumed`; creates the `bound` commitment; seals the pre-effect
`commitment` record event, and mints the token.

The commitment also pins the policy-owned recovery contract and its eligible role. A later policy reload
therefore cannot reroute an already-bound unknown effect, and the services caller cannot nominate its
own recovery owner.

- **Idempotency key** = hex SHA-256 over canonical `{world_id, ruling_id, nonce}`. One ruling ⇒ one nonce
  ⇒ one key ⇒ at most one effect. It is minted by the authorization service and carried in the token, and
  it is filename-safe on Windows (64 lowercase hex chars, no separators, no reserved names).
- **Mandate binding** is re-verified here, not assumed: an HMAC that is `invalid` **or** `unverifiable`
  (unknown key id, ADR-007) is defective authority → deny.
- **Token** = `{world_id, effect_id, ruling_id, frozen_proposal_hash, effect_request_digest,
  idempotency_key, service, action_class, expires_at}` plus an ADR-007 MAC block
  `{alg, key_id, value}` under the `commit-token` domain. The executing service recomputes the exact
  effect-intent digest, verifies MAC and TTL locally, and uses the token once. Single use is
  guaranteed upstream — the nonce is consumable exactly once — and again downstream, where the
  idempotency key cannot create a second effect; an exact repeat returns the recorded outcome while a
  conflicting outcome is rejected.
- **Ledger continuity id** — the services host creates one persistent, non-secret id beside the effect
  ledger. `commit-verify` pins it into the commitment and the service repeats it in outcomes and probes.
  Replacement or cleared storage therefore cannot prove that a bound effect was absent.
- **One local transaction on the service side:** the effect payload *is* the ledger record. The service
  writes a unique `records/{world_id}/effects/{idempotency_key}.*.tmp`, fsyncs it, then atomically creates
  `…/{idempotency_key}.json` as a hard link to that complete inode. `link` is create-only on NTFS and
  POSIX, unlike Windows `rename`, which may overwrite. Creating the final link is the commit point: the
  file exists ⇔ the effect happened ⇔ its outcome is recorded.
  Stale `.tmp` files are deleted at service startup. This directory is owned exclusively by the services
  host; the authorization service reads it only over HTTP (ADR-002), never from the filesystem, so the
  process boundary stays real.
- **Retry with the same key** returns the recorded outcome without re-executing, and appends a
  `retry_served` record event.
- There is deliberately no durable `in_flight` ledger state — a second write would break the
  one-transaction rule. Its absence is exactly why a crash yields an honest `unknown` rather than a false
  `failed`, resolved by the probe rule in §8.

### 7. Escalation consumption and the disposition map

Escalations are single-use. The first transaction to consume one inside the world mutex wins; every later
arrival is a recorded no-op (`late_disposition_ignored`, with the authenticated actor). An escalation
whose six intervention-contract fields are not all present **refuses to fire**: the escalation is not
created and the action fails closed.

| Disposition | Next state | Effect on the transaction graph |
|---|---|---|
| allow within scope | `disposed` | Re-runs the evaluator against the *unchanged* frozen proposal and the *current* mandate; on `allow` it mints a **fresh** ruling with a new nonce and a new reservation, linking the human-intervention event as basis. It never bypasses evaluation and never widens the mandate; an out-of-scope approval is refused at issuance and, defence in depth, at `commit-verify` (beat 17). An `escalate` ruling never becomes a commitment. |
| narrow / modify; dialogue confirm / correct | `disposed` | The disposition itself creates no authority. The orchestrator submits the next immutable revision through Authorize → Submit → Verify, with screening re-run over the new hash; the terminal pre-commit ruling is linked as successor. |
| deny / cancel | `disposed` | Terminal; the reservation is `released`. |
| seek review / route to remedy | `disposed` | Recorded routing obligation, case parked; reservation `released`. No independent institution exists (spec §3). |
| timeout | `timed_out` | Only the declared fallback, which must itself lie within existing authority; if the fallback acts it is a new proposal. Otherwise the Stop remains and the reservation is `released`. |

Dialogue escalations are the same machine with the extended disposition set ADR-004 defines
(`confirm | correct | narrow | permit | abstain | route`); all of them land in the `disposed` row above,
none issues a ruling directly, and their timeout default is `abstain` or `narrow` — never proceed.

M4 implements the `allow within scope` successor as a private authorization-service operation invoked
only by the authenticated disposition transaction after it consumes the escalation. It reuses the
evaluator; the public orchestrator-only proposal endpoint is not widened to manufacture successors.
The authorization service derives the authorized-agent check from the original authenticated submission
record; it does not fabricate an orchestrator actor. Revised proposals use the separate orchestrator-only
continuation route and carry the human disposition record as basis through each pre-commit gate. A
wrong-state, malformed-sequence, or duplicate continuation is a recorded refusal, not an invisible no-op.
An Authorize/Submit/Verify deny is recorded but does not consume the escalation's successor link: the
orchestrator may submit only the next contiguous revision, which reruns the full sequence. An escalate or
final Verify allow claims the link and makes later continuation attempts recorded `already_continued`
refusals.
Every fresh Submit or Verify ruling, including an unchanged-proposal rerule, obtains its screening result
through the authorization core; caller-supplied screening fields are ignored.

### 8. Time, expiry, and the sweeper

- **Authority-relevant expiry is always evaluated lazily**, by comparing timestamps at decision time —
  never by asking whether a record is *marked* expired. Correctness therefore never depends on the
  sweeper running.
- A **sweeper transaction** runs at startup and every `SWEEP_INTERVAL_MS`, writing the explicit
  `expired` / `released` / `timed_out` ops so the state machines have observable terminal transitions and
  counters are freed. It makes state visible; it never makes state safe.
- **Reconciliation** of a `bound` commitment with no outcome: probe the services host by idempotency key
  (read-only, no token). `recorded` → adopt the outcome and discharge. `absent` **and** the services host
  reports the **same `ledger_id`** and a different `boot_id` from binding → `no-effect` (an unrenamed
  `.tmp` cannot survive a restart). A changed ledger id is not evidence of absence: bounded probes end in
  `unknown`. Rollback to an older copy carrying the same ledger id remains an M3 limit pending ADR-003
  anchoring. `absent` **and** the host has run continuously → retry with backoff, then
  `unknown → reconciliation-required`, which opens an escalation whose routing and eligible role come
  from the policy file's intervention-contract parameters — this is where criterion 7's *named recovery
  owner* lives, so no new mandate field is introduced. Its permitted dispositions record findings only;
  anything that acts is a new proposal.

### 9. Startup and crash-recovery order

Nothing is served until every step completes; the listener binds last.

1. Acquire the per-world writer lock (fail closed if held).
2. Scan the WAL: verify `seq` contiguity and digest links, truncate a torn tail, check the clock guard.
3. Replay every op through `apply()` into memory.
4. Repair `records/{world_id}/action.jsonl` and `records/{world_id}/access.jsonl` from `record.append`
   ops missing in those files (idempotent by `entry_id`; entries are deterministic in payload +
   predecessor hash, so repair reproduces identical `entry_hash` values). Verify both heads.
5. Run ADR-003's run-start verification against the last anchored checkpoint. Detected tampering or
   rollback **halts** — a rewound record layer is not a base to keep acting from. An absent prior anchor
   or an unreachable remote does not halt: availability is not authority (ADR-003's asymmetry).
6. Run the sweeper pass, including the reconciliation probes of §8.
7. Bind the listener.

### 10. Configured defaults

`RULING_VALIDITY_MS` 120000 · `COMMIT_TOKEN_TTL_MS` 5000 · `SWEEP_INTERVAL_MS` 5000 ·
`RECONCILE_PROBE_ATTEMPTS` 3 with 250/1000/4000 ms backoff. Escalation response bounds come from the
policy file, per escalation class. Reservation expiry is **not** independently configurable — it is the
ruling's validity window by definition. Every value is recorded in the ruling or token it governs. The
token TTL is the §9 honest-limit window and nothing else depends on its size.

## Consequences

**Testable now.** Replay of a consumed ruling or nonce (beat 8) → deny. Proposal mutation after allow →
frozen-hash mismatch → deny. Mid-flight revocation or policy change → exactly two admissible outcomes,
selected by mutex order. Concurrent requests racing a ceiling → serialized reservations, ceiling never
exceeded. Kill the process between `commitment` and `effect_outcome` → restart yields exactly one
reconciliation escalation, no duplicate effect, and a counter still consumed. Retry with the same
idempotency key → no second effect, identical recorded outcome. Deny or timeout → reservation released,
counter back to baseline ("unbound attempts consume nothing"). Illegal transitions → `apply()` rejects
them, and the rejection is itself recorded. Every one of these is decidable from the WAL alone.

**Deferred, by decision.** No WAL compaction or snapshots (replay from genesis; the seam is a
`snapshot` op carrying full state + digest). No group commit. Single writer per world only — no
multi-process or multi-node writer, enforced by the lock file rather than by consensus. The commit-token
window remains the spec §9 interpretive limit. Compensation of an irreversible effect stays a recorded
routing obligation, since the POC has no remedy decider. Clock handling is local wall-clock plus the
monotonicity guard, not a monotonic source across restarts.
