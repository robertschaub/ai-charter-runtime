<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-003 — Composite-head checkpoint anchoring

**Status:** accepted (M1, 2026-08-01); M6.0a acknowledgment-classification implementation reviewed at
`be7f2ef` (2026-08-12), GO — no findings. **Spec:** §3 record layer, §9 (cryptography limits).

## Context
Local streams cannot detect their own tail rollback: a truncated chain is still internally valid. A composite head digest — write-ahead state, action chain, access-log chain — is written to a checkpoint file in this public repo and pushed, so the remote copy pins a prefix the local process can no longer silently drop. All canonicalization, hashing, and encoding follow ADR-007.

## Decision

### Streams, heads, and the composite digest
Three chains per world, identical construction (ADR-007's chain rule, one domain tag each): `records/<world>/wal.jsonl`, `.../action.jsonl`, `.../access.jsonl`. The demo runs a single world, `w-demo`; per-world files are the M1 seam for a possible later public sandbox, and ordering guarantees are per world.

A **head** is `{world, stream, length, head_hash}`. The entry count matters as much as the hash: it turns a rollback into a readable "7 entries missing" instead of a bare mismatch.

The **composite digest** is SHA-256 (domain `checkpoint-composite`) over the canonicalized array of all heads, sorted by `world` then `stream` under ADR-007's single sort rule — no hand-declared stream order to remember. **One composite over all worlds, with the per-world heads listed inside the artifact**, so a single world's chain can still be verified in isolation from its own row. The composite is a whole-system state commitment, never a per-world identifier: it moves whenever any world appends.

### Checkpoint artifact
`docs/checkpoints/<seq>-<compact UTC>.json`, e.g. `0007-20260801T093214Z.json` — no colons in the filename (Windows), zero-padded seq for lexical ordering. Files are append-only: never edited, never deleted; superseding means a new file. `docs/checkpoints/latest.json` is a pointer (`{seq, file, checkpoint_id, composite_digest}`) that the verifier reads *and* cross-checks against the highest seq on disk, so a pointer rolled backwards is itself detected. Both are JSON and carry no SPDX header — the `docs/` row of [LICENSE.md](../../LICENSE.md) governs.

```json
{
  "schema": "ai-charter-runtime/checkpoint/v1",
  "seq": 7,
  "checkpoint_id": "cp-0007",
  "created_at": "2026-08-01T09:32:14.512Z",
  "reason": "run-end",
  "run_id": "run-2026-08-01-02",
  "hash_alg": "sha256",
  "policy_content_digest": "b7e2…",
  "evaluator_build_id": "gate-core@0.0.1+9f3c1a2b7d4e5f60",
  "prev_checkpoint_id": "cp-0006",
  "prev_checkpoint_digest": "41ad…",
  "streams": [
    { "world": "w-demo", "stream": "access", "length": 42,  "head_hash": "9c01…" },
    { "world": "w-demo", "stream": "action", "length": 118, "head_hash": "0f7b…" },
    { "world": "w-demo", "stream": "wal",    "length": 233, "head_hash": "5ee9…" }
  ],
  "composite_digest": "d3a4…"
}
```

Checkpoints chain to each other: `prev_checkpoint_digest` is the ADR-007 digest (domain `checkpoint`) of the whole previous file, so removing an intermediate checkpoint leaves a gap. The policy digest and evaluator build id ride along so the anchor also pins which rules and which evaluator were live at that point.

### Cadence
- **Run start** — verify first, then anchor. This is the run's baseline.
- **Run end** — always.
- **Optional flush** — every N appended entries across all streams (`CHECKPOINT_FLUSH_EVERY`, default `0`, off). Run-boundary anchoring keeps git history small; the flush trades commits for a shorter window and is enabled for long capture sessions.
- The deterministic test suite runs the writer in `write-only` mode: artifacts on disk, **no commit, no push**. Beat 15 asserts the detector against a locally written checkpoint; the pushed anchor is exercised in demo runs and the M6 capture.
- Every anchor attempt appends one `anchor` event (success: checkpoint id, composite digest, remote sha; failure: error class) to the access-log chain. That entry necessarily lands *after* the heads were computed, so it belongs to the next window — expected, not a bug.

### Push and acknowledgment, and what a failure means
"Committed and remotely acknowledged" is checked, not assumed: `git commit -m … -- <checkpoint-paths> docs/checkpoints/latest.json` in pathspec form, where `<checkpoint-paths>` is the explicit list of only the new checkpoint and any earlier local checkpoint artifacts needed to make its chain complete, so the maintainer's unrelated working-tree edits are never swept in; then `git push`; then a read-only remote observation must prove that the configured branch contains the exact checkpoint commit. Git commands run through `execFile` with argument arrays, `GIT_TERMINAL_PROMPT=0`, and a timeout, so a credential prompt fails fast instead of hanging the demo. Never `--force`; no path outside `docs/checkpoints/` is ever staged; a rejected non-fast-forward push is **not** auto-pulled or rebased — the writer never rewrites or moves the maintainer's branch. Anchoring is skipped with a warning on a detached HEAD or an in-progress merge or rebase.

**A definitely failed push does not fail the run closed.** The checkpoint remains a local candidate, an
`anchor_failed` event goes to the access-log chain, the console warns, and the run continues with an explicitly
**extended un-anchored window**. This is deliberate. Anchoring detects after-the-fact rollback; it does not gate
authority, and the invariants that must fail closed are about ambiguity and missing authority
([AGENTS.md](../../AGENTS.md)), not network reachability. Treating an availability failure as an authority failure
would misrepresent what the mechanism does. M6.0a narrows “definitely failed” and removes the unsafe assumption
that every absent latest commit is an honest failed push.

**The one fail-closed case is its mirror:** if verification at run start finds tampering or rollback against the last anchor, the run **halts**. A rewound or corrupted record layer is not a base to keep acting from.

### M6.0a — acknowledgment evidence and fail-safe classification

This amendment closes one deferred ambiguity before M6 capture. The M1 verifier asks whether the latest local
checkpoint commit is on the configured remote branch, but an absent result can mean either an honestly unpushed
local candidate or removal of a checkpoint that the remote previously acknowledged. The former extends the open
window; the latter must halt. Remote absence alone cannot distinguish them.

The amendment changes no `ai-charter-runtime/checkpoint/v1` artifact or `latest.json` field. Its evidence is the
already-defined immutable checkpoint chain, an exact local commit that contains an artifact and matching pointer or
an explicit `uncommitted` result, the access-chain `anchor` or `anchor_failed` event, and a current observation of
the configured remote. M6.0a must first validate the checkpoint and record chains under steps 2–5 below, then
resolve this evidence. A malformed or contradictory local chain is a local integrity alarm regardless of remote
availability.

#### Terminal attempt evidence

For each checkpoint id there is at most one terminal attempt event across the configured world's verified access
chain:

- `anchor` is written only after a reachable remote observation proves that the configured branch contains the
  exact local checkpoint commit. Its `checkpoint_id`, `composite_digest`, and `remote_sha` must bind that artifact,
  digest, and commit exactly.
- `anchor_failed.error_class` has a closed interpretation: `pre_remote_failure` means no remote mutation was
  attempted; `remote_definite_absence` means a post-attempt reachable observation proved the candidate commit
  absent; and `acknowledgment_unknown` covers timeout, transport failure, unreachable remote, or any other outcome
  for which acceptance cannot be excluded. Any unknown class is treated as `acknowledgment_unknown`; the existing
  string field therefore needs no schema widening or checkpoint-artifact field.
- `pre_remote_failure` and `remote_definite_absence` are the only affirmative evidence that a local candidate was
  not acknowledged. A command error, timeout, or credential message is not by itself such evidence.
- A candidate for which no local commit contains the exact artifact and matching pointer is `uncommitted`. Only a
  `pre_remote_failure` can definitely classify that candidate; `anchor`, `remote_definite_absence`, or an asserted
  commit sha for it is invalid evidence and halts.
- A checkpoint is never retried after either terminal event. A later attempt creates a new checkpoint id and must
  include every locally retained checkpoint artifact needed to keep the committed checkpoint chain complete.
  `anchor` plus `anchor_failed`, duplicate terminal events, an event for an unknown checkpoint, or an event whose
  binding is invalid is an ambiguity and halts.

The one-event rule matters because the event follows the checkpoint heads and is pinned only by a later
checkpoint. If a failed checkpoint could later be successfully retried under the same id, truncating the later
success event could expose the earlier failure and falsely relabel a real remote rollback as “honest unpushed.” A
new checkpoint id for every later attempt makes the earlier terminal evidence immutable in meaning. A crash after
remote acceptance but before `anchor` append remains `acknowledgment_unknown`; current positive remote presence can
still establish acknowledgment, while later absence cannot be laundered into a definite failure.

“Most recent prior acknowledged commit” means the commit bound by the latest valid `anchor` event before the
candidate in the completely verified checkpoint/access history. “No prior acknowledgment” is available only when
that complete history contains no valid `anchor` event; it is never inferred merely from the latest tail or pointer.

#### Remote observation seam and outcome matrix

Remote I/O enters through an injectable observation seam bound to the exact configured repository URL and branch.
The production observer reports one of:

- `unavailable(reason)` for a network, transport, authentication, timeout, or observation-backend failure;
- `ref_absent`; or
- `ref_present(remote_head_sha, contains)` where `contains(commit_sha)` is a proved containment result for each
  locally relevant checkpoint commit.

The observer only reads remote state. It performs no push, pull, rebase, force operation, branch move, recovery, or
automatic retry. If its backend cannot prove containment, it reports `unavailable` rather than guessing. Unit and
integration tests inject observations directly and must not invoke `git push`, `git ls-remote`, or any network.
`--local` continues to skip the remote observation explicitly; it can prove local integrity but can never satisfy a
remote-acknowledgment predicate.

After local validation, a pure classifier applies these outcomes:

| Current observation and verified local evidence | Result |
|---|---|
| Remote contains the most recent prior acknowledged commit (when one exists), contains the exact latest candidate commit, and that candidate commit contains the exact artifact and pointer bytes | `acknowledged`; use that checkpoint as the current remote anchor. A missing local terminal event does not defeat this current positive proof, and no recovery event is synthesized. |
| Latest candidate is uncommitted with a sole `pre_remote_failure`, or remote omits its exact commit with a sole `pre_remote_failure` or `remote_definite_absence`; and the remote still contains the most recent prior acknowledged commit, or no prior acknowledgment has ever existed | `unanchored_local_candidate`; continue with an extended open window. |
| Remote ref is absent, no prior acknowledgment has ever existed, and the latest candidate has one of those two definite-failure events | `unanchored_local_candidate`; report “no prior acknowledged checkpoint.” |
| Remote ref is absent after any prior acknowledgment, or a present/diverged ref does not contain the most recent prior acknowledged commit | `remote_rollback`; halt. |
| Remote omits the latest candidate and its terminal evidence is missing, contradictory, invalid, or `acknowledgment_unknown` | `remote_acknowledgment_ambiguous`; halt. |
| Remote is unavailable after local integrity succeeds | availability warning and extended open window; do not claim a pushed checkpoint or satisfy M6 completion. |

A present but diverged ref is therefore not automatically a rollback: it is safe to continue only when it still
contains the last acknowledged checkpoint and the newer local candidate has affirmative definite-failure evidence.
For every reachable observation, containment of the most recent prior acknowledged commit is evaluated before the
latest candidate; dropping that prior commit halts even if the ref independently contains the candidate bytes.
Every ambiguity in a reachable-remote result resolves toward halt, never toward “honest unpushed.” Remote
unavailability remains the one availability result; it cannot convert missing or unknown evidence into definite
failure.

The classifier trusts terminal-attempt evidence from the verified local access chain. An operator able to forge
that chain and also roll back the force-push-protected remote can defeat this single-custodian mechanism; that
combined control is the no-independent-custody limit disclosed below, not an assurance this POC claims to solve.

`latestPushedCheckpoint`, receipts, and the open-window calculation use the most recent checkpoint proved present
by the current remote observation, not merely `latest.json`. When a newer candidate is honestly unpushed, receipts
continue to name the prior acknowledged checkpoint and the open window includes every record after that prior
anchor. With no prior acknowledged checkpoint, the whole locally validated chain is labelled unanchored.

#### M6 completion predicate and acceptance tests

M6.4 may assert `remotely_acknowledged` only from a current `acknowledged` result containing
`checkpoint_id`, `composite_digest`, `checkpoint_commit_sha`, `remote_head_sha`, configured `repo_url` and
`branch`, and `observed_at`. The checkpoint commit must contain the exact artifact and pointer bytes, the local
chains must extend its heads, and the current remote head must contain that commit. A stored `anchor` event, a
successful historical push, local mode, or an availability warning cannot satisfy this predicate.

The M6.0a implementation acceptance matrix must deterministically cover all rows above plus: a remote that contains
the latest commit after an ambiguous push; a dropped prior anchor; a diverged ref that retains the prior anchor and
omits a definitely failed latest candidate; missing, duplicate, mutually contradictory, unknown-class, and
mis-bound terminal events; receipts and window counts based on the prior anchor; and preservation of the existing
tamper, truncation, and pointer-rollback alarms. Tests use synthetic records through the harness only. They perform
no push or network operation and edit no generated or append-only record by hand.

The implementation reviewed at `be7f2ef` adds classification and reporting only. It adds no checkpoint writer,
retry, recovery, provider call, capture, key or card operation, generated/append-only record edit outside the
synthetic test harness, or push. Exact-SHA review returned GO with no findings. The unrelated general `reverse`
disposition remains parked for M6.0b.

### Verification procedure (beat 15)
`npm run verify:records`, a `tooling/` CLI over the gate-core verifier (combined artifact per LICENSE.md):

1. Resolve the latest local checkpoint from `latest.json`, cross-checked against the highest seq on disk.
2. Walk the checkpoint chain — contiguous seq, each `prev_checkpoint_digest` recomputed — and recompute each file's `composite_digest` from its own `streams` rows, so a hand-edited anchor fails here.
3. Recompute every local chain from entry 0, link by link: **in-line tampering** fails loudly at index k (beat 15a).
4. For each anchored head, require local `length ≥ anchored length` **and** that the local entry at index `anchored_length − 1` hashes to `head_hash` — the local chain must *extend* the anchor. Equality would be wrong: chains legitimately grow after a checkpoint. Failure is a **rollback alarm** naming world, stream, and divergence index (beat 15b: the truncated prefix is internally valid, and only the anchor exposes it).
5. Streams listed in the anchor must exist. A world appearing only after the anchor is unconstrained — and a world created *and* destroyed inside one window leaves no trace (§9).
6. After local validation, M6.0a resolves terminal attempt evidence and
   applies the current-remote outcome matrix above rather than treating every absent latest commit as rollback or
   honest failure. `--local` skips only this remote step, for the test suite and offline runs, and says so in the
   report. With no remotely acknowledged checkpoint, the report states "no prior acknowledged checkpoint".
7. The verification run appends its own access-log entry **after** reading, recording the lengths it read, so verification never mutates the chain it verifies and the access chain's self-reference is explicit rather than circular.

The pass state reports the latest locally validated checkpoint, current remote-acknowledgment basis, and open
window separately — never as a green check. Any alarm exits non-zero; the record viewer renders the same facts.

### Receipts (beat 16)
The applicant's record receipt names the latest **pushed** checkpoint: `checkpoint_id`, `composite_digest`, the remote commit sha and repo URL, the world's action-chain length at anchor, and this action's entry index — so the receipt states plainly whether the action falls inside the anchored prefix or in the open window. Its own text says it is a local receipt: a true lodgment receipt needs the independent custody that is out of scope (§9).

## Consequences
- Rollback is detectable only back to the last currently proved remote acknowledgment. §9's window stands, now
  carrying a number that the console and every receipt state out loud. A definite local push failure extends that
  window; ambiguous acknowledgment with a reachable remote halts.
- The anchor is external to the record layer's storage — different medium, remote copy, force-push-protected `main` — but **not** external to the operator. It is not independent custody, and nothing in this repo may call it that.
- `records/` stays gitignored: only hashes leave the machine, never record content. That is the split-custody direction in miniature.
- Checkpoint timestamps come from the local clock. GitHub holds an independent record of when the push arrived; the POC does not retrieve it, so the anchoring *time* is self-asserted while the anchored *content* is remotely pinned.
- Git history grows by one commit per checkpoint — a couple per demo run at run-boundary cadence, which is why per-N flush is off by default.
- Anchoring adds a dependency on the network and on `git` being on PATH: observation unavailability is degraded,
  never fatal, while locally ambiguous evidence or proved rollback remains fatal.
