<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-003 — Composite-head checkpoint anchoring

**Status:** accepted (M1, 2026-08-01). **Spec:** §3 record layer, §9 (cryptography limits).

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
"Committed and remotely acknowledged" is checked, not assumed: `git commit -m … -- docs/checkpoints/<file> docs/checkpoints/latest.json` in pathspec form, so the maintainer's unrelated working-tree edits are never swept in; then `git push`; then `git ls-remote origin <branch>` must return the commit sha that contains the checkpoint. All three run through `execFile` with argument arrays, `GIT_TERMINAL_PROMPT=0`, and a timeout, so a credential prompt fails fast instead of hanging the demo. Never `--force`; no path outside `docs/checkpoints/` is ever staged; a rejected non-fast-forward push is **not** auto-pulled or rebased — the writer never rewrites or moves the maintainer's branch. Anchoring is skipped with a warning on a detached HEAD or an in-progress merge or rebase.

**A failed push does not fail the run closed.** The checkpoint is simply *not made*: the artifact stays on disk uncommitted, an `anchor_failed` event goes to the access-log chain, the console warns, and the run continues with an explicitly **extended un-anchored window**; the next run start retries. This is deliberate. Anchoring detects after-the-fact rollback; it does not gate authority, and the invariants that must fail closed are about ambiguity and missing authority ([AGENTS.md](../../AGENTS.md)), not network reachability. Treating an availability failure as an authority failure would misrepresent what the mechanism does.

**The one fail-closed case is its mirror:** if verification at run start finds tampering or rollback against the last anchor, the run **halts**. A rewound or corrupted record layer is not a base to keep acting from.

### Verification procedure (beat 15)
`npm run verify:records`, a `tooling/` CLI over the gate-core verifier (combined artifact per LICENSE.md):

1. Resolve the latest anchored checkpoint from `latest.json`, cross-checked against the highest seq on disk, and confirm its commit is present on the remote via `git ls-remote`. `--local` skips only the remote step, for the test suite and offline runs, and says so in the report. With no prior anchor, step 4 is vacuous and the report states "no prior anchor".
2. Walk the checkpoint chain — contiguous seq, each `prev_checkpoint_digest` recomputed — and recompute each file's `composite_digest` from its own `streams` rows, so a hand-edited anchor fails here.
3. Recompute every local chain from entry 0, link by link: **in-line tampering** fails loudly at index k (beat 15a).
4. For each anchored head, require local `length ≥ anchored length` **and** that the local entry at index `anchored_length − 1` hashes to `head_hash` — the local chain must *extend* the anchor. Equality would be wrong: chains legitimately grow after a checkpoint. Failure is a **rollback alarm** naming world, stream, and divergence index (beat 15b: the truncated prefix is internally valid, and only the anchor exposes it).
5. Streams listed in the anchor must exist. A world appearing only after the anchor is unconstrained — and a world created *and* destroyed inside one window leaves no trace (§9).
6. The verification run appends its own access-log entry **after** reading, recording the lengths it read, so verification never mutates the chain it verifies and the access chain's self-reference is explicit rather than circular.

The pass state is reported as *"no divergence detected as of checkpoint 0007; un-anchored window 14 min / 23 entries"* — never a green check. Any alarm exits non-zero; the record viewer renders the same two facts.

### Receipts (beat 16)
The applicant's record receipt names the latest **pushed** checkpoint: `checkpoint_id`, `composite_digest`, the remote commit sha and repo URL, the world's action-chain length at anchor, and this action's entry index — so the receipt states plainly whether the action falls inside the anchored prefix or in the open window. Its own text says it is a local receipt: a true lodgment receipt needs the independent custody that is out of scope (§9).

## Consequences
- Rollback is detectable only back to the last successful push. §9's window stands, now carrying a number that the console and every receipt state out loud.
- The anchor is external to the record layer's storage — different medium, remote copy, force-push-protected `main` — but **not** external to the operator. It is not independent custody, and nothing in this repo may call it that.
- `records/` stays gitignored: only hashes leave the machine, never record content. That is the split-custody direction in miniature.
- Checkpoint timestamps come from the local clock. GitHub holds an independent record of when the push arrived; the POC does not retrieve it, so the anchoring *time* is self-asserted while the anchored *content* is remotely pinned.
- Git history grows by one commit per checkpoint — a couple per demo run at run-boundary cadence, which is why per-N flush is off by default.
- Anchoring adds a dependency on the network and on `git` being on PATH: degraded, never fatal, by the failure path above.
