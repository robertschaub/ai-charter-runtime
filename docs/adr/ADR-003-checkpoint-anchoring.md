<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-003 — Composite-head checkpoint anchoring

**Status:** proposed (M1). **Spec:** §3 record layer, §9 (cryptography limits).

## Context
Local streams cannot detect their own tail rollback. A composite head digest — write-ahead state + action chain + access-log chain — is checkpointed to the public repo (committed **and pushed**, i.e. remotely acknowledged) at run boundaries.

## Questions to answer
- Digest construction (which stream heads, in which canonical order) and the checkpoint file format in-repo.
- Cadence (run boundaries; optionally per-N-entries) and the push/acknowledge failure path (fail closed vs record-and-warn).
- Verification procedure: how beat 15's rollback test checks a working tree against the anchored checkpoint.
- Per-world chains: one composite digest per world or one global digest over all worlds.

## Decision
TBD at M1.
