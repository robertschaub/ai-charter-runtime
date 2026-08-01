<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-002 — Authenticated inter-process interfaces

**Status:** proposed (M1). **Spec:** §3 (three processes, demo authentication), §5.

## Context
Per-role tokens (principal, case officer, applicant) and per-process credentials on every call; the orchestrator can reach no authority-changing endpoint. Demo-grade by declared limit — not an IAM design.

## Questions to answer
- Token format and custody (static demo tokens; storage; localhost binding; CORS between the two console origins).
- Per-process credentials on orchestrator→authorization-service, service→authorization-service calls.
- Which endpoints are authority-changing (mandate grant/amend/revoke, escalation dispositions, dialogue responses) and how they are unreachable from the orchestrator's credential.
- World-id keying on every stored object (single world in the demo; seam for the v1.1 public sandbox).

## Decision
TBD at M1.
