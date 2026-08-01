<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-004 — Dialogue-response channel (browser → authorization service)

**Status:** proposed (M1). **Spec:** §5 (dialogue triggers; empathy layer).

## Context
Dialogue triggers are escalations routed to the conversation partner. The response control is served from the authorization service's own origin (embedded in or linked from the case console); the orchestrator neither serves the credential-bearing control nor carries the answer.

## Questions to answer
- Embed vs link (iframe from the governance-console origin vs deep link); CSRF protection; session/token custody on that origin only.
- Payload: escalation id (single-use), disposition (confirm / correct / narrow / permit), cited evidence reference where standing requires it.
- Enforcement that "confirm" of third-party facts requires evidence or routing — refused otherwise.
- How the case console learns the outcome (poll/SSE from the orchestrator's non-authoritative view).

## Decision
TBD at M1.
