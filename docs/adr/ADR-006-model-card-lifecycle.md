<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-006 — Model-card lifecycle

**Status:** proposed (M1; cards authored at M3). **Spec:** §4 Model card, §5 find → check → use.

## Context
Cards are the v0 evidence registry: signed Markdown/JSON in git, bound to the pinned deployed version. Trust root is the **public verification key** in this repo; the private signing key stays local and gitignored. Fields are marked self-declared or probe-tested — never independently attested.

## Questions to answer
- Card schema (id + version, operator, endpoint, jurisdiction, openness class, capabilities, dated evidence status incl. what was **not** checked, known limits, declared data classes per role, card version + signature).
- Signing mechanics (key pair generation, signature format, verification tooling) and key rotation.
- Ordinary supersession → re-arms Authorize (pinned mandates flagged for principal re-confirmation) vs **security withdrawal → affected mandates fail closed immediately** — the state wiring for both.
- How mandate entries reference card versions (role-scoped: acting / screening / both).

## Decision
TBD at M1.
