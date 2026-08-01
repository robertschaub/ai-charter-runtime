<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Copilot / AI agent instructions — ai-charter-runtime

> **Canonical source:** [/AGENTS.md](../AGENTS.md). This is a short summary for inline completions; if rules diverge, follow AGENTS.md.

- **What this is.** A local-only, public proof of concept of the Our AI Charter runtime gates (Authorize → Submit → Verify → Commit → Rely). Node ≥ 20, TypeScript/ESM, minimal dependencies. No hosted service, no production data, no deployment machinery.
- **The spec is authoritative** and lives in the documentation repository: [runtime-gates-poc-spec.md](https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md). Trace code to a spec section; change the spec there rather than drifting here.
- **Gate invariants — never weaken them:** model output never authorizes; a screening signal has no code path to `allow` (Flag or force Escalate only); ambiguity or missing authority fails closed; the orchestrator reaches no authority-changing endpoint; every consequential effect requires a valid single-use commit token.
- **Honesty rules.** A maintainer sketch, not a certification artifact ([NOTICE](../NOTICE)). Do not generate green-light surfaces, trust APIs, "queryable certification", or any claim of independent assurance. Coverage is stated as exercised / partial / not assessed.
- **Licensing is per-directory** ([LICENSE.md](../LICENSE.md)): AGPL-3.0-only for `packages/gate-core/`, MIT for adapters, consoles, mocks, tooling and fixtures, CC BY 4.0 for documentation. Every new source file gets the matching `SPDX-License-Identifier` header; do not move code across the AGPL/MIT boundary without updating the map.
- **Secrets and data.** Keys live only in the gitignored `.env.local` — never in code, logs, fixtures, records, or probe output. Fixtures are synthetic by rule; no real personal data. Treat every commit to this public repo as permanent and worldwide.
- **Repository boundary.** Stay in this public repository and the linked public Charter/spec sources unless the maintainer explicitly names another path. Never import or disclose private-repository material, private paths, or unpublished operational context in a public artifact.
- **Records are part of the system under test.** Never hand-edit files under `records/`; tamper tests do that deliberately through the test harness.
- **Git safety.** Work directly on `main`; conventional commits (`type(scope): description`). Avoid destructive git (`reset --hard`, forced push, `clean -f`, `checkout -- .`) — prefer a revert commit or a targeted edit. The maintainer decides when to push.
- **Verification.** Normal checks are `npm run typecheck`, `npm test`, and, for model-card changes, `npm run cards:verify`. Do not run live probes, generate or rotate keys, or sign model cards without explicit maintainer approval.
- **Platform:** Windows, PowerShell-compatible commands.
