<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Copilot / AI agent instructions — ai-charter-runtime

> **Canonical source:** [/AGENTS.md](../AGENTS.md). This is a short summary for inline completions; if rules diverge, follow AGENTS.md.

- **What this is.** A local-only, public proof of concept of the Our AI Charter runtime gates and technical preparation for Evidence-Gated Agents (Authorize → Submit → Verify → Commit → Rely). Node ≥ 20, TypeScript/ESM, minimal dependencies. No hosted service, no production data, no deployment machinery.
- **The spec is authoritative** and lives beside the code: [runtime-gates-poc-spec.md](../docs/spec/runtime-gates-poc-spec.md). Trace code to a spec section; changes require the root approval/review rules and update the governing specification or ADR here. For assigned EGA-related work, follow the root EGA-preparation rule.
- **Gate invariants — never weaken them:** model output never authorizes; a screening signal has no code path to `allow` (Flag or force Escalate only); ambiguity or missing authority fails closed; the current orchestrator boundary in `AGENTS.md` is preserved; every consequential effect requires a valid single-use commit token.
- **Honesty rules.** A maintainer sketch, not a certification artifact ([NOTICE](../NOTICE)). Do not generate green-light surfaces, trust APIs, "queryable certification", or any claim of independent assurance. Coverage is stated as exercised / partial / not assessed.
- **Licensing follows material type and path assignments** ([Licensing guide](../LICENSING.md)): AGPL-3.0-only for original software and CC BY-SA 4.0 for documentation. Every new source file gets the matching `SPDX-License-Identifier` header; do not move code across the software/documentation boundary without updating the map.
- **Secrets and data.** Keys live only in the gitignored `.env.local` — never in code, logs, fixtures, records, or probe output. Fixtures are synthetic by rule; no real personal data. Treat every commit to this public repo as permanent and worldwide.
- **Repository boundary.** Use this public repository, its linked public sources and only the task-authorized repositories and read/write scope under root AGENTS.md. Never import or disclose private-repository material, private paths, or unpublished operational context in a public artifact.
- **Records are part of the system under test.** Never hand-edit files under `records/`; tamper tests do that deliberately through the test harness.
- **Git safety.** Follow root AGENTS.md for solo/main and concurrent worktree ownership; the integrator owns shared records and integration, restricted writers return edits/evidence. Use conventional commits only within current authority. Avoid destructive git (`reset --hard`, forced push, `clean -f`, `checkout -- .`) — prefer a revert commit or a targeted edit. The maintainer decides when to push.
- **Verification.** Normal checks are `npm run typecheck`, `npm test`, and, for model-card changes, `npm run cards:verify`. Do not run live probes, generate or rotate keys, or sign model cards without explicit maintainer approval.
- **Platform:** Windows, PowerShell-compatible commands.

Read applicable nested instructions before target work. Use focused checks within assigned state; strict read-only review uses captured evidence and creates no output. Client metadata does not establish installed control coverage. Existing task authority persists; preparation/review does not grant live/provider-spending or external actions.
