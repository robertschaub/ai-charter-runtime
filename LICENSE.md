# Licensing

This repository uses a multi-license model aligned with FactHarbor's, decided 2026-07-31 and recorded in the
[POC specification §1](https://robertschaub.github.io/our-ai-charter/wip/runtime-gates-poc-spec/).
Full license texts are in [`LICENSES/`](LICENSES/). Strategic choice, not legal advice.

## Per-directory license map

| Path | License | SPDX identifier | Why |
|---|---|---|---|
| `packages/gate-core/` | GNU AGPL v3.0 **only** | `AGPL-3.0-only` | The governance core (authorization service: policy evaluator, mandate store, counters/nonces, commit-verify, escalation state machine, record-integrity chains). Intended to require an operator who modifies the gate and offers it as a network service to publish the modified source — no black-box gates |
| `packages/adapters/` | MIT | `MIT` | Model adapters (OpenAI-compatible clients) — maximum reuse |
| `packages/consoles/` | MIT | `MIT` | Case console + governance console assets |
| `packages/services-mock/` | MIT | `MIT` | Mock connected services (registry, filing, notification) |
| `tooling/` | MIT | `MIT` | Probes, scripts, test harness |
| `fixtures/` | MIT | `MIT` | Synthetic demo data (no ODbL: not a curated database) |
| Root build/config files (`package.json`, `tsconfig*.json`, `vitest.config.ts`, lockfile) | MIT | `MIT` | Build scaffolding (JSON files carry no header; the map governs) |
| `docs/`, `README.md`, repo-meta Markdown (`AGENTS.md`, `CLAUDE.md`, `SECURITY.md`), `.github/` | CC BY 4.0 | `CC-BY-4.0` | Documentation and agent/contributor guidance. Deliberate deviation from FactHarbor's CC BY-SA so text moves freely in both directions between this repo and the CC BY 4.0 [our-ai-charter](https://github.com/robertschaub/our-ai-charter) repository |

## Rules

- **SPDX headers.** Every source file carries `SPDX-License-Identifier: <id>` matching this map. The map, not the header, is authoritative on conflict.
- **Where a header would not work.** JSON config (`package.json`, `.claude/settings.json`, `.codex/hooks.json`) has no comment syntax, and a comment in the GitHub templates (`.github/pull_request_template.md`, `.github/ISSUE_TEMPLATE/`) would be copied into every issue and pull-request body. Those files carry no header and are governed by the map alone.
- **Combined artifacts.** MIT-licensed console assets served *by* the AGPL authorization service remain separate MIT works; the service itself stays AGPL-3.0-only. Linking MIT code *into* `gate-core` is fine (MIT is AGPL-compatible); the combined work is distributed under AGPL-3.0-only.
- **Charter-derived text** (policy-file wording, field lists, quotations from Our AI Charter documents) keeps CC BY 4.0 attribution: *"Derived from [Our AI Charter](https://github.com/robertschaub/our-ai-charter) by Robert Schaub, CC BY 4.0."*
- **No ODbL** unless a genuine curated database ever emerges here.
