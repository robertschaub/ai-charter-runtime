<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Claude Code instructions — ai-charter-runtime

**Primary rules live in [AGENTS.md](AGENTS.md) — read it.** This file adds Claude-Code-specific notes; on divergence, AGENTS.md wins.

- The **build authority** is the spec in the documentation repo: [runtime-gates-poc-spec.md](https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md). Spec changes happen there, never by drifting here.
- A **PreToolUse hook** in [.claude/settings.json](.claude/settings.json) blocks destructive git (`reset --hard`, forced push, `clean -f`, `checkout -- .`), mirrored for Codex in [.codex/hooks.json](.codex/hooks.json). Do not rely on it outside the main session — never delegate destructive git to a subagent.
- No committed permission `defaultMode` — your session's own mode applies, so a prompt is still the second guard behind the hook. (This follows `our-ai-charter`; FactHarbor commits `bypassPermissions`, where the hook is the *only* guard. Maintainer's call if that ever changes here.) The committed allowlist is read-only: `git status/log/diff/show` and `node --check`.
- **Licensing is per-directory** ([LICENSE.md](LICENSE.md)); every new source file needs the matching `SPDX-License-Identifier` header.
- Keys live only in gitignored `.env.local`. The probe and all tooling must never print or persist them.
- Windows / PowerShell environment; Node ≥ 20; LF line endings enforced via [.gitattributes](.gitattributes).
