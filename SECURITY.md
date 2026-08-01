<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Security and public-repo safety

ai-charter-runtime is a public proof-of-concept repository. It runs **locally only** — no hosted
service, no production data, no real personal data (fixtures are synthetic by rule).

## Report privately

Do not open a public issue or pull request if you find:

- a leaked secret, token, or key (including a `.env.local` value that reached git);
- a way to bypass the gate — executing a consequential effect without a valid single-use commit
  token, forging a dialogue response or escalation disposition, or making a screening signal
  produce an `allow`;
- record-integrity problems (silent chain rewrite that verification misses, checkpoint bypass);
- a repository-configuration problem that could expose non-public material.

Contact the maintainer privately at [info@factharbor.ch](mailto:info@factharbor.ch), or use
GitHub private vulnerability reporting.

## Public issues

Public issues are for everything else: build problems, an unclear or unreachable spec beat, a
challenge to the declared limits, a licensing question. Specification changes belong in
[our-ai-charter](https://github.com/robertschaub/our-ai-charter/issues), not here.

## Keys

All API keys live in the gitignored `.env.local` and must never appear in code, fixtures,
records, logs, or probe results. If a key leaks: revoke it at the provider first, then purge.

## Local safeguards

The Claude Code and Codex hook files block the most dangerous destructive git commands. Coverage
outside the main session is not guaranteed — subagents and other tools may run unhooked. They are
a backstop, not a substitute for review.

## Scope honesty

Gate-bypass reports are very welcome — they are the point of the exercise — but note the
[declared limits](README.md#honest-limits--read-this-first): demo-grade authentication,
single-operator custody, and the documented commit-token window are known, recorded limits,
not undisclosed vulnerabilities.
