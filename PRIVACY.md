<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# Privacy notice

> **Status: DRAFT FOR REVIEW — not yet effective.** This notice was checked against the repository on 17 September 2026. It is not legal advice or retained-counsel sign-off. Complete the provider-contract and retention review gates before adopting it.

Last updated: 17 September 2026 · Draft version: 0.3

## The important boundary

`ai-charter-runtime` is public, local-only proof-of-concept software. The project does **not** operate a hosted runtime service, collect production-user data, or receive the content that another person processes in their own local installation.

There are two separate privacy roles:

1. **Repository interactions.** The project maintainer processes public contributions and direct communications as described here.
2. **A local installation.** The person or organisation running the software decides what data to enter, which people may use it, whether to call an external model provider, and how long local records are kept. That operator is responsible for its own privacy notice, lawful basis, provider terms, security, retention, and rights process. This repository notice does not make the maintainer the controller of an independent operator's data.

## 1. Repository controller and contact

For repository maintenance and direct project communications, the controller is the FactHarbor association:

- Controller: **FactHarbor (Verein), c/o Robert Schaub, In Lederäcker 11, 8305 Dietlikon, Switzerland**
- Maintainer and contact person: **Robert Schaub**
- Privacy/security contact: [info@factharbor.ch](mailto:info@factharbor.ch)

GitHub separately controls account and platform data under its [General Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

## 2. Data the maintained project receives

The maintainer may receive:

- GitHub account information, issue or pull-request text, commits, review comments, timestamps, and other data you publish in the repository;
- email address, message, attachments, and correspondence metadata when you contact the project privately;
- security-report details you provide through email or GitHub private vulnerability reporting.

The maintainer does not receive local runtime records, console entries, tokens, `.env.local` values, prompts, or provider outputs merely because someone runs the software. The current project has no maintainer telemetry or analytics endpoint.

We use received data to maintain and secure the project, review contributions, answer requests, preserve attribution and decision history, investigate vulnerabilities, and comply with law. We do not sell it or use it for advertising.

## 3. Local processing by the software

The repository uses synthetic fixtures by rule, but a downstream operator could enter other data. Local components can create or hold:

- mandates, proposals, decisions, evidence references, audit and integrity records;
- names or role labels entered into the local consoles;
- authorization/session data in memory and browser storage: governance-role authorization credentials and the selected world ID are persisted in `localStorage` until removed or cleared, while case-handoff session tokens use tab-scoped `sessionStorage`;
- local logs, checkpoints, probe results, and configuration;
- model prompts and outputs when a provider call is explicitly enabled.

The orchestrator and authorization listeners enforce binding to `127.0.0.1` and reject another configured host. Local binding reduces network exposure; it is not a privacy guarantee. Operators must not use real personal data merely because the demonstration can technically accept text.

By default, checkpoint verification runs `git ls-remote` against the configured Git `origin` (normally the public GitHub repository). GitHub therefore receives the operator's IP address, repository/ref request and ordinary connection metadata even when no model provider is called. An operator who requires local-only checkpoint verification can set `CHECKPOINT_VERIFY_LOCAL=1`, subject to the documented integrity and operational trade-offs.

## 4. Optional external model calls

No provider call occurs from reading the repository or opening its documentation. Calls require an operator to configure credentials and intentionally run the relevant probe or runtime path.

The current configuration supports:

- **Public AI / Apertus** through an OpenAI-compatible API; and
- **OpenAI API**.

When called, the selected provider receives the request content, model and account/API metadata, and ordinary network metadata. Provider processing, location, retention, abuse monitoring, and training terms are governed by the operator's agreement and the provider's current notice. The operator must review those terms at the time of use and must not infer zero retention from this repository.

The maintainer does not receive or control provider-side data from an independent operator's API account.

## 5. Legal basis, retention, and public records

Repository processing follows the Swiss FADP principles. Where the GDPR applies, the likely grounds are legitimate interests in maintaining and securing an open-source research project (Article 6(1)(f)), steps or performance requested through a contribution relationship (Article 6(1)(b)), and legal obligations (Article 6(1)(c)). Consent is not inferred from merely viewing the repository.

- Public contributions and Git history are retained as a durable public record and may remain in forks, clones, releases, archives, or quotations.
- Private vulnerability records are retained while remediation and any necessary follow-up remain active, then minimized. **[REVIEW REQUIRED: approve a maximum routine period.]**
- Other project correspondence has a proposed two-year maximum after closure unless law, a dispute, or a documented security need requires longer. **[REVIEW REQUIRED: approve and implement.]**
- Local runtime data is controlled by the local operator. The repository sets no universal retention period for independent installations.

## 6. Your rights and security

Depending on the applicable law and circumstances, you may request access, correction, deletion, restriction, objection, or data release/portability by contacting [info@factharbor.ch](mailto:info@factharbor.ch). Identity or authority may need to be verified. Distributed public Git records cannot always be fully erased, but reasonable correction, redaction, or platform measures will be assessed.

You may complain to the [Swiss FDPIC](https://www.edoeb.admin.ch/en) or, where applicable, an EU/EEA supervisory authority.

Never publish secrets, tokens, private records, or unnecessary personal data in an issue, commit, fixture, log, or probe result. Follow [SECURITY.md](SECURITY.md) for private reporting. On a shared computer, clear stored governance credentials and the world selection after use; closing the browser does not by itself clear `localStorage`. Operators remain responsible for access control, encryption, backups, deletion, provider credentials, and incident response in their installation.

## 7. Review gates

Before adoption:

1. obtain the responsible FactHarbor association approval and set the effective date;
2. approve correspondence and vulnerability-report retention;
3. record GitHub's role and any required international-transfer safeguard, including default remote checkpoint verification;
4. add current Public AI and OpenAI privacy/DPA links only after the actual account terms are verified;
5. confirm operator guidance for persistent browser credentials and shared computers;
6. re-audit if hosted services, telemetry, non-synthetic fixtures, or additional providers are introduced.
