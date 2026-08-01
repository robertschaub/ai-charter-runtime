# Agent rules — ai-charter-runtime

- **The spec is authoritative.** Build to [runtime-gates-poc-spec.md](https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md) (mirrored on the [site](https://robertschaub.github.io/our-ai-charter/wip/runtime-gates-poc-spec/)); on divergence the spec and its linked Charter sources win. Spec changes happen in `our-ai-charter`, never by silently drifting here.
- **Licensing is per-directory** — [LICENSE.md](LICENSE.md) is the map; every source file carries a matching `SPDX-License-Identifier` header. Do not move code across the AGPL/MIT boundary without updating the map.
- **Honesty rules:** this is a maintainer sketch, not a certification artifact ([NOTICE](NOTICE)). No green-light surfaces, no "queryable certification", no claims of independent assurance. Test-family coverage is marked exercised / partial / not assessed — never implied.
- **Secrets:** keys live only in gitignored `.env.local`; never in code, logs, fixtures, or records.
- **Git:** work directly on `main`; the maintainer decides when to push. Conventional commits (`type(scope): description`).
- **Records are part of the system under test**: never hand-edit files under `records/`; tamper tests do it deliberately via the test harness.
- The gate invariants are non-negotiable in code review: model output never authorizes; a signal has no code path to allow; ambiguity or missing authority fails closed; the orchestrator reaches no authority-changing endpoint; every consequential effect requires a valid single-use commit token.
