<!-- SPDX-License-Identifier: MIT -->
# consoles

License: MIT (see ../../LICENSE.md).

M3 contains the deterministic orchestrator loop used by the dual-model vertical-slice tests. It parses
the acting model's proposal, supplies server-owned model identity fields, submits the frozen proposal,
and exercises the Commit ruling through effect and receipt; it never receives a commit token. Submit,
Verify, and Rely are not claimed as part of this one M3 slice. That legacy fixture is intentionally
in-process; the native boundary described below is the separate headless M4 transport path.

The first headless M4 test exercises beat 3 through the authenticated adapter: Verify escalation,
direct case-officer narrowing, orchestrator continuation through Authorize, Submit, and Verify, then a
fresh Commit ruling, commitment, effect, and outcome.

The native M4 transport test starts three OS processes over loopback HTTP. The orchestrator submits a
frozen proposal, the authorization process alone rules, and the services process obtains and verifies its
own commit token before effect. Audience-scoped child environments prevent the orchestrator from receiving
human authorization credentials and prevent the services host from replaying its orchestrator-facing
credential at the authorization service. The supervisor starts services recovery first, authorization
replay/sweep/reconciliation second, and the orchestrator last. Case-browser surfaces remain M4 work; the
derived case credential remains a headless synthetic-test seam and is never a browser credential. The
approved browser path instead uses ADR-002's one-time handoff and independent dynamic session.

The M4 authorization-origin governance console is now a dependency-free MIT asset set served by `gate-core`.
Its principal surface covers mandate grant/amend/revoke, routed escalation contracts and permitted general
dispositions, signed-card evidence, and action/access records; its applicant surface requests only the
server-side scoped extract. The shell has no inline or third-party executable content, keeps role tokens in
authorization-origin `localStorage`, and sends them only on same-origin bearer requests. The case console and
credential-bearing dialogue response control remain unimplemented; the next bounded slice is the approved
handoff/session protocol, followed by those browser surfaces.
