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
replay/sweep/reconciliation second, and the orchestrator last. Governance/case browser surfaces remain M4
work; in particular, the headless derived case credential has no browser handoff yet.
