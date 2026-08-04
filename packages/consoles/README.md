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
replay/sweep/reconciliation second, and the orchestrator last. The derived case credential remains a
headless synthetic-test seam and is never a browser credential. The approved browser path uses ADR-002's
one-time handoff and independent dynamic session.

The M4 authorization-origin governance console is now a dependency-free MIT asset set served by `gate-core`.
Its principal surface covers mandate grant/amend/revoke, routed escalation contracts and permitted general
dispositions, signed-card evidence, and action/access records; its applicant surface requests only the
server-side scoped extract. The shell has no inline or third-party executable content, keeps role tokens in
authorization-origin `localStorage`, and sends them only on same-origin bearer requests. A token-free dialogue
deep link loads its routed question and six-field contract on that origin and posts the answer there directly.
The orchestrator-origin case surface uses only its dynamic tab session: it displays signed-card evidence,
requires an in-tab evidence review before a model can be prepared, and polls a ruling-status mirror without
receiving the question, contract, answer, or role credential. Model interaction remains closed with an explicit
`501`. M5.3 supplies the authorization-owned output-admission boundary, but a later reviewed ingress slice must
make its use mandatory before any provider response can reach this browser surface.
M5.4, reviewed at `b247d5b`, adds a headless `ModelTurnCoordinator`: it accepts only a configured card/version/requested-id
tuple, fetches the current authorization-owned projection, invokes an injected adapter, and returns the raw result
to authorization for M5.3 admission. An admitted result is copied into a process-private quarantine that exposes
metadata and destruction only, with bounded entry and byte capacity. Its seal capability is module-private to the
coordinator; this is structural confinement, not cryptographic provenance or release approval. Withheld output or any
authority/provider/protocol/capacity failure adds no held-buffer entry and halts that lane for the coordinator
lifetime. Real-listener tests use a synthetic loopback provider. The coordinator has no HTTP, browser,
conversation-store, proposal, or runtime-process entry point, so this is containment plumbing rather than active
provider ingress or output release.
The M5.5 candidate makes the authorization-owned call reference mandatory around that flow. Before the adapter
can receive projected items, authorization durably records the exact turn, mandate, card, requested model, case,
and projection digest. Admission or a fixed failure report consumes that boot-bound reference once. Provider
timeout, outage, malformed response, tool calls, and post-response authority invalidation record bounded metadata
only; reporting failure never includes provider text or error detail. If reporting is interrupted, the durable
attempt stays indeterminate and the lane remains halted. The coordinator is still not mounted by the native
runtime or exposed to a browser, and the quarantine still has no output-release path.
The applicant surface can also submit an extract-bound factual correction directly to authorization. The
result is an append-only challenge plus a principal routing obligation and withdrawn-reliance marker, not a
remedy decision or a mutation of the earlier effect record.
