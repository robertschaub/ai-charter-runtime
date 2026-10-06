<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->
# Runtime documentation

Start with the [project overview and offline setup](../README.md). Use the paths below to explore the behavior, inspect its evidence, or work on the implementation.

| I want to… | Read |
|---|---|
| Understand the worked example | [Scripted grant-scenario beats](m6/acceptance.md#scripted-beats) |
| See what has and has not been exercised | [M6.3 acceptance ledger](m6/acceptance.md), including the seven criteria and thirteen test families |
| Understand the implementation contract | [Runtime specification](spec/runtime-gates-poc-spec.md) and [system-use decision record](spec/system-use-decision-record.md) |
| Follow the architecture and protocols | [Architecture decision records](adr/) |
| Find current status, reviewed revisions, and remaining work | [Implementation plan](implementation-plan.md) |
| Inspect earlier milestone evidence | [M4 acceptance](m4-acceptance.md) and [M5 acceptance](m5-acceptance.md) |
| Understand the browser and process boundaries | [Console documentation](../packages/consoles/README.md) |
| Inspect model evidence | [Signed model cards](cards/README.md) and the historical [M0 probe memo](m0-probe-memo.md) |

The specification and its linked Charter sources govern on divergence. Acceptance records describe bounded evidence; they do not establish independent assurance or certification. Live M6.4 capture remains pending.

## Reference directories

Documentation is CC BY-SA 4.0 (see [Licensing guide](../LICENSING.md)). Text derived from
[Our AI Charter](https://github.com/robertschaub/our-ai-charter) documents keeps CC BY-SA 4.0
attribution to Robert Schaub / Our AI Charter.

- `spec/` — the current implementation specification and its system-use companion.
- `adr/` — architecture decision records: the protocol detail the
  [spec](spec/runtime-gates-poc-spec.md) delegates here, including the
  M6 evidence/capture boundary in [ADR-016](adr/ADR-016-m6-evidence-capture.md), the reviewed M6.2 native
  commitment continuation in [ADR-018](adr/ADR-018-native-commitment-continuation.md), and the reviewed M6.3
  offline conformance/artifact definition in
  [ADR-019](adr/ADR-019-m6-offline-conformance-and-capture-artifacts.md). The M6.4 live-capture and publication
  candidate is [ADR-020](adr/ADR-020-m6-live-capture-and-publication.md); its definition remains review-pending
  and authorizes no live operation.
- `cards/` — signed, version-pinned model cards (M3): the v0 evidence registry.
- `m0-probe-memo.md` — the M0 endpoint decisions, filled from probe results.
