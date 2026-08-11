<!-- SPDX-License-Identifier: MIT -->
# fixtures

Synthetic grant-scenario data and pinned test fixtures (MIT). Never real personal data.

`demo/conversation.json` is the synthetic authorization-owned, case-scoped four-store seed used by the
native-process M5 tests. It is input data, not a generated or append-only runtime record.

`demo/screening-proposal.json` and `demo/screening-injection-proposal.json` are frozen synthetic proposals.
The latter contains the scripted applicant-document injection from specification beat 5.
`demo/screening.json` binds deterministic offline screening results to each exact proposal hash and gate. A
changed proposal has no fixture match and therefore cannot be treated as screened. These files exercise signal
plumbing only; none represents a provider call, live prompt-injection detection, or provider evidence.

`demo/system-use-decision.json` is the authorization-owned synthetic decision fixture for the bounded public
grant POC. Its digest binds the exact policy, model-card roles/digests, data classes, jurisdiction, validity,
conditions, evidence metadata, and accountability gaps. It is not an assurance, certification, legal approval,
conformity result, or action authorization, and it contains no real personal data.
