<!-- SPDX-License-Identifier: MIT -->
# fixtures

Synthetic grant-scenario data and pinned test fixtures (MIT). Never real personal data.

`demo/conversation.json` is the synthetic authorization-owned, case-scoped four-store seed used by the
native-process M5 tests. It is input data, not a generated or append-only runtime record.

`demo/screening-proposal.json` is one frozen synthetic proposal. `demo/screening.json` binds deterministic
offline screening results to that exact proposal hash and gate. A changed proposal has no fixture match and
therefore cannot be treated as screened. Neither file represents a provider call or provider evidence.
