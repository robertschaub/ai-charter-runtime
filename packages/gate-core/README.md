<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# gate-core

License: AGPL-3.0-only (see ../../LICENSE.md).

M1 layer (frozen ADRs 001–007): `canonicalize` (JCS subset, throwing), domain-tagged hashing, the
hash-chain writer/verifier with torn-tail semantics, the three-state HMAC keyring
(valid / invalid / unverifiable), the zod schema set under the integer-only regime, and the
alias-aware served-model comparator. The transactional core (WAL apply, policy evaluator,
escalation machine) lands at M2.
