<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# cards

M3's two version-pinned model cards and their Ed25519 public trust root live here (schema and lifecycle
per ADR-006). The private key remains under the gitignored `keys/` directory. From the repository root,
run `npm run cards:verify` to build the verifier, validate both signatures, and print their content
digests.
