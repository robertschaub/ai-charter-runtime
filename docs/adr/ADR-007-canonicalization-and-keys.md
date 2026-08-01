<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-007 — Canonical JSON and key handling

**Status:** proposed (M1). **Spec:** §4 (frozen proposals, HMAC binding), §9 (minimal cryptography).

## Context
Frozen proposals, mandate bindings, rulings, and record entries are hashed/HMAC'd over canonical JSON; policy content digests and evaluator build ids enter every ruling.

## Questions to answer
- Canonicalization algorithm (candidate: RFC 8785 JCS) and its Node implementation (library vs ~50-line subset for the POC's value types).
- HMAC key lifecycle: generation, storage (gitignored), rotation, and what a rotation does to verifiability of older chains.
- Policy content digest: over the canonicalized rule file(s); evaluator build id source (package version + content hash).
- Hash algorithm choices and encoding conventions across chains, checkpoints, and signatures (one convention everywhere).

## Decision
TBD at M1.
