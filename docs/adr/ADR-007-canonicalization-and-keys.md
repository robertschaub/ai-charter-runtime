<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-007 — Canonical JSON and key handling

**Status:** accepted (M1, 2026-08-01). **Spec:** §4 (frozen proposals, HMAC binding), §9 (minimal cryptography).

**Amendment (M3 review, 2026-08-01):** `effect-intent` is a separate digest domain; an exact service request must not reuse the frozen-proposal context.

**Amendment (M5.3 output admission, 2026-08-04):** `conversation-projection` binds the exact authorization-owned
provider projection and `model-output` binds one bounded result to its case, turn, approval, requested/served
ids, and projection digest. Neither digest is a ruling or action authority.

**Amendment (M5.10 conversation transport, 2026-08-07):** `conversation-ingress-profile` binds the fixed
authorization-owned classification profile used for case-officer message ingress. `conversation-item-content`
binds one exact durable conversation item's case, item id, and text. Message-ingress and model-output-ingress
metadata use the item digest without copying raw text into access/action records or release metadata.

## Context
Frozen proposals, mandate bindings, rulings, record entries, and checkpoints (ADR-003) are hashed over canonical JSON; every ruling carries a policy content digest and an evaluator build id, because a version label alone cannot prove which rules ran. One byte-level convention has to hold across all of them, and the cryptography stays deliberately minimal — hash chain plus HMAC, with a single asymmetric exception for model cards.

## Decision

### Canonicalization — a JCS-compatible subset, ~50 lines, no dependency
`canonicalize(value): string` in `packages/gate-core/` (AGPL, SPDX header) implements the RFC 8785 (JCS) rules for the value subset this POC uses:

- **objects** — keys sorted with JavaScript's default string sort, i.e. UTF-16 code-unit order, which is exactly what JCS specifies; no whitespace; arrays keep their given order;
- **strings** — `JSON.stringify` of the string (Node ≥ 20's well-formed stringify already emits JCS's shortest-escape form, lowercase `\uXXXX`, for valid Unicode);
- **numbers** — safe integers only, serialized with `String(n)`;
- **`true` / `false` / `null`** literally; output is UTF-8, no BOM.

**The subset is enforced by throwing:** non-integer numbers, `NaN`, `±Infinity`, unsafe integers, `BigInt`, `undefined`, `Date`, class instances, `Map`/`Set`, and lone surrogates are rejected. A value that cannot be canonicalized cannot be hashed, so it can be neither ruled on nor recorded — the gate treats it as ambiguity and fails closed.

Schemas keep the subset true: amounts and ceilings are **integers in minor units** (Rappen), timestamps are RFC 3339 UTC strings with millisecond precision (`2026-08-01T09:32:14.512Z`), and screening confidence is `confidence_pct`, an integer 0–100. That removes floats from the data contracts entirely, so JCS's number-formatting edge cases never arise.

**The claim we make** is JCS-compatible *for this subset*, asserted as a tested property against committed vectors in `fixtures/jcs/` (the RFC 8785 examples and reference-suite cases that fall inside the subset) plus rejection tests for everything outside it. Neither the code nor the README claims a general RFC 8785 implementation.

### Hashes, MACs, encodings — one convention
- **SHA-256 everywhere** from `node:crypto`; digests are **lowercase hex**, unprefixed, over the UTF-8 bytes of the canonical string. Keys and signatures are **base64**; ids are lowercase ASCII; times are RFC 3339 UTC as above.
- **Domain separation.** Every digest and MAC is taken over `"ai-charter-runtime/v1/<context>\n"` followed by the canonical bytes, `<context>` ∈ {`proposal`, `effect-intent`, `record-entry`, `access-entry`, `wal-entry`, `mandate-binding`, `commit-token`, `policy-set`, `evaluator-build`, `checkpoint`, `checkpoint-composite`, `model-card`, `card-revocation`, `conversation-projection`, `conversation-ingress-profile`, `conversation-item-content`, `model-output`, `system-use-decision`, `system-use-configuration`}. A digest is therefore never valid in a context other than the one it was computed for. The tag frames the hash input; it is not part of the canonical JSON.
- **Audience-credential derivation** is the one non-artifact framing family:
  `SHA-256(UTF-8("ai-charter-runtime/v1/credential-audience/<audience>\n" + lowercase_source_hex))`.
  The source is high-entropy credential text, not canonical JSON or decoded raw bytes; the output is a
  lowercase 64-character hex bearer credential. It is never stored or accepted outside the named audience.
- **Chain rule** (all three streams of ADR-003): `entry_hash = H(domain ‖ canonical(entry without entry_hash))`, the entry including its `prev_hash`; the first entry's `prev_hash` is 64 zeros.
- Digest and MAC comparisons use `crypto.timingSafeEqual` on equal-length buffers.
- Artifacts verified on their own — mandate binding, checkpoint, card signature — name their `alg` explicitly. Chain entries do not: the chain algorithm is a repo constant, restated in every checkpoint.

### HMAC keys — lifecycle
- **HMAC-SHA256**, 32 bytes from `crypto.randomBytes`. The active key lives in gitignored `.env.local` as `GATE_HMAC_KEY` (hex) with `GATE_HMAC_KEY_ID` (e.g. `hmac-2026-08-01`); retired keys live in `keys/hmac-keyring.json`, already gitignored by the existing `keys/` rule. Nothing else holds key material — records, logs, and fixtures carry the **key id only**.
- **Used for** the §4 mandate binding — `{"alg":"hmac-sha256","key_id":"…","value":"<base64>"}` over the canonical mandate minus that field, so every amendment (a new version) is re-bound — and for the single-use bearer bookkeeping ADR-001/ADR-002 define (commit tokens), through this same registry under their own domain tags. Nothing else is MAC'd.
- **Rotation is a new key id, never a re-signing pass.** `tooling/keys.mjs rotate` moves the outgoing pair into the keyring and writes the new pair into `.env.local`. Older bindings stay verifiable because the verifier resolves `key_id` against {active} ∪ keyring.
- **Unknown key id ≠ bad MAC.** The verifier reports `unverifiable (unknown key id)` distinctly from `invalid (mismatch)`, the record viewer shows which, and an unverifiable binding is treated as defective authority — deny.
- **Honest limit.** HMAC is symmetric: it shows a binding was produced by a holder of the key, which is the authorization service, i.e. the same operator who runs everything else. That is tamper-evidence inside one operator's system, not non-repudiation (§9). Record-chain integrity does not depend on it — the chains are keyless SHA-256, so losing the keyring makes historical *mandate bindings* unverifiable without touching record verifiability.

### Model-card signatures — the one asymmetric need
- **Ed25519** via `node:crypto` (`generateKeyPairSync('ed25519')`, `sign(null, …)` / `verify(null, …)`). The card key pair is **separate from the HMAC keys** and used for nothing else. No PKI, no CA, no chain of trust: the trust root is one committed public key, consistent with §9's minimal cryptography.
- Public verification keys ship in `docs/cards/signing-keys.json` as `{key_id, alg, public_key_b64 (SPKI DER), created, retired_at?, revoked_at?}`. Deliberately **not** a `.pem`: the repo's `.gitignore` excludes `*.pem` and `*.key`, and a committed public key must not depend on an ignore-rule exception.
- The private key is `keys/model-card-signing.ed25519.json` (gitignored), never in `.env.local` and never printed.
- The signature covers the canonical card minus its `signature` block, domain `model-card`; the block is `{"alg":"ed25519","key_id":"…","signature":"<base64>"}`.
- **Rotation** adds a new key id and keeps retired public keys, so historical card versions still verify. A **compromised** key is marked `revoked_at`: cards signed by it stop verifying and are handled as a security withdrawal — affected mandates fail closed immediately (ADR-006).

### Policy content digest and evaluator build id
Both use one **file-set digest** construction: for each file `{path, sha256}`, with POSIX relative paths and bytes normalized (UTF-8 BOM stripped, CRLF → LF) so a Windows checkout hashes identically whatever git's autocrlf does; the list sorted by path under the same UTF-16 rule; the digest taken over the canonicalized list under its own domain tag.

- **`policy_content_digest`** — over *every* file under the policy-set root `packages/gate-core/policy/` (settled here), recursively, with no extension filter, because a filter is a place for a rule to hide. Content only: the declared `policy_version` label is **not** an input, so relabelled-but-identical rules appear as a label change against an unchanged digest — which is why both are recorded. Computed at service start and on reload; a mid-run change invalidates live rulings (§4 invalidation rule) and fails closed.
- **`evaluator_build_id`** = `gate-core@<package version>+<first 16 hex of the file-set digest of packages/gate-core/src/>`, no exclusions. A test-only edit therefore bumps the id — accepted noise in exchange for no exclusion rule to argue about, with the corollary that **no test may assert a literal build id**. The full digest is written once per run into the WAL run header so the short form resolves.

```json
{
  "policy_version": "2026-08-01.3",
  "policy_content_digest": "b7e2…",
  "evaluator_build_id": "gate-core@0.0.1+9f3c1a2b7d4e5f60"
}
```

- **Honest limit.** Both are self-computed change detectors: they prove which files the evaluator *reports* having run, not that those are the files that ran. Attestation is out of scope (§9).

## Consequences
- One canonicalizer, one hash, one encoding table across chains, checkpoints, bindings, and cards; ADR-003 inherits all of it and adds only its own domain tags.
- Schemas must enforce the value subset (zod `.int()`, minor units, `confidence_pct`). A float reaching a schema is a build-time bug; at runtime it fails closed rather than hashing something ambiguous.
- Key loss degrades gracefully: chains keep verifying, mandate bindings become *unverifiable* rather than invalid, and the viewer says which. The gitignored keyring is therefore a real asset — the maintainer backs it up outside git; the repo cannot.
- The crypto surface stays SHA-256, HMAC-SHA256, and Ed25519, all from `node:crypto`. No crypto dependency enters the tree, and the JCS subset costs ~50 lines plus vectors instead of a package.
- Deliberately absent: encryption at rest, threshold custody, timestamping authorities, non-repudiation. §9's limits stand exactly as written.
