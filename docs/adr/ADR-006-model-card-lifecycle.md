<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# ADR-006 — Model-card lifecycle

**Status:** accepted (M1, 2026-08-01; cards authored at M3). **Spec:** §4 Model card, §5 find → check → use, §9 (cryptography limits; provider-side substitution), §7 beats 19–21.

**Amendment (M5.3 served-model admission, 2026-08-04):** the authorization-owned output boundary reloads the
approved signed card, applies this ADR's resolution policy to the provider-reported served id, and withholds a
mismatch before output may enter conversation state, a proposal, or a browser path. A benign unrecorded alias
snapshot remains admitted with `model_resolution_unrecorded`; the decision carries no action authority.

**Amendment (M5.5 durable call evidence, 2026-08-04):** authorization records the exact approved card/version,
requested model, mandate, turn, case, and projection digest before provider disclosure. The resulting call
reference is boot-bound, expires, and is consumed once by admission or a fixed failure report. Failure evidence
may state only timeout, unavailable, malformed response, tool-call refusal, or authorization invalidation plus
bounded disclosure/served-model metadata. An interrupted call remains indeterminate after recovery; it is neither
retried nor represented as successful.

**Amendment (M5.7 governed selection, reviewed at `442397a`, 2026-08-05):** the mandate HMAC binds an explicit
`default_acting_model` that exactly matches one approved acting entry. Authorization issues a short-lived
single-use check over the current signed card before accepting an initial selection or switch. The append-only
transition records requested target/card/key evidence; served identity is appended only later from confirmed
model-call evidence and can never select a substitute. A switch terminalizes an open prior-lane call with the
distinct authorization-owned `selection-invalidated` reason, `possible` disclosure, and no served id when
authorization has no response evidence. The caller-facing failure route cannot assert that reason. Adding its
durable schema/refinement is an explicit, exact-SHA-reviewed amendment to M5.5; it does not relax the
confirmed-disclosure requirement on existing post-response failure classes.

## Context
Cards are the v0 evidence registry: signed JSON in git, bound to the pinned deployed version, every field marked self-declared or probe-tested — never independently attested. The trust root is a public verification key in this repo; the private key stays local. The mandate governs disclosure; a card can narrow but never widen it.

## Decision

### 1. Files and keys
One card per wired model at `docs/cards/<slug>.json`. Slug = `<lane>-<requested id sanitized>`: lowercase, `[a-z0-9.-]` only, `/` → `-`, so `swiss-ai/apertus-v1.5-70b` → `publicai-apertus-v1.5-70b` and `gpt-5.5` → `openai-gpt-5.5`. Windows-safe by construction (no `/`, no `:`, no case collisions).

**Signing mechanics are ADR-007's, adopted unchanged** (that ADR was frozen the same day and owns key handling): Ed25519 via `node:crypto`, an **embedded** `signature` block `{"alg":"ed25519","key_id":"…","signature":"<base64>"}` covering the canonical card *minus that block* under the `model-card` domain tag — not a detached `.sig`; public verification keys in `docs/cards/signing-keys.json` (`{key_id, alg, public_key_b64, created, retired_at?, revoked_at?}`), private key at gitignored `keys/model-card-signing.ed25519.json`. The gitignore nuance is the reason for both paths: `keys/`, `*.key` and `*.pem` are all excluded, so neither the trust root nor any committed key material may live under those names. Tooling: `tooling/cards.mjs sign|verify`, no shell pipes.

This is the POC's only asymmetric key; mandate bindings, rulings, and the record chains stay HMAC/SHA-256 per §4/§9. All digests below are ADR-007 form: SHA-256, lowercase hex, unprefixed, domain-tagged.

### 2. Card schema

```json
{
  "schema": "ai-charter-runtime/model-card@1",
  "card_id": "openai-gpt-5.5",
  "card_version": 1,
  "valid_from": "2026-08-01",
  "attestation": "self-declared or probe-tested — never independently attested",
  "model": {
    "requested_id": "gpt-5.5",
    "pinning_mode": "alias",
    "resolution": {
      "lane": "openai", "policy": "alias-to-dated-snapshot",
      "snapshot_pattern": "^gpt-5\\.5-\\d{4}-\\d{2}-\\d{2}$",
      "observed_snapshots": [{ "id": "gpt-5.5-2026-04-23", "first_seen": "2026-08-01" }]
    }
  },
  "operator":       { "value": "OpenAI", "provenance": "self-declared", "date": "2026-08-01" },
  "endpoint":       { "value": "https://api.openai.com/v1", "provenance": "probe-tested", "date": "2026-08-01" },
  "jurisdiction":   { "value": "US", "provenance": "self-declared", "date": "2026-08-01" },
  "openness_class": { "value": "closed weights, hosted API", "provenance": "self-declared", "date": "2026-08-01" },
  "capabilities": {
    "tools":            { "value": true, "provenance": "probe-tested", "date": "2026-08-01" },
    "response_format":  { "value": ["json_schema", "json_object"], "provenance": "probe-tested", "date": "2026-08-01" },
    "token_parameter":  { "value": "max_completion_tokens", "provenance": "probe-tested", "date": "2026-08-01" }
  },
  "evidence_status": {
    "as_of": "2026-08-01", "source": "M0 probe",
    "not_checked": [
      { "item": "training data / weights provenance", "why": "not exposed by the API" },
      { "item": "sustained latency under varied prompts", "why": "M0 samples cache-suspect" }
    ]
  },
  "known_limits": [
    { "value": "reasoning tokens count against the completion cap", "provenance": "probe-tested", "date": "2026-08-01" }
  ],
  "declared_data_classes": {
    "acting":    ["conf:public", "conf:case", "purpose:grant-assessment"],
    "screening": ["conf:public", "purpose:grant-assessment"]
  },
  "signature": { "alg": "ed25519", "key_id": "card-2026-08-01", "signature": "MEUCIQ…" }
}
```

Every substantive field is a `{ value, provenance, date }` triple with `provenance ∈ { self-declared, probe-tested }`; there is deliberately no third value. `declared_data_classes` is **role-scoped** and draws on ADR-005's closed vocabulary. `card_version` is a monotonic integer — an evidence artifact has no meaningful major/minor distinction.

The Apertus card differs only in the pinning block: `pinning_mode: "exact"`, `policy: "exact-match-required"`, `requested_id: "swiss-ai/apertus-v1.5-70b"`, `not_checked` naming the untried `platform.publicai.co/v1` base URL, the absent `x-ratelimit-*` headers, and the router's cross-border/cross-model fallback disclosure behaviour (§9).

### 3. Alias vs snapshot pinning (M0 finding)
The card pins the **requested id** — the alias where the provider aliases, the exact id where it does not — and declares the lane's resolution behaviour. The served-id comparison beat 21 uses is a pure function of `(requested_id, resolution.policy, served_id)`:

| Lane | Policy | Accepted served ids |
|---|---|---|
| `publicai` | `exact-match-required` | `served == requested` only (M0 row 7: served equals requested, no alias indirection) |
| `openai` | `alias-to-dated-snapshot` | `served == requested`, or `served` matches `^<escaped requested>-\d{4}-\d{2}-\d{2}$` (M0 row 8: `gpt-5.5` → `gpt-5.5-2026-04-23`) |

Outcomes: `exact` → continue; `benign-resolution` → continue, recording the resolved snapshot per call (`gen_ai.request.model` / `gen_ai.response.model`); **anything else, including a missing or malformed served id → mismatch → beat-21 quarantine** (response never enters conversation state or a proposal; violation recorded including that disclosure to the substitute already occurred; lane halted, fail closed).

One addition: a benign snapshot **not yet listed** in `resolution.observed_snapshots` is recorded as `model_resolution_unrecorded` and raises a **Flag** — never a Stop, because the alias is what the principal approved and what the mandate pins. It marks the card's probe evidence stale and queues a re-probe plus a card-version bump. Silent provider-side rotation is drift (family 11), not defective authority.

M5.3 exercises this comparison on the strict output-admission boundary. The model text is hashed under its own
domain together with the current case/turn/projection and approval references; only that digest and the fixed
comparison metadata enter the access record. This is the first native quarantine seam, not provider ingress.

M5.4 adds the containment-only caller of that seam. The configured adapter's lane and requested id must match
the selected card binding before projection disclosure. A valid but substituted served id reaches M5.3 and is
durably recorded as withheld; the coordinator adds no quarantine entry and halts the lane. Timeout, malformed
provider evidence, null content, or tool calls also halt without fallback.
The quarantine exposes no sealing operation to importers: a module-private coordinator capability creates entries
only after admission and local binding verification. That is in-process structural confinement rather than
cryptographic proof of decision provenance, and a future release consumer must not treat quarantine presence as
safety clearance.

M5.5 supplies the previously deferred durable attempt/failure evidence without adding a provider entry point.
Authorization writes the open attempt before returning the projection and admits only through its exact single-use
reference. Terminal success records only admission metadata and digests; terminal failure uses the fixed classes
above. A provider timeout or network outage may leave disclosure as `possible`; response-derived failures require
`confirmed`, and tool-call refusal also binds the served id. An unfinished attempt remains explicitly
`indeterminate` across recovery and blocks a second attempt for that case/turn. Native runtime wiring, browser
ingress, conversation persistence, model switching, and output release remain deferred.

### 4. How mandates reference cards
Each approved-model entry is role-scoped and pins `card_version` **and** `card_digest`. The digest is taken over **exactly the signed bytes** — the canonical card minus its `signature` block, `model-card` domain — so digest equality means signed-content equality, and re-signing a card under a rotated key leaves the digest untouched:

```json
{ "card_id": "publicai-apertus-v1.5-70b", "card_version": 1,
  "card_digest": "9c1f…", "requested_id": "swiss-ai/apertus-v1.5-70b",
  "roles": ["acting", "screening"],
  "data_classes": { "acting": ["conf:public","conf:case","purpose:grant-assessment"],
                    "screening": ["conf:public","purpose:grant-assessment"] } }
```

The mandate also names one exact `default_acting_model` reference `{card_id, card_version, requested_id}`.
It must match an entry above with the `acting` role. This implements the specification's rule that the default
comes from the mandate, not array order or software configuration. The reference adds no second digest: the
matching approved entry already carries the HMAC-bound card digest and role permissions.

Effective disclosure = `mandate.data_classes[role] ∩ card.declared_data_classes[role]` (ADR-005 §5). Because the intersection is recomputed per projection, **a card update can only ever shrink effective disclosure** — a widened card field is inert unless the principal separately amends the mandate.

The pinned digest doubles as the supersession detector: no archive of old card files is needed, git history holds them, and comparing the pinned digest to the current file answers "is this mandate on a stale card?" in one hash.

### 5. Supersession, withdrawal, rotation

**Ordinary supersession** — new `card_version`, new digest, no revocation. At every Authorize touch the service compares pinned digest vs current file. On mismatch it sets `re_confirmation_required` on that mandate entry: the model keeps acting (reproducibility is preserved, the pinned evidence is what was approved), the governance console shows the flag, the find → check → use card view shows both the pinned version and that a newer one exists, and **the next Authorize-class transaction on that mandate cannot complete until the principal re-confirms or drops the entry** — starting a new case under the mandate counts as an Authorize-class transaction, so it too waits. That is "re-arms Authorize", concretely.

**Security withdrawal** — a signed `docs/cards/<slug>.revocation.json`, same embedded-signature convention:

```json
{ "card_id": "openai-gpt-5.5", "revokes_versions": "all",
  "reason_class": "security", "effective_at": "2026-08-14T10:00:00.000Z",
  "issued_by": "maintainer",
  "signature": { "alg": "ed25519", "key_id": "card-2026-08-01", "signature": "MEUCIQ…" } }
```

This needs one addition to ADR-007's domain-tag list: a `card-revocation` context, so a revocation digest can never be replayed as a card digest.

Checked at service start and at every Authorize and Submit touch. Affected mandate entries **suspend immediately** — Submit denies (fail closed), and every `issued` ruling bound to that acting-model entry is invalidated through ADR-001's eager sweep, with its lazy re-read at `commit-verify` as the backstop. The card digest and verifying `key_id` are already part of ADR-001's binding tuple, so a suspended card cannot survive as an in-flight authority. Un-suspension requires a principal re-authorization against a **new, unrevoked** card version.

**Fail-closed asymmetries, deliberate:** a card whose signature fails, whose `key_id` is unknown or marked `revoked_at`, or whose file is absent makes the model unusable — never warn-and-continue. A **revocation** whose signature fails still suspends, and raises an integrity alarm: an unverifiable withhold-signal can only withhold, never grant, so honouring it is the fail-closed reading. The cost is a local denial-of-service surface — anyone who can write to the working tree can park a lane — accepted at POC scale and named here rather than discovered later.

**Key rotation** follows ADR-007 and is transparent here: a new `key_id` is added, retired public keys stay in `signing-keys.json`, historical cards keep verifying, and the pinned `card_digest` is unaffected because the signature block is outside it. Rotation therefore does **not** re-arm Authorize. A key marked `revoked_at` is the opposite case: every card it signed stops verifying and is handled as a security withdrawal — affected mandates fail closed immediately. Each ruling records the `key_id` that verified the card at ruling time.

## Consequences
- Two cards at M3, authored straight from `m0-probe-memo.md`; both lanes' pinning behaviour is already observed, not assumed.
- Beat 21 becomes a table-driven unit test over `(requested, policy, served)` triples plus a mock provider; the live lanes only ever produce `exact` or `benign-resolution`.
- Card handling needs no git plumbing at runtime — digest comparison covers supersession, and the M3 tooling is one small `node:crypto` script.
- Depends on ADR-007 (frozen 2026-08-01) for canonicalization, digest form, and Ed25519 mechanics; the one thing it asks back is a `card-revocation` domain tag.
- Review rulings 2026-08-01: `re_confirmation_required` **does** gate starting a new case (an Authorize-class transaction, see §5); and the unverifiable-revocation-still-suspends rule gets **no demo override** — an override switch is a bypass path, exactly what complete mediation forbids, and the named local-DoS surface is the accepted cost.
