<!-- SPDX-License-Identifier: MIT -->
# adapters

License: MIT (see ../../LICENSE.md).

One fail-closed OpenAI-compatible adapter drives the PublicAI/Apertus and OpenAI lanes. Lane config
selects the M0-probed output-token parameter; every response keeps requested and provider-served model
ids separate. An outage or malformed response halts the lane—there is no silent endpoint or model
fallback. M5.4 exposes the adapter's configured lane and requested id as read-only identity so the
containment coordinator can reject a duplicated binding mismatch before disclosing a projection.
