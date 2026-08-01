<!-- SPDX-License-Identifier: MIT -->
# adapters

License: MIT (see ../../LICENSE.md).

One fail-closed OpenAI-compatible adapter drives the PublicAI/Apertus and OpenAI lanes. Lane config
selects the M0-probed output-token parameter; every response keeps requested and provider-served model
ids separate. An outage or malformed response halts the lane—there is no silent endpoint or model
fallback.
