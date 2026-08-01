<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# M0 probe — decision memo

**Status:** open — fill from `docs/m0-probe-results.json` after running `node tooling/probe.mjs --lane all`.

The spec ([§8](https://robertschaub.github.io/our-ai-charter/wip/runtime-gates-poc-spec/)) flags these discrepancies and unknowns for M0 to settle. Record the observed answer and the decision; the spec's evidence note documented `api.publicai.co` + portal keys + Free 100 req/min (2026-07-27), while LiteLLM's provider doc gave `platform.publicai.co/v1` and the older HF launch route was described at 20 req/min.

| # | Question | Observed (date) | Decision |
|---|---|---|---|
| 1 | PublicAI working base URL (`api.publicai.co/v1` vs `platform.publicai.co/v1`) | | |
| 2 | Exact hosted Apertus model id(s) from `/models` (`swiss-ai/apertus-v1.5-70b` vs router-style names) | | |
| 3 | Hosted `tools` (function calling) support on the Apertus lane | | |
| 4 | Hosted `response_format` support (`json_schema` / `json_object`) — else prompted-JSON fallback | | |
| 5 | Effective rate limits + informative headers (tier, `Inference-Id`, `x-ratelimit-*`) | | |
| 6 | Latency envelope (p50/p95 of small completions) | | |
| 7 | Served-model reporting (response `model` field present and plausible?) | | |
| 8 | OpenAI lane sanity (`gpt-5.5` reachable; `response_format`; `tools`) — settles the assumed-GPT open point | | |

**Fallback stance (pre-decided in the spec):** prompted-JSON with schema validation + one retry wherever native structured output is absent; fail closed on endpoint absence.
