## Summary

What changed, and why?

## Checklist

- [ ] Traceable to the [spec](https://github.com/robertschaub/our-ai-charter/blob/main/docs/wip/runtime-gates-poc-spec.md) (section/beat named in the description); spec divergences were changed in the spec first, not here.
- [ ] Gate invariants preserved: model output never authorizes; signals have no path to `allow`; ambiguity or missing authority fails closed; the orchestrator reaches no authority-changing endpoint; every consequential effect needs a valid single-use commit token.
- [ ] License map respected: files carry the correct `SPDX-License-Identifier`; nothing moved across the AGPL/MIT boundary without updating [LICENSE.md](../LICENSE.md).
- [ ] No secrets, no real personal data, no hand-edited `records/`.
- [ ] Honest-limits claims (README/NOTICE) still accurate after this change.
