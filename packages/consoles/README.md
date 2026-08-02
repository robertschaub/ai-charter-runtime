<!-- SPDX-License-Identifier: MIT -->
# consoles

License: MIT (see ../../LICENSE.md).

M3 contains the deterministic orchestrator loop used by the dual-model vertical-slice tests. It parses
the acting model's proposal, supplies server-owned model identity fields, submits the frozen proposal,
and exercises the Commit ruling through effect and receipt; it never receives a commit token. Submit,
Verify, and Rely are not claimed as part of this one M3 slice. The three-process boundary, the remaining
gate paths, and the browser consoles remain M4–M5 work; until then the keyring is necessarily co-located
inside this test harness rather than isolated by process credentials.

The first headless M4 test now exercises beat 3 through the authenticated adapter: Verify escalation,
direct case-officer narrowing, revised Verify and Commit rulings, commitment, effect, and outcome. It is
still an in-process test; process wrappers and the governance/case browser surfaces remain M4 work.
