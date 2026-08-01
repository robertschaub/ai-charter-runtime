<!-- SPDX-License-Identifier: MIT -->
# consoles

License: MIT (see ../../LICENSE.md).

M3 contains the deterministic orchestrator loop used by the dual-model vertical-slice tests. It parses
the acting model's proposal, supplies server-owned model identity fields, submits the frozen proposal,
and hands an allowed ruling to the services host; it never receives a commit token. The three HTTP
process wrappers and browser consoles remain M4 work.
