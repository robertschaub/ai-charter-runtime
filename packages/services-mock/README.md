<!-- SPDX-License-Identifier: MIT -->
# services-mock

License: MIT (see ../../LICENSE.md).

The M3 services host obtains commit-verify itself, verifies the token and exact effect intent again,
and atomically commits a local idempotency ledger entry that is the mock effect. A same-process retry is
served from that ledger without re-execution; startup removes uncommitted temporary files, and probes
report the current boot id plus a persistent ledger id, so replacement storage cannot prove absence.
