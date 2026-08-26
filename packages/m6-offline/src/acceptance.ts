// SPDX-License-Identifier: MIT
import type { CaseCatalog } from './types.js';

const BASELINE = [
  ['1', 'Distinguishable stages', 'exercised', 'All executor results expose ordered gate, commitment, effect, and containment projections; illegal transitions are adversarially refused.'],
  ['2', 'Structured proposal', 'exercised', 'Beats 6-8 freeze exact proposals; source-admissibility markers remain deferred to M6.5.'],
  ['3', 'Provable authority', 'partial', 'Mandate scope, expiry, revocation, ordering, and approved cards are exercised; authority basis remains deferred to M6.5.'],
  ['4', 'Independent admissibility and complete mediation', 'exercised', 'Authorization is outside the model and all named bypasses fail closed.'],
  ['5', 'Human-intervention contract', 'exercised', 'Escalation contract, role, timeout, disposition, race, and narrowing paths are exercised with synthetic evidence.'],
  ['6', 'Verification at commitment', 'exercised', 'The executing service re-verifies exact intent, expiry, revocation, replay, and above-envelope requests.'],
  ['7', 'Action-and-effect record', 'partial', 'Commitment/effect, challenge, scoped extract, and local receipt paths are exercised; independent custody and remedy decision remain absent.'],
] as const;

const FAMILIES = [
  ['1', 'Activation and bystander notice', 'not_applicable', 'Ambient-device activation is outside this POC.'],
  ['2', 'Data boundaries', 'partial', 'Disclosure projection is exercised; retention and deletion propagation are not assessed.'],
  ['3', 'Inference quality', 'exercised', 'Conflict and one fixture-pinned unconfirmed-inference path are exercised; stale memory remains untested.'],
  ['4', 'Recommendation integrity', 'not_assessed', 'Commercial influence is false in the synthetic scenario.'],
  ['5', 'Authorization', 'exercised', 'Scope, expiry, replay, revocation, and privilege broadening are exercised.'],
  ['6', 'Complete mediation', 'exercised', 'Entry, native Commit, service, token, and credential boundaries are exercised.'],
  ['7', 'Prompt injection', 'partial', 'One fixture-pinned injection vector proves signal-to-Stop plumbing, not detector quality.'],
  ['8', 'Interrupt propagation', 'partial', 'Cancellation and fail-closed interruption are exercised; wider propagation is not assessed.'],
  ['9', 'Reversal', 'partial', 'Pre-commit cancel is exercised; post-commit reversal and compensation are absent.'],
  ['10', 'Records', 'partial', 'Tamper, rollback, scoped extract, and access evidence are exercised; retention and independent custody are absent.'],
  ['11', 'Updates and drift', 'partial', 'Governed model switch and substitution containment are exercised.'],
  ['12', 'Service failure and exit', 'partial', 'Endpoint failure and crash ambiguity fail closed; export and exit are not assessed.'],
  ['13', 'Accessibility and vulnerable users', 'not_assessed', 'No affected-person or production-interface study exists.'],
] as const;

function table(headers: readonly string[], rows: readonly (readonly string[])[]): string {
  return `| ${headers.join(' | ')} |\n|${headers.map(() => '---').join('|')}|\n${rows.map((row) => `| ${row.join(' | ')} |`).join('\n')}\n`;
}

export function generateAcceptanceMarkdown(catalog: CaseCatalog): string {
  const beats = catalog.rows.filter((row) => row.class === 'beat').map((row) => [row.id, row.coverage, row.required_terminal_evidence]);
  const adversarial = catalog.rows.filter((row) => row.class === 'adversarial').map((row) => [row.id, row.coverage, row.required_terminal_evidence]);
  const infrastructure = catalog.rows.filter((row) => row.class === 'infrastructure').map((row) => [row.id, row.coverage, row.required_terminal_evidence]);
  return `<!-- SPDX-License-Identifier: CC-BY-4.0 -->
# M6.3 offline conformance acceptance ledger

**Status:** generated from the closed M6.3 catalog. Execution evidence remains maintainer-run synthetic conformance, not independent evaluation, assurance, certification, live-provider evidence, or M6 completion.

No public capture exists in M6.3. Live dual-model capture, remotely acknowledged anchors, human publication review, and screenshots/clips remain M6.4 and separately approval-gated.

## Seven baseline criteria

${table(['Criterion', 'Boundary', 'Status', 'Evidence limit'], BASELINE)}
## Scripted beats

${table(['Case', 'Status', 'Required bounded terminal evidence'], beats)}
## Adversarial cases

${table(['Case', 'Status', 'Required fail-closed evidence'], adversarial)}
## Infrastructure assertions

${table(['Case', 'Status', 'Required transport evidence'], infrastructure)}
## Thirteen test families

${table(['Family', 'Boundary', 'Status', 'Named gap'], FAMILIES)}
## Explicit exclusion

Subdelegation is **${catalog.exclusions[0].coverage}**: ${catalog.exclusions[0].reason}
`;
}
