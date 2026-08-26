// SPDX-License-Identifier: MIT
import { ADVERSARIAL_IDS, BEAT_IDS, EXPECTED_CASE_IDS, INFRASTRUCTURE_IDS } from './catalog.js';
import { executeAdversarial } from './adversarialExecutors.js';
import { executeBeat } from './beatExecutors.js';
import { executeInfrastructure } from './infrastructureHarness.js';
import type { CaseExecutor } from './types.js';

export const EXECUTORS: ReadonlyMap<string, CaseExecutor> = new Map([
  ...BEAT_IDS.map((id) => [id, executeBeat] as const),
  ...ADVERSARIAL_IDS.map((id) => [id, executeAdversarial] as const),
  ...INFRASTRUCTURE_IDS.map((id) => [id, executeInfrastructure] as const),
]);

export function assertExecutorBijection(catalogIds: readonly string[], registry = EXECUTORS): void {
  const expected = [...EXPECTED_CASE_IDS];
  const registered = [...registry.keys()];
  if (catalogIds.length !== expected.length || catalogIds.some((id, index) => id !== expected[index])) {
    throw new Error('catalog does not contain the exact reviewed executor id sequence');
  }
  if (registered.length !== expected.length || registered.some((id, index) => id !== expected[index])) {
    throw new Error('executor registry is not bijective with the reviewed catalog');
  }
}

export function executorFor(caseId: string): CaseExecutor {
  const executor = EXECUTORS.get(caseId);
  if (executor === undefined) throw new Error(`no M6 executor for ${caseId}`);
  return executor;
}
