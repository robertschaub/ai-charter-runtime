// SPDX-License-Identifier: MIT
import { sha256Hex } from 'gate-core/offline-safe';

import { readSafeRepositoryFile } from './repository.js';
import { SchemaRegistry } from './schemas.js';
import type { CaseCatalog, CatalogRow } from './types.js';

export const CATALOG_PATH = 'docs/m6/case-catalog.json';
export const PROVIDER_FIXTURE_PATH = 'docs/m6/provider-projections/beat-20.json';

export const BEAT_IDS = Array.from({ length: 22 }, (_, index) => `beat-${index.toString().padStart(2, '0')}`);
export const ADVERSARIAL_IDS = [
  'adv-changed-mandate-ordering',
  'adv-concurrent-dispositions',
  'adv-consumed-ruling-replay',
  'adv-consumed-token-replay',
  'adv-counter-ceiling-race',
  'adv-crash-after-commitment',
  'adv-disposition-outside-set',
  'adv-disposition-unauthorized-substitute',
  'adv-disposition-wrong-role',
  'adv-escalation-missing-contract-field',
  'adv-handoff-authz-restart',
  'adv-handoff-concurrent-redemption',
  'adv-handoff-expired',
  'adv-handoff-missing-process-auth',
  'adv-handoff-on-authority-route',
  'adv-handoff-opaque-origin',
  'adv-handoff-replay',
  'adv-handoff-wrong-case',
  'adv-handoff-wrong-origin',
  'adv-handoff-wrong-role',
  'adv-handoff-wrong-target-origin',
  'adv-handoff-wrong-window',
  'adv-handoff-wrong-world',
  'adv-illegal-stage-transition',
  'adv-late-approval',
  'adv-overlapping-mandates',
  'adv-policy-after-commit',
  'adv-policy-before-commit',
  'adv-proposal-mutated-after-allow',
  'adv-revocation-after-commit',
  'adv-revocation-before-commit',
  'adv-ruling-wrong-proposal',
  'adv-service-without-token',
  'adv-session-on-authority-route',
  'adv-session-orchestrator-restart',
] as const;
export const INFRASTRUCTURE_IDS = [
  'infra-browser-execute-foreign-origin',
  'infra-browser-execute-stale-session',
  'infra-browser-prepare-foreign-origin',
  'infra-browser-prepare-stale-session',
  'infra-services-five-routes',
  'infra-services-health',
  'infra-services-legacy-origin',
  'infra-services-no-store',
  'infra-services-unmatched-404',
] as const;

export const EXPECTED_CASE_IDS = [...BEAT_IDS, ...ADVERSARIAL_IDS, ...INFRASTRUCTURE_IDS] as const;

export interface LoadedCatalog {
  readonly catalog: CaseCatalog;
  readonly rowsById: ReadonlyMap<string, CatalogRow>;
  readonly digest: string;
}

export function loadCatalog(registry = new SchemaRegistry()): LoadedCatalog {
  const bytes = readSafeRepositoryFile(CATALOG_PATH);
  const parsed = JSON.parse(bytes.toString('utf8')) as unknown;
  registry.validate('caseCatalog', parsed);
  const catalog = parsed as CaseCatalog;
  const ids = catalog.rows.map((row) => row.id);
  if (new Set(ids).size !== ids.length) throw new Error('catalog row ids must be unique');
  const expected = [...EXPECTED_CASE_IDS];
  if (ids.length !== expected.length || ids.some((id, index) => id !== expected[index])) {
    throw new Error('catalog ids do not exactly match the reviewed M6.3 closed set');
  }
  for (const row of catalog.rows) {
    const expectedClass = row.id.startsWith('beat-') ? 'beat' : row.id.startsWith('adv-') ? 'adversarial' : 'infrastructure';
    if (row.class !== expectedClass) throw new Error(`${row.id} has incorrect class ${row.class}`);
    const expectedMode = row.id === 'beat-20' ? 'provider_specific' : row.class === 'infrastructure' ? 'single' : 'invariant';
    if (row.comparison_mode !== expectedMode) throw new Error(`${row.id} has incorrect comparison mode`);
  }
  return { catalog, rowsById: new Map(catalog.rows.map((row) => [row.id, row])), digest: sha256Hex(bytes) };
}

export function loadProviderFixture(registry = new SchemaRegistry()): unknown {
  const parsed = JSON.parse(readSafeRepositoryFile(PROVIDER_FIXTURE_PATH).toString('utf8')) as unknown;
  registry.validate('providerProjectionFixture', parsed);
  return parsed;
}
