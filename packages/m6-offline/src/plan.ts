// SPDX-License-Identifier: MIT
import { canonicalize, digestFor, verifyDigest } from 'gate-core/offline-safe';

import { loadCatalog } from './catalog.js';
import { readSafeRepositoryFile } from './repository.js';
import { SchemaRegistry } from './schemas.js';
import type { CapturePlan } from './types.js';

export class M6PlanError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'M6PlanError';
  }
}

export function capturePlanDigest(plan: Omit<CapturePlan, 'plan_digest'>): string {
  return digestFor('m6-capture-plan', plan);
}

function assertSortedUnique(values: readonly string[], label: string): void {
  const sorted = [...values].sort();
  if (new Set(values).size !== values.length || values.some((value, index) => value !== sorted[index])) {
    throw new M6PlanError('m6-plan-set-order', `${label} must be sorted and unique`);
  }
}

function assertEmbeddedRelativePath(value: string, label: string): void {
  if (/^(?:[a-zA-Z]:|\\|\/|file:)/i.test(value) || value.includes('\\') || value.split('/').some((part) => part === '' || part === '.' || part === '..')) {
    throw new M6PlanError('m6-plan-path-refused', `${label} must be a normalized repository-relative path`);
  }
}

function assertCommand(command: CapturePlan['commands'][number]): void {
  if (command.argv[0] !== 'npm' || command.argv[1] !== 'run' || command.argv[2] !== command.name) {
    throw new M6PlanError('m6-plan-command-refused', `${command.name} argv must invoke only its exact root script`);
  }
  if (command.argv.some((argument) => /(?:^|[-:])(live|network|provider|api-key|retry|fallback|probe|checkpoint|push|publish|effect-target)(?:$|[-:])/i.test(argument))) {
    throw new M6PlanError('m6-plan-command-refused', `${command.name} argv contains a capability outside M6.3`);
  }
}

export function validatePlan(value: unknown, registry = new SchemaRegistry()): CapturePlan {
  registry.validate('capturePlan', value);
  const plan = value as CapturePlan;
  assertSortedUnique(plan.layers, 'layers');
  assertSortedUnique(plan.synthetic_inputs.map((input) => input.id), 'synthetic input ids');
  assertSortedUnique(plan.commands.map((command) => command.name), 'command names');
  for (const command of plan.commands) assertCommand(command);
  assertSortedUnique(plan.storyboards.map((storyboard) => storyboard.id), 'storyboard ids');
  for (const storyboard of plan.storyboards) assertSortedUnique(storyboard.case_ids, `${storyboard.id} case ids`);
  const expectedBoundaries = plan.expected_boundaries as { stop_case_ids: readonly string[]; effect_case_ids: readonly string[] };
  assertSortedUnique(expectedBoundaries.stop_case_ids, 'expected stop case ids');
  assertSortedUnique(expectedBoundaries.effect_case_ids, 'expected effect case ids');
  if (plan.lanes[0].card_binding.card_digest === plan.lanes[1].card_binding.card_digest) {
    throw new M6PlanError('m6-plan-lanes-not-distinct', 'lane card bindings must be distinct');
  }
  if (plan.catalog_digest !== loadCatalog(registry).digest) {
    throw new M6PlanError('m6-plan-catalog-digest', 'plan does not bind the exact committed catalog bytes');
  }
  const provenance = plan.provenance as {
    runtime_specification: { path: string };
    system_use_decision: { source_path: string };
  };
  assertEmbeddedRelativePath(provenance.runtime_specification.path, 'runtime specification path');
  assertEmbeddedRelativePath(provenance.system_use_decision.source_path, 'system-use source path');
  if (plan.network_classification === 'offline-fixture') {
    if (plan.request_ceilings.provider_requests !== 0 || plan.request_ceilings.screening_requests !== 0) {
      throw new M6PlanError('m6-plan-network-ceiling', 'offline fixture plans must bind zero provider and screening requests');
    }
    if (plan.checkpoint_requirements.run_start !== 'not_required' || plan.checkpoint_requirements.run_end !== 'not_required') {
      throw new M6PlanError('m6-plan-checkpoint-refused', 'M6.3 offline execution cannot require checkpoint operations');
    }
  }
  const { plan_digest: ignored, ...body } = plan;
  void ignored;
  if (!verifyDigest(capturePlanDigest(body), plan.plan_digest)) {
    throw new M6PlanError('m6-plan-digest', 'plan digest does not match the canonical plan body');
  }
  return plan;
}

export function loadPlan(relativePath: string, registry = new SchemaRegistry()): CapturePlan {
  const bytes = readSafeRepositoryFile(relativePath);
  let parsed: unknown;
  try {
    parsed = JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    throw new M6PlanError('m6-plan-json', 'plan is not valid JSON');
  }
  if (Buffer.from(`${canonicalize(parsed)}\n`, 'utf8').compare(bytes) !== 0) {
    throw new M6PlanError('m6-plan-noncanonical', 'plan must be canonical JSON followed by one LF');
  }
  return validatePlan(parsed, registry);
}

export function assertExecutableOfflinePlan(plan: CapturePlan): void {
  if (plan.network_classification === 'live') {
    throw new M6PlanError('m6-live-plan-refused', 'M6.3 has no live-provider execution path');
  }
  if (plan.network_classification !== 'offline-fixture') {
    throw new M6PlanError('m6-plan-layer-refused', 'offline execution requires network_classification offline-fixture');
  }
}
