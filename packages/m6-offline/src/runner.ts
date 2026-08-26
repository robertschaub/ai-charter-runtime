// SPDX-License-Identifier: MIT
import { arch, platform, release } from 'node:os';

import { sha256Hex } from 'gate-core/offline-safe';

import { loadCatalog } from './catalog.js';
import { comparePair } from './comparison.js';
import { assertExecutorBijection, executorFor } from './executors.js';
import { assertExecutableOfflinePlan, loadPlan, M6PlanError } from './plan.js';
import { sanitizeArtifact } from './sanitization.js';
import { SchemaRegistry } from './schemas.js';
import { AttemptLifecycle, createCaptureDirectory, createCaptureStaging, writeExclusiveCanonicalJson } from './staging.js';
import type { BoundedCaseResult, CapturePlan, PairComparison } from './types.js';

interface ArtifactDescriptor { readonly path: string; readonly schema_version: string; readonly sha256: string; readonly byte_length: number }

function writeArtifact(root: string, path: string, schemaVersion: string, value: unknown): ArtifactDescriptor {
  const written = writeExclusiveCanonicalJson(root, path, value);
  return { path, schema_version: schemaVersion, sha256: sha256Hex(written.bytes), byte_length: written.byteLength };
}

export interface OfflineRunResult { readonly captureRoot: string; readonly manifest: unknown }

export async function runOfflinePlan(relativePlanPath: string): Promise<OfflineRunResult> {
  const registry = new SchemaRegistry();
  const plan = loadPlan(relativePlanPath, registry);
  // This check intentionally precedes every staging or executor operation.
  assertExecutableOfflinePlan(plan);
  const expectedEnvironment = plan.runtime_environment;
  if (
    expectedEnvironment.node_version !== process.version || expectedEnvironment.os_platform !== platform() ||
    expectedEnvironment.os_release !== release() || expectedEnvironment.architecture !== arch()
  ) throw new M6PlanError('m6-runtime-environment-mismatch', 'offline plan does not bind the current bounded runtime environment');
  const loaded = loadCatalog(registry);
  assertExecutorBijection(loaded.catalog.rows.map((row) => row.id));
  const root = createCaptureStaging(plan.capture_id);
  const lifecycle = new AttemptLifecycle('offline-attempt', 'offline-fixture', '2026-08-01T09:00:00.000Z');
  lifecycle.transition('planned');
  const artifacts: ArtifactDescriptor[] = [];
  sanitizeArtifact('capturePlan', plan, 'offline-fixture', registry);
  artifacts.push(writeArtifact(root, 'capture-plan.json', plan.schema_version, plan));
  lifecycle.transition('preflighted');
  lifecycle.transition('running');
  const results: BoundedCaseResult[] = [];
  const comparisons: PairComparison[] = [];
  try {
    for (const row of loaded.catalog.rows) {
      const executor = executorFor(row.id);
      if (row.class === 'infrastructure') {
        const recordsRoot = createCaptureDirectory(root, `records/${row.id}/single`);
        results.push(await executor({ captureId: plan.capture_id, attemptId: 'offline-attempt', row, laneSlot: 'single', selectedCard: null, fixedNow: '2026-08-01T09:00:00.000Z', stagingRoot: root, recordsRoot }));
        continue;
      }
      const laneResults: BoundedCaseResult[] = [];
      for (const lane of plan.lanes) {
        const recordsRoot = createCaptureDirectory(root, `records/${row.id}/${lane.lane_slot}`);
        const result = await executor({ captureId: plan.capture_id, attemptId: 'offline-attempt', row, laneSlot: lane.lane_slot, selectedCard: lane.card_binding, fixedNow: '2026-08-01T09:00:00.000Z', stagingRoot: root, recordsRoot });
        if (result.selected_card?.card_digest !== lane.card_binding.card_digest) throw new Error(`${row.id} did not report the exact selected card`);
        laneResults.push(result);
        results.push(result);
      }
      comparisons.push(comparePair(laneResults[0]!, laneResults[1]!, row.comparison_mode as 'invariant' | 'provider_specific'));
    }
    if (results.length !== 123 || comparisons.length !== 57) throw new Error('M6 offline runner did not execute the closed matrix exactly once');
    lifecycle.transition('complete');
  } catch (error) {
    lifecycle.transition('failed', 'executor-failure');
    lifecycle.transition('sanitized');
    const failedEvents = { schema_version: 'm6-attempt-events/v1', capture_id: plan.capture_id, events: lifecycle.events } as const;
    const failedSanitization = {
      schema_version: 'm6-sanitization-report/v1', capture_id: plan.capture_id, attempt_id: 'offline-attempt', plan_digest: plan.plan_digest,
      layer: 'offline-fixture', status: 'pass',
      checks: ['artifact-schema', 'bounded-environment', 'fixed-projection', 'layer-labels', 'no-forbidden-content', 'no-secret-material', 'path-confinement', 'retained-failures', 'synthetic-only'],
      failed_attempt_count: 1, indeterminate_attempt_count: 0, sanitized_at: '2026-08-01T09:00:00.000Z',
    } as const;
    sanitizeArtifact('attemptEvents', failedEvents, 'offline-fixture', registry);
    sanitizeArtifact('sanitizationReport', failedSanitization, 'offline-fixture', registry);
    artifacts.push(writeArtifact(root, 'attempt-events.json', failedEvents.schema_version, failedEvents));
    artifacts.push(writeArtifact(root, 'sanitization-report.json', failedSanitization.schema_version, failedSanitization));
    const failedManifest = {
      schema_version: 'm6-capture-manifest/v1', capture_id: plan.capture_id, plan_digest: plan.plan_digest, layer: 'offline-fixture', artifacts,
      attempt_summary: { total: 1, complete: 0, failed: 1, indeterminate: 0 }, publication_state: 'staged-not-published',
    } as const;
    sanitizeArtifact('captureManifest', failedManifest, 'offline-fixture', registry);
    writeArtifact(root, 'capture-manifest.json', failedManifest.schema_version, failedManifest);
    throw error;
  }
  const matrix = {
    schema_version: 'm6-offline-matrix/v1', capture_id: plan.capture_id, attempt_id: 'offline-attempt', plan_digest: plan.plan_digest,
    layer: 'offline-fixture', results, comparisons,
    summary: { result_count: 123, comparison_count: 57, failed_count: 0, indeterminate_count: 0 },
  } as const;
  sanitizeArtifact('offlineMatrix', matrix, 'offline-fixture', registry);
  lifecycle.transition('sanitized');
  const events = { schema_version: 'm6-attempt-events/v1', capture_id: plan.capture_id, events: lifecycle.events } as const;
  const sanitization = {
    schema_version: 'm6-sanitization-report/v1', capture_id: plan.capture_id, attempt_id: 'offline-attempt', plan_digest: plan.plan_digest,
    layer: 'offline-fixture', status: 'pass',
    checks: ['artifact-schema', 'bounded-environment', 'fixed-projection', 'layer-labels', 'no-forbidden-content', 'no-secret-material', 'path-confinement', 'retained-failures', 'synthetic-only'],
    failed_attempt_count: 0, indeterminate_attempt_count: 0, sanitized_at: '2026-08-01T09:00:00.000Z',
  } as const;
  sanitizeArtifact('attemptEvents', events, 'offline-fixture', registry);
  sanitizeArtifact('sanitizationReport', sanitization, 'offline-fixture', registry);
  artifacts.push(writeArtifact(root, 'offline-matrix.json', matrix.schema_version, matrix));
  artifacts.push(writeArtifact(root, 'attempt-events.json', events.schema_version, events));
  artifacts.push(writeArtifact(root, 'sanitization-report.json', sanitization.schema_version, sanitization));
  const manifest = {
    schema_version: 'm6-capture-manifest/v1', capture_id: plan.capture_id, plan_digest: plan.plan_digest, layer: 'offline-fixture', artifacts,
    attempt_summary: { total: 1, complete: 1, failed: 0, indeterminate: 0 }, publication_state: 'staged-not-published',
  } as const;
  sanitizeArtifact('captureManifest', manifest, 'offline-fixture', registry);
  writeArtifact(root, 'capture-manifest.json', manifest.schema_version, manifest);
  return { captureRoot: root, manifest };
}

export function dryRunPlan(relativePlanPath: string): CapturePlan {
  return loadPlan(relativePlanPath);
}
