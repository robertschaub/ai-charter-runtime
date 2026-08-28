// SPDX-License-Identifier: MIT
import { existsSync, linkSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { arch, platform, release } from 'node:os';
import { join } from 'node:path';

import { canonicalize, CardRegistry } from 'gate-core/offline-safe';
import { afterAll, describe, expect, it } from 'vitest';

import { generateAcceptanceMarkdown } from './acceptance.js';
import { M6CapabilityTrap } from './capabilityTrap.js';
import { loadCatalog, loadProviderFixture } from './catalog.js';
import { assertExecutorBijection, EXECUTORS } from './executors.js';
import { assertOfflineImportBoundary, assertOfflineSourceText } from './importBoundary.js';
import { capturePlanDigest, M6PlanError, validatePlan } from './plan.js';
import { readSafeRepositoryFile, REPOSITORY_ROOT, resolveSafeRepositoryFile } from './repository.js';
import { runOfflinePlan } from './runner.js';
import { currentNpmVersion } from './runtimeEnvironment.js';
import { assertNoForbiddenContent, sanitizeArtifact, sanitizeAttemptArtifacts } from './sanitization.js';
import { SchemaRegistry } from './schemas.js';
import { AttemptLifecycle, assertStagingNodeType, createCaptureDirectory, createCaptureStaging, writeExclusiveCanonicalJson } from './staging.js';
import type { CapturePlan, CaseExecutor } from './types.js';

const created: string[] = [];

afterAll(() => {
  for (const path of created.reverse()) rmSync(path, { recursive: true, force: true });
});

function cardBinding(cardId: string) {
  const inspection = CardRegistry.load(join(REPOSITORY_ROOT, 'docs', 'cards')).get(cardId);
  if (inspection === undefined) throw new Error(`missing card ${cardId}`);
  return { card_id: inspection.card.card_id, card_version: inspection.card.card_version, card_digest: inspection.digest, requested_id: inspection.card.model.requested_id };
}

function plan(captureId: string, classification: 'offline-fixture' | 'live' = 'offline-fixture'): CapturePlan {
  const body = {
    schema_version: 'm6-capture-plan/v1' as const,
    capture_id: captureId,
    supersedes_capture_id: null,
    scenario_id: 'synthetic-grant-decision',
    layers: [classification] as ('offline-fixture' | 'live')[],
    catalog_digest: loadCatalog().digest,
    lanes: [
      { lane_slot: 'lane-0' as const, card_binding: cardBinding('publicai-apertus-v1.5-70b') },
      { lane_slot: 'lane-1' as const, card_binding: cardBinding('openai-gpt-5.5') },
    ] as const,
    screening_role: cardBinding('publicai-apertus-v1.5-70b'),
    provenance: {
      runtime_commit: '1'.repeat(64), charter_commit: '2'.repeat(64),
      runtime_specification: { path: 'docs/wip/runtime-gates-poc-spec.md', digest: '3'.repeat(64) },
      system_use_decision: { decision_id: 'system-use-poc', decision_version: 1, decision_digest: '4'.repeat(64), source_path: 'docs/wip/system-use-decision.md', source_digest: '5'.repeat(64) },
      policy: { version: 1, content_digest: '6'.repeat(64) }, evaluator: { build_id: 'm6-offline', build_digest: '7'.repeat(64) }, fixture_file_set_digest: '8'.repeat(64),
    },
    synthetic_inputs: [{ id: 'grant-fixtures', digest: '9'.repeat(64) }],
    clock_profile: 'fixed-2026-08-01', deterministic_id_profile: 'm6-sequential-v1',
    expected_boundaries: { stop_case_ids: ['beat-02', 'beat-05', 'beat-20', 'beat-21'], effect_case_ids: ['beat-03', 'beat-06'] },
    runtime_environment: { node_version: process.version, npm_version: currentNpmVersion(), os_platform: platform(), os_release: release(), architecture: arch() },
    commands: [
      { name: 'm6:dry-run', argv: ['npm', 'run', 'm6:dry-run'] },
      { name: 'm6:offline', argv: ['npm', 'run', 'm6:offline'] },
      { name: 'm6:schemas', argv: ['npm', 'run', 'm6:schemas'] },
    ],
    network_classification: classification,
    timeout_ms: 120000, write_roots: ['.m6-staging'] as const,
    request_ceilings: { provider_requests: 0, screening_requests: 0, effects: 4 }, no_retry: true as const, no_fallback: true as const,
    checkpoint_requirements: { run_start: 'not_required', run_end: 'not_required' },
    artifact_schema_versions: {
      case_catalog: 'm6-case-catalog/v1', provider_projection_fixture: 'm6-provider-projection-fixture/v1', capture_plan: 'm6-capture-plan/v1',
      offline_matrix: 'm6-offline-matrix/v1', attempt_events: 'm6-attempt-events/v1', sanitization_report: 'm6-sanitization-report/v1', capture_manifest: 'm6-capture-manifest/v1',
    },
    storyboards: [
      { id: 'conflict-to-effect', case_ids: ['beat-03', 'beat-06'] },
      { id: 'injection-contained', case_ids: ['beat-05'] },
      { id: 'model-switch-contained', case_ids: ['beat-19', 'beat-20', 'beat-21'] },
    ],
  };
  return { ...body, plan_digest: capturePlanDigest(body as Omit<CapturePlan, 'plan_digest'>) } as CapturePlan;
}

describe('M6.3 offline conformance boundary', () => {
  it('compiles all seven strict schemas, pins the exact catalog, import boundary, and generated acceptance bytes', () => {
    expect(() => new SchemaRegistry()).not.toThrow();
    const loaded = loadCatalog();
    expect(loaded.catalog.rows).toHaveLength(66);
    expect(loaded.catalog.exclusions).toEqual([expect.objectContaining({ id: 'subdelegation', coverage: 'not_assessed' })]);
    expect(() => assertExecutorBijection(loaded.catalog.rows.map((row) => row.id))).not.toThrow();
    expect(() => assertOfflineImportBoundary()).not.toThrow();
    expect(generateAcceptanceMarkdown(loaded.catalog)).toBe(readSafeRepositoryFile('docs/m6/acceptance.md').toString('utf8'));
    const schemas = new SchemaRegistry();
    expect(() => schemas.validate('caseCatalog', { ...loaded.catalog, unexpected: true })).toThrow();
    expect(() => schemas.validate('providerProjectionFixture', { ...(loadProviderFixture() as object), unexpected: true })).toThrow();
    expect(() => schemas.validate('capturePlan', { ...plan('m6-schema-plan'), unexpected: true })).toThrow();
  });

  it('binds every plan field and refuses live execution before creating staging', async () => {
    const valid = plan('m6-plan-vector');
    expect(validatePlan(valid)).toEqual(valid);
    const digestMutations: CapturePlan[] = [
      { ...valid, timeout_ms: valid.timeout_ms + 1 },
      { ...valid, commands: valid.commands.map((command, index) => index === 0 ? { ...command, argv: [...command.argv, '--silent'] } : command) },
      { ...valid, lanes: [{ ...valid.lanes[0], card_binding: valid.lanes[1].card_binding }, { ...valid.lanes[1], card_binding: valid.lanes[0].card_binding }] },
      { ...valid, provenance: { ...valid.provenance, runtime_commit: 'a'.repeat(64) } },
      { ...valid, request_ceilings: { ...valid.request_ceilings, effects: valid.request_ceilings.effects! + 1 } },
      { ...valid, expected_boundaries: { ...valid.expected_boundaries, stop_case_ids: ['beat-02', 'beat-04', 'beat-05', 'beat-20', 'beat-21'] } },
    ];
    for (const mutation of digestMutations) {
      expect(() => validatePlan(mutation)).toThrowError(expect.objectContaining<Partial<M6PlanError>>({ code: 'm6-plan-digest' }));
    }
    expect(() => validatePlan({ ...valid, expected_boundaries: { ...valid.expected_boundaries, stop_case_ids: ['beat-05', 'beat-02'] } })).toThrowError(expect.objectContaining<Partial<M6PlanError>>({ code: 'm6-plan-set-order' }));
    const live = plan('m6-live-refused', 'live');
    const planDir = join(REPOSITORY_ROOT, 'packages', 'm6-offline', '.m6-test-plans');
    mkdirSync(planDir, { recursive: true });
    created.push(planDir);
    const livePath = join(planDir, 'live.json');
    writeFileSync(livePath, `${canonicalize(live)}\n`, 'utf8');
    const refusedRoot = join(REPOSITORY_ROOT, '.m6-staging', live.capture_id);
    expect(existsSync(refusedRoot)).toBe(false);
    await expect(runOfflinePlan('packages/m6-offline/.m6-test-plans/live.json')).rejects.toMatchObject({ code: 'm6-live-plan-refused' });
    expect(existsSync(refusedRoot)).toBe(false);
    const { plan_digest: ignoredDigest, ...environmentBody } = plan('m6-npm-refused');
    void ignoredDigest;
    const wrongEnvironmentBody = {
      ...environmentBody,
      runtime_environment: { ...environmentBody.runtime_environment, npm_version: '0.0.0' },
    };
    const wrongEnvironment = { ...wrongEnvironmentBody, plan_digest: capturePlanDigest(wrongEnvironmentBody) };
    writeFileSync(join(planDir, 'wrong-environment.json'), `${canonicalize(wrongEnvironment)}\n`, 'utf8');
    await expect(runOfflinePlan('packages/m6-offline/.m6-test-plans/wrong-environment.json')).rejects.toMatchObject({ code: 'm6-runtime-environment-mismatch' });
    expect(existsSync(join(REPOSITORY_ROOT, '.m6-staging', wrongEnvironment.capture_id))).toBe(false);
  });

  it('runs the exact 123-result matrix through the shared executors and strict staged projections', async () => {
    const captureId = 'm6-offline-vitest';
    const fixture = plan(captureId);
    const planDir = join(REPOSITORY_ROOT, 'packages', 'm6-offline', '.m6-test-run');
    mkdirSync(planDir, { recursive: true });
    created.push(planDir, join(REPOSITORY_ROOT, '.m6-staging', captureId));
    writeFileSync(join(planDir, 'plan.json'), `${canonicalize(fixture)}\n`, 'utf8');
    const result = await runOfflinePlan('packages/m6-offline/.m6-test-run/plan.json');
    expect(result.captureRoot).toBe(join(REPOSITORY_ROOT, '.m6-staging', captureId));
    expect(result.manifest).toMatchObject({ publication_state: 'staged-not-published', attempt_summary: { total: 1, complete: 1, failed: 0, indeterminate: 0 } });
    const schemas = new SchemaRegistry();
    for (const [schema, file] of [
      ['offlineMatrix', 'offline-matrix.json'], ['attemptEvents', 'attempt-events.json'],
      ['sanitizationReport', 'sanitization-report.json'], ['captureManifest', 'capture-manifest.json'],
    ] as const) {
      const value = JSON.parse(readFileSync(join(result.captureRoot, file), 'utf8')) as object;
      expect(() => schemas.validate(schema, { ...value, unexpected: true })).toThrow();
      expect(() => schemas.validate(schema, { ...value, capture_id: 'con' })).toThrow();
    }
  }, 120_000);

  it('retains a bounded failed attempt and rejects hard-linked repository inputs', async () => {
    const captureId = 'm6-failure-vitest';
    const fixture = plan(captureId);
    const planDir = join(REPOSITORY_ROOT, 'packages', 'm6-offline', '.m6-test-failure');
    mkdirSync(planDir, { recursive: true });
    created.push(planDir, join(REPOSITORY_ROOT, '.m6-staging', captureId));
    const path = join(planDir, 'plan.json');
    writeFileSync(path, `${canonicalize(fixture)}\n`, 'utf8');
    const hardlink = join(planDir, 'hardlink.json');
    linkSync(path, hardlink);
    expect(() => resolveSafeRepositoryFile('packages/m6-offline/.m6-test-failure/hardlink.json')).toThrow(/hard-linked/);
    rmSync(hardlink);
    const registry = EXECUTORS as unknown as Map<string, CaseExecutor>;
    const original = registry.get('beat-00');
    if (original === undefined) throw new Error('missing beat-00 executor');
    registry.set('beat-00', async () => { throw new Error('synthetic executor failure'); });
    try {
      await expect(runOfflinePlan('packages/m6-offline/.m6-test-failure/plan.json')).rejects.toThrow('synthetic executor failure');
    } finally {
      registry.set('beat-00', original);
    }
    expect(JSON.parse(readFileSync(join(REPOSITORY_ROOT, '.m6-staging', captureId, 'capture-manifest.json'), 'utf8'))).toMatchObject({
      attempt_summary: { total: 1, complete: 0, failed: 1, indeterminate: 0 },
    });
  });

  it('enforces append-only legal attempt transitions', () => {
    const lifecycle = new AttemptLifecycle('attempt-test', 'offline-fixture', '2026-08-01T09:00:00.000Z');
    lifecycle.transition('planned'); lifecycle.transition('preflighted'); lifecycle.transition('running'); lifecycle.transition('failed', 'synthetic-failure'); lifecycle.transition('sanitized');
    expect(lifecycle.events.map((event) => event.state)).toEqual(['planned', 'preflighted', 'running', 'failed', 'sanitized']);
    expect(() => lifecycle.transition('running')).toThrow(/illegal M6 attempt transition/);
  });

  it('refuses traversal, links, collisions, reserved ids, and artifact overwrite in staging', () => {
    expect(() => createCaptureStaging('con')).toThrow(/reserved/);
    const collisionPath = join(REPOSITORY_ROOT, '.m6-staging', 'M6-Case-Collision');
    mkdirSync(collisionPath, { recursive: true });
    created.push(collisionPath);
    expect(() => createCaptureStaging('m6-case-collision')).toThrow(/case-collides/);
    const root = createCaptureStaging('m6-staging-negative');
    created.push(root);
    expect(() => createCaptureDirectory(root, '../escape')).toThrow(/invalid M6 staging directory/);
    createCaptureDirectory(root, 'plain');
    writeExclusiveCanonicalJson(root, 'plain/artifact.json', { ok: true });
    expect(() => writeExclusiveCanonicalJson(root, 'plain/artifact.json', { ok: false })).toThrow(/overwrite/);
    expect(() => assertStagingNodeType('injected-symlink', { symbolicLink: true, directory: false, file: false, linkCount: 1 })).toThrow(/linked\/special/);
    const junction = join(root, 'junction');
    symlinkSync(join(root, 'plain'), junction, 'junction');
    expect(() => createCaptureDirectory(root, 'junction/child')).toThrow(/linked\/special/);
  });

  it('rejects side-effect imports and unavailable socket, listener, and worker capabilities', () => {
    expect(() => assertOfflineSourceText('negative.ts', "import 'node:net';\n")).toThrow(/node:net/);
    expect(() => assertOfflineSourceText('negative.ts', 'fetch("http://127.0.0.1");\n')).toThrow(/global boundary/);
    expect(() => assertOfflineSourceText('negative.ts', 'process.env.API_KEY;\n')).toThrow(/global boundary/);
    const ordinary = new M6CapabilityTrap();
    expect(() => ordinary.assertSocket('http://127.0.0.1:1')).toThrow(/socket/);
    expect(() => ordinary.assertListen('127.0.0.1')).toThrow(/listener/);
    expect(() => ordinary.assertWorker()).toThrow(/worker/);
    const infrastructure = new M6CapabilityTrap(true);
    expect(() => infrastructure.assertSocket('https://127.0.0.1:1')).toThrow(/socket/);
    expect(() => infrastructure.assertListen('0.0.0.0')).toThrow(/listener/);
    expect(() => infrastructure.assertSocket('http://127.0.0.1:1')).not.toThrow();
  });

  it('enforces exact layer labels and expanded path and secret exclusions', () => {
    const registry = new SchemaRegistry();
    const report = {
      schema_version: 'm6-sanitization-report/v1', capture_id: 'm6-sanitize-vector', attempt_id: 'attempt-one', plan_digest: 'a'.repeat(64),
      layer: 'dry-run', status: 'pass', checks: ['artifact-schema', 'retained-failures', 'success-only-omission'],
      failed_attempt_count: 0, indeterminate_attempt_count: 0, sanitized_at: '2026-08-01T09:00:00.000Z',
    };
    expect(() => sanitizeArtifact('sanitizationReport', report, 'offline-fixture', registry)).toThrow(/layer label mismatch/);
    for (const value of ['\\??\\C:\\private', '/var/private', '/tmp/private', '/mnt/private', '=C:\\private', '\\Windows\\System32']) {
      expect(() => assertNoForbiddenContent({ value }, 'offline-fixture')).toThrow(/forbidden content/);
    }
    for (const key of ['api_key', 'access_token', 'secret', 'password']) {
      expect(() => assertNoForbiddenContent({ [key]: 'redacted' }, 'offline-fixture')).toThrow(/forbidden key/);
    }
    const events = {
      schema_version: 'm6-attempt-events/v1', capture_id: 'm6-sanitize-vector', events: [
        { sequence: 0, attempt_id: 'attempt-one', layer: 'offline-fixture', state: 'planned', recorded_at: '2026-08-01T09:00:00.000Z', failure_class: null },
        { sequence: 1, attempt_id: 'attempt-one', layer: 'offline-fixture', state: 'failed', recorded_at: '2026-08-01T09:00:00.000Z', failure_class: 'synthetic-failure' },
        { sequence: 2, attempt_id: 'attempt-one', layer: 'offline-fixture', state: 'sanitized', recorded_at: '2026-08-01T09:00:00.000Z', failure_class: null },
      ],
    } as const;
    const failedReport = { ...report, layer: 'offline-fixture' as const, failed_attempt_count: 1 };
    expect(() => sanitizeAttemptArtifacts(events, failedReport, { total: 1, complete: 0, failed: 0, indeterminate: 1 }, [], 'offline-fixture', registry)).toThrow(/summary does not reconcile/);
    expect(() => sanitizeAttemptArtifacts(events, failedReport, { total: 1, complete: 0, failed: 1, indeterminate: 0 }, ['attempt-one'], 'offline-fixture', registry)).toThrow(/omit failed or indeterminate/);
    expect(() => sanitizeAttemptArtifacts(events, failedReport, { total: 1, complete: 0, failed: 1, indeterminate: 0 }, [], 'offline-fixture', registry)).not.toThrow();
  });
});
