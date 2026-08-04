// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  AUTHORIZATION_ROUTES,
  AuthorizationHttpAdapter,
  assertAuthorizationRouteCoverage,
  type CredentialBinding,
} from './authorizationHttpAdapter.js';
import { AuthorizationCore, type IdFactory } from './authorizationCore.js';
import { digestFor } from './hash.js';
import { Keyring } from './keyring.js';
import { loadPolicyFile } from './policyLoader.js';
import { modelCallAdmission, modelCallFailedRecord, modelOutputAdmission } from './schemas/index.js';
import { WalStore } from './walStore.js';

const POLICY_FILE = fileURLToPath(new URL('../policy/v1.yaml', import.meta.url));
const BUILD_DIGEST = digestFor('evaluator-build', { package: 'gate-core', test: 'http-adapter' });
const roots: string[] = [];
const stores: WalStore[] = [];

class SequentialIds implements IdFactory {
  #next = 0;
  next(prefix: Parameters<IdFactory['next']>[0]): string {
    this.#next += 1;
    return `${prefix}_${this.#next}`;
  }
}

const credentials: readonly CredentialBinding[] = [
  { label: 'role:principal', token: '1'.repeat(64), worldId: 'w-demo' },
  { label: 'role:case_officer', token: '2'.repeat(64), worldId: 'w-demo' },
  { label: 'role:applicant', token: '3'.repeat(64), worldId: 'w-demo' },
  { label: 'proc:orchestrator', token: '4'.repeat(64), worldId: 'w-demo' },
  { label: 'proc:services_host', token: '5'.repeat(64), worldId: 'w-demo' },
];

afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function setup(
  options: {
    credentials?: readonly CredentialBinding[];
    registeredRouteIds?: readonly string[];
    unauthenticatedDetailLimit?: number;
    unauthenticatedWindowMs?: number;
    nowMilliseconds?: () => number;
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), 'authz-http-m4-'));
  roots.push(root);
  const policy = loadPolicyFile(POLICY_FILE, BUILD_DIGEST);
  const store = WalStore.open({
    recordsRoot: root,
    worldId: 'w-demo',
    runId: 'run_http_1',
    bootId: 'authz_boot_http_1',
    policyVersion: policy.policy.policy_version,
    policyContentDigest: policy.policyContentDigest,
    evaluatorBuildDigest: policy.evaluatorBuildDigest,
    now: () => '2026-08-02T09:00:00.000Z',
  });
  stores.push(store);
  const authorization = new AuthorizationCore({
    store,
    keyring: new Keyring(new Map([['hmac-test', 'a'.repeat(64)]]), 'hmac-test'),
    policy,
    ids: new SequentialIds(),
    resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
    resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
    validateScreeningResolution: () => true,
    resolveModelEvidence: () => ({
      servedModelAccepted: true,
      cardStatus: 'current',
      cardKeyId: 'card-test',
      cardDigest: 'c'.repeat(64),
    }),
  });
  const adapter = new AuthorizationHttpAdapter({
    authorization,
    ownOrigin: 'http://127.0.0.1:7801',
    demoWorldId: 'w-demo',
    credentials: options.credentials ?? credentials,
    registeredRouteIds: options.registeredRouteIds,
    unauthenticatedDetailLimit: options.unauthenticatedDetailLimit,
    unauthenticatedWindowMs: options.unauthenticatedWindowMs,
    nowMilliseconds: options.nowMilliseconds,
  });
  return { adapter, store };
}

describe('ADR-002 authorization HTTP adapter', () => {
  it('fails startup on incomplete credentials, duplicate tokens, or route/ACL drift', () => {
    expect(() => setup({ credentials: credentials.slice(0, -1) })).toThrow(/missing authorization credential/);
    expect(() =>
      setup({ credentials: credentials.map((entry, index) => (index === 1 ? { ...entry, token: '1'.repeat(64) } : entry)) }),
    ).toThrow(/mutually distinct/);
    expect(() => assertAuthorizationRouteCoverage(AUTHORIZATION_ROUTES.slice(1).map((route) => route.id))).toThrow(
      /ACL mismatch/,
    );
  });

  it('records an absent credential as 401 and never invokes the operation', async () => {
    const { adapter, store } = setup();
    const operation = vi.fn(async () => ({ status: 200, body: { ok: true } }));
    await expect(
      adapter.dispatch({ method: 'POST', pathname: '/w/w-demo/proposals' }, operation),
    ).resolves.toMatchObject({ status: 401, body: { error: 'unauthenticated' } });
    expect(operation).not.toHaveBeenCalled();
    expect(store.snapshot().accessRecords).toEqual([
      expect.objectContaining({
        route: 'POST /w/{world_id}/proposals',
        authenticated_actor: null,
        outcome: 'unauthenticated',
        http_status: 401,
      }),
    ]);
  });

  it('bounds unauthenticated denial evidence to detailed entries plus one suppression marker per window', async () => {
    let now = 1_000;
    const { adapter, store } = setup({
      unauthenticatedDetailLimit: 2,
      unauthenticatedWindowMs: 1_000,
      nowMilliseconds: () => now,
    });
    const operation = vi.fn(async () => ({ status: 200, body: { ok: true } }));
    const responses = await Promise.all(
      Array.from({ length: 20 }, () =>
        adapter.dispatch({ method: 'POST', pathname: '/w/w-demo/proposals' }, operation),
      ),
    );
    expect(responses.slice(0, 2).map((response) => response.status)).toEqual([401, 401]);
    expect(responses.slice(2).every((response) => response.status === 429)).toBe(true);
    expect(operation).not.toHaveBeenCalled();
    expect(store.snapshot().accessRecords).toEqual([
      expect.objectContaining({ outcome: 'unauthenticated', http_status: 401 }),
      expect.objectContaining({ outcome: 'unauthenticated', http_status: 401 }),
      expect.objectContaining({
        route: 'AUTHZ unauthenticated ingress',
        outcome: 'rate-limited',
        http_status: 429,
        suppressed_count: 1,
        suppression_final: false,
      }),
    ]);
    now = 2_000;
    await expect(
      adapter.dispatch({ method: 'POST', pathname: '/w/w-demo/proposals' }, operation),
    ).resolves.toMatchObject({ status: 401 });
    expect(store.snapshot().accessRecords.slice(-2)).toEqual([
      expect.objectContaining({
        outcome: 'rate-limited',
        suppressed_count: 18,
        suppression_window_ms: 1_000,
        suppression_final: true,
      }),
      expect.objectContaining({ outcome: 'unauthenticated', http_status: 401 }),
    ]);
  });

  it('records a forged orchestrator mandate call as 403 without trusting its claimed role', async () => {
    const { adapter, store } = setup();
    const operation = vi.fn(async () => ({ status: 200, body: { ok: true } }));
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/mandates',
          authorization: `Bearer ${'4'.repeat(64)}`,
          claimedRole: 'principal',
          sessionId: 'session_forged',
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 403, body: { error: 'forbidden' } });
    expect(operation).not.toHaveBeenCalled();
    expect(store.snapshot().accessRecords[0]).toMatchObject({
      authenticated_actor: 'proc:orchestrator',
      claimed_actor: { role: 'principal', session: 'session_forged' },
      outcome: 'forbidden',
      http_status: 403,
    });
  });

  it('rejects cross-world use and a foreign browser origin before the core operation', async () => {
    const { adapter, store } = setup();
    const operation = vi.fn(async () => ({ status: 200, body: { ok: true } }));
    expect(
      (
        await adapter.dispatch(
          {
            method: 'POST',
            pathname: '/w/w-other/proposals',
            authorization: `Bearer ${'4'.repeat(64)}`,
          },
          operation,
        )
      ).status,
    ).toBe(403);
    expect(
      (
        await adapter.dispatch(
          {
            method: 'POST',
            pathname: '/w/w-demo/proposals',
            authorization: `Bearer ${'4'.repeat(64)}`,
            origin: 'http://127.0.0.1:7802',
          },
          operation,
        )
      ).status,
    ).toBe(403);
    expect(operation).not.toHaveBeenCalled();
    expect(store.snapshot().accessRecords).toHaveLength(2);
  });

  it('keeps handoff mint and redemption roles disjoint and origin-guards non-authority redemption', async () => {
    const { adapter, store } = setup();
    const operation = vi.fn(async () => ({ status: 200, body: { ok: true } }));
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/case-session-handoffs',
          authorization: `Bearer ${'4'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 403, body: { error: 'forbidden' } });
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/case-session-handoffs/handoff_one/redeem',
          authorization: `Bearer ${'2'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 403, body: { error: 'forbidden' } });
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/case-session-handoffs/handoff_one/redeem',
          authorization: `Bearer ${'4'.repeat(64)}`,
          origin: 'null',
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 403, body: { error: 'forbidden' } });
    expect(operation).not.toHaveBeenCalled();
    expect(store.snapshot().accessRecords).toHaveLength(3);
  });

  it('passes an allowed process identity to the operation without exposing its token', async () => {
    const { adapter, store } = setup();
    const operation = vi.fn(async (context) => ({ status: 200, body: { actor: context.actor?.credential } }));
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/proposals',
          authorization: `Bearer ${'4'.repeat(64)}`,
          origin: 'http://127.0.0.1:7801',
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 200, body: { actor: 'proc:orchestrator' } });
    expect(operation).toHaveBeenCalledOnce();
    expect(JSON.stringify(operation.mock.calls)).not.toContain('4'.repeat(64));
    expect(store.snapshot().accessRecords).toHaveLength(0);
  });

  it('begins a model call only for the orchestrator and records every attempt', async () => {
    const { adapter, store } = setup();
    const operation = vi.fn(async (context) => ({ status: 200, body: { actor: context.actor?.credential } }));
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/model-calls/begin',
          authorization: `Bearer ${'4'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 200, body: { actor: 'proc:orchestrator' } });
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/model-calls/begin',
          authorization: `Bearer ${'1'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 403, body: { error: 'forbidden' } });
    expect(operation).toHaveBeenCalledOnce();
    expect(store.snapshot().accessRecords).toEqual([
      expect.objectContaining({
        route: 'POST /w/{world_id}/model-calls/begin',
        authenticated_actor: 'proc:orchestrator',
        outcome: 'served',
        http_status: 200,
      }),
      expect.objectContaining({
        route: 'POST /w/{world_id}/model-calls/begin',
        authenticated_actor: 'role:principal',
        outcome: 'forbidden',
        http_status: 403,
      }),
    ]);
  });

  it('origin-guards output admission and records only fixed decision evidence', async () => {
    const { adapter, store } = setup();
    const decision = modelOutputAdmission.parse({
      kind: 'model_output_control',
      case_id: 'case_demo',
      turn_id: 'turn_output',
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
      served_id: 'swiss-ai/apertus-v1.5-70b',
      projection_digest: 'a'.repeat(64),
      projection_item_count: 3,
      output_digest: 'b'.repeat(64),
      model_resolution: 'exact',
      flags: [],
      authority_effect: 'none',
      disposition: 'admitted',
      reasons: [],
      derived_tags: ['conf:case', 'conf:public', 'purpose:grant-assessment'],
    });
    const admission = modelCallAdmission.parse({
      kind: 'model_call_admission',
      call_id: 'mcl_output',
      decision,
    });
    const operation = vi.fn(async () => ({
      status: 200,
      body: admission,
      readLengths: { conversation_items: 3 },
      accessEvidence: admission,
    }));
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/model-outputs/admit',
          authorization: `Bearer ${'4'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({
      status: 200,
      body: { call_id: 'mcl_output', decision: { disposition: 'admitted', authority_effect: 'none' } },
    });
    for (const request of [
      {
        method: 'POST',
        pathname: '/w/w-demo/model-outputs/admit',
        authorization: `Bearer ${'1'.repeat(64)}`,
      },
      {
        method: 'POST',
        pathname: '/w/w-demo/model-outputs/admit',
        authorization: `Bearer ${'4'.repeat(64)}`,
        origin: 'http://127.0.0.1:7802',
      },
    ]) {
      await expect(adapter.dispatch(request, operation)).resolves.toMatchObject({
        status: 403,
        body: { error: 'forbidden' },
      });
    }
    expect(operation).toHaveBeenCalledOnce();
    expect(store.snapshot().accessRecords).toEqual([
      expect.objectContaining({
        route: 'POST /w/{world_id}/model-outputs/admit',
        authenticated_actor: 'proc:orchestrator',
        outcome: 'served',
        operation_evidence: admission,
      }),
      expect.objectContaining({ authenticated_actor: 'role:principal', outcome: 'forbidden' }),
      expect.objectContaining({ authenticated_actor: 'proc:orchestrator', outcome: 'forbidden' }),
    ]);
  });

  it('origin-guards fixed model-call failure reports and rejects every non-orchestrator', async () => {
    const { adapter, store } = setup();
    const failure = modelCallFailedRecord.parse({
      kind: 'model_call_lifecycle',
      world_id: 'w-demo',
      call_id: 'mcl_failed',
      authorization_boot_id: 'authz_boot_http_1',
      case_id: 'case_demo',
      turn_id: 'turn_failed',
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
      projection_digest: 'a'.repeat(64),
      projection_item_count: 3,
      opened_at: '2026-08-02T08:59:59.000Z',
      expires_at: '2026-08-02T09:00:59.000Z',
      state: 'terminal',
      outcome: 'failed',
      provider_disclosure: 'possible',
      completed_at: '2026-08-02T09:00:00.000Z',
      served_id: null,
      output_digest: null,
      failure_reason: 'provider-timeout',
    });
    const operation = vi.fn(async () => ({ status: 200, body: failure, accessEvidence: failure }));
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/model-calls/failures',
          authorization: `Bearer ${'4'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 200, body: { outcome: 'failed', failure_reason: 'provider-timeout' } });
    for (const request of [
      {
        method: 'POST',
        pathname: '/w/w-demo/model-calls/failures',
        authorization: `Bearer ${'5'.repeat(64)}`,
      },
      {
        method: 'POST',
        pathname: '/w/w-demo/model-calls/failures',
        authorization: `Bearer ${'4'.repeat(64)}`,
        origin: 'http://127.0.0.1:7802',
      },
    ]) {
      await expect(adapter.dispatch(request, operation)).resolves.toMatchObject({
        status: 403,
        body: { error: 'forbidden' },
      });
    }
    expect(operation).toHaveBeenCalledOnce();
    expect(JSON.stringify(store.snapshot().accessRecords)).not.toContain('error detail');
    expect(store.snapshot().accessRecords).toEqual([
      expect.objectContaining({
        route: 'POST /w/{world_id}/model-calls/failures',
        authenticated_actor: 'proc:orchestrator',
        outcome: 'served',
        operation_evidence: failure,
      }),
      expect.objectContaining({ authenticated_actor: 'proc:services_host', outcome: 'forbidden' }),
      expect.objectContaining({ authenticated_actor: 'proc:orchestrator', outcome: 'forbidden' }),
    ]);
  });

  it('records dynamic role refusals and successful record-family reads', async () => {
    const { adapter, store } = setup();
    await adapter.dispatch(
      {
        method: 'POST',
        pathname: '/w/w-demo/escalations/esc_1/disposition',
        authorization: `Bearer ${'2'.repeat(64)}`,
      },
      async ({ params }) => ({ status: 403, body: { defect: 'wrong-role', escalation_id: params.id } }),
    );
    await adapter.dispatch(
      {
        method: 'GET',
        pathname: '/w/w-demo/records/action',
        authorization: `Bearer ${'1'.repeat(64)}`,
      },
      async () => ({ status: 200, body: { entries: [] }, readLengths: { action: 0, access: 1 } }),
    );
    expect(store.snapshot().accessRecords).toEqual([
      expect.objectContaining({ outcome: 'forbidden', http_status: 403 }),
      expect.objectContaining({ outcome: 'served', http_status: 200, read_lengths: { action: 0, access: 1 } }),
    ]);
  });

  it('matches fixed console assets before the shell and supplies only validated named parameters', async () => {
    const { adapter } = setup();
    const consoleOperation = vi.fn(async ({ params, routeId }) => ({ status: 200, body: { params, routeId } }));
    await expect(adapter.dispatch({ method: 'GET', pathname: '/console' }, consoleOperation)).resolves.toMatchObject({
      status: 200,
      body: { params: {}, routeId: 'console.shell' },
    });
    await expect(adapter.dispatch({ method: 'GET', pathname: '/console/app.js' }, consoleOperation)).resolves.toMatchObject({
      status: 200,
      body: { params: {}, routeId: 'console.script' },
    });
    await expect(adapter.dispatch({ method: 'GET', pathname: '/console/styles.css' }, consoleOperation)).resolves.toMatchObject({
      status: 200,
      body: { params: {}, routeId: 'console.style' },
    });
    await expect(
      adapter.dispatch({ method: 'GET', pathname: '/console/runtime-config.json' }, consoleOperation),
    ).resolves.toMatchObject({
      status: 200,
      body: { params: {}, routeId: 'console.config' },
    });
    const recordOperation = vi.fn(async ({ params }) => ({ status: 200, body: { params } }));
    await expect(
      adapter.dispatch(
        {
          method: 'GET',
          pathname: '/w/w-demo/records',
          authorization: `Bearer ${'1'.repeat(64)}`,
        },
        recordOperation,
      ),
    ).resolves.toMatchObject({ status: 200, body: { params: { world_id: 'w-demo' } } });
  });

  it('lets the principal read fixed model-card evidence without opening a mutation route', async () => {
    const { adapter } = setup();
    const operation = vi.fn(async ({ actor }) => ({ status: 200, body: { actor: actor?.credential } }));
    await expect(
      adapter.dispatch(
        {
          method: 'GET',
          pathname: '/w/w-demo/mandates/mdt_demo/approved-models',
          authorization: `Bearer ${'1'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 200, body: { actor: 'role:principal' } });
    expect(operation).toHaveBeenCalledOnce();
  });

  it('returns 404 for an unregistered route without invoking or fabricating evidence', async () => {
    const { adapter, store } = setup();
    const operation = vi.fn(async () => ({ status: 200, body: { ok: true } }));
    await expect(
      adapter.dispatch(
        {
          method: 'POST',
          pathname: '/w/w-demo/authority-backdoor',
          authorization: `Bearer ${'1'.repeat(64)}`,
        },
        operation,
      ),
    ).resolves.toMatchObject({ status: 404, body: { error: 'not-found' } });
    expect(operation).not.toHaveBeenCalled();
    expect(store.snapshot().accessRecords).toHaveLength(0);
  });
});
