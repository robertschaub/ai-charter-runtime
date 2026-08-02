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

function setup(options: { credentials?: readonly CredentialBinding[]; registeredRouteIds?: readonly string[] } = {}) {
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

  it('records dynamic role refusals and successful record-family reads', async () => {
    const { adapter, store } = setup();
    await adapter.dispatch(
      {
        method: 'POST',
        pathname: '/w/w-demo/escalations/esc_1/disposition',
        authorization: `Bearer ${'2'.repeat(64)}`,
      },
      async () => ({ status: 403, body: { defect: 'wrong-role' } }),
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
