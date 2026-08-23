// SPDX-License-Identifier: MIT
import { afterEach, describe, expect, it, vi } from 'vitest';

import type { ServicesAccessDenial } from './authorizationHttpClient.js';
import type { EffectLedger } from './effectLedger.js';
import type { MockServicesHost } from './servicesHost.js';
import { ServicesHttpServer } from './servicesHttpServer.js';

const servers: ServicesHttpServer[] = [];

afterEach(async () => {
  for (const server of servers.splice(0)) await server.close();
});

describe('services HTTP denial evidence', () => {
  it('records authenticated refusals and bounds unauthenticated detail before responding', async () => {
    const denials: ServicesAccessDenial[] = [];
    const accessRecorder = {
      recordAccessDenial: vi.fn(async (_worldId: string, denial: ServicesAccessDenial) => {
        denials.push(denial);
        return `acc_${denials.length}`;
      }),
    };
    let now = 0;
    const orchestratorToken = '1'.repeat(64);
    const authorizationToken = '2'.repeat(64);
    const executePrepared = vi.fn(async (_worldId: string, preparationId: string) => ({
      execution_preparation_id: preparationId,
      state: 'commit-denied' as const,
      effect_outcome: null,
      recorded_at: null,
    }));
    const server = new ServicesHttpServer({
      services: { execute: vi.fn(), executePrepared } as unknown as MockServicesHost,
      ledger: { probe: vi.fn() } as unknown as EffectLedger,
      worldId: 'w-demo',
      orchestratorToken,
      authorizationToken,
      accessRecorder,
      host: '127.0.0.1',
      port: 0,
      unauthenticatedDetailLimit: 2,
      unauthenticatedWindowMs: 1_000,
      nowMilliseconds: () => now,
    });
    servers.push(server);
    const address = await server.listen();
    const execute = new URL('/w/w-demo/services/filing/execute', address.origin);
    const probe = new URL(`/w/w-demo/effects/${'a'.repeat(64)}`, address.origin);
    const registry = new URL('/w/w-demo/registry-records/reg%3ACH-0042', address.origin);
    const native = new URL('/w/w-demo/execution-preparations/xpr_native/execute', address.origin);
    const post = (token: string) =>
      fetch(execute, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: '{}',
      });

    expect((await post('3'.repeat(64))).status).toBe(401);
    expect((await post('3'.repeat(64))).status).toBe(401);
    expect((await post('3'.repeat(64))).status).toBe(429);
    expect(denials.map((denial) => denial.outcome)).toEqual([
      'unauthenticated',
      'unauthenticated',
      'rate-limited',
    ]);

    now = 1_000;
    expect((await post('3'.repeat(64))).status).toBe(401);
    expect(denials.at(-2)).toMatchObject({
      outcome: 'rate-limited',
      suppressed_count: 1,
      suppression_final: true,
    });
    expect(denials.at(-1)).toMatchObject({ outcome: 'unauthenticated', http_status: 401 });

    expect((await post(authorizationToken)).status).toBe(403);
    expect(denials.at(-1)).toMatchObject({
      route: 'services.execute',
      authenticated_actor: 'proc:authz',
      outcome: 'forbidden',
      http_status: 403,
    });
    expect((await fetch(native, {
      method: 'POST',
      headers: { authorization: `Bearer ${authorizationToken}`, 'content-type': 'application/json' },
      body: '{}',
    })).status).toBe(403);
    expect(denials.at(-1)).toMatchObject({ route: 'services.native-execute', authenticated_actor: 'proc:authz' });
    expect((await fetch(native, {
      method: 'POST',
      headers: { authorization: `Bearer ${orchestratorToken}`, origin: 'http://127.0.0.1:7802', 'content-type': 'application/json' },
      body: '{}',
    })).status).toBe(403);
    expect(executePrepared).not.toHaveBeenCalled();
    expect((await fetch(native, {
      method: 'POST',
      headers: { authorization: `Bearer ${orchestratorToken}`, 'content-type': 'application/json' },
      body: JSON.stringify({ service: 'filing' }),
    })).status).toBe(422);
    const nativeResult = await fetch(native, {
      method: 'POST',
      headers: { authorization: `Bearer ${orchestratorToken}`, 'content-type': 'application/json' },
      body: '{}',
    });
    expect(nativeResult.status).toBe(200);
    await expect(nativeResult.json()).resolves.toEqual({
      execution_preparation_id: 'xpr_native',
      state: 'commit-denied',
      effect_outcome: null,
      recorded_at: null,
    });
    expect(executePrepared).toHaveBeenCalledOnce();
    expect((await fetch(probe, {
      headers: { authorization: `Bearer ${authorizationToken}`, origin: 'null' },
    })).status).toBe(403);
    expect((await fetch(registry, {
      headers: { authorization: `Bearer ${authorizationToken}`, origin: 'http://127.0.0.1:7801' },
    })).status).toBe(403);
    expect(
      (
        await fetch(probe, {
          headers: { authorization: `Bearer ${orchestratorToken}` },
        })
      ).status,
    ).toBe(403);
    expect(denials.at(-1)).toMatchObject({
      route: 'services.effect-probe',
      authenticated_actor: 'proc:orchestrator',
      outcome: 'forbidden',
      http_status: 403,
    });
    expect(
      (
        await fetch(registry, {
          headers: { authorization: `Bearer ${orchestratorToken}` },
        })
      ).status,
    ).toBe(403);
    expect(denials.at(-1)).toMatchObject({
      route: 'services.registry-read',
      authenticated_actor: 'proc:orchestrator',
      outcome: 'forbidden',
    });
    const evidence = await fetch(registry, {
      headers: { authorization: `Bearer ${authorizationToken}` },
    });
    expect(evidence.status).toBe(200);
    const evidenceBody = await evidence.json();
    expect(evidenceBody).toMatchObject({
      kind: 'registry_record',
      id: 'reg:CH-0042',
      retrieved_at: '2026-08-01T09:14:02.000Z',
      content_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
    });
    expect(evidenceBody).not.toHaveProperty('content');
    expect(
      (
        await fetch(new URL('/w/w-demo/registry-records/reg%3ACH-9999', address.origin), {
          headers: { authorization: `Bearer ${authorizationToken}` },
        })
      ).status,
    ).toBe(404);
  });
});
