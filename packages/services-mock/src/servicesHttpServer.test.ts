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
    const server = new ServicesHttpServer({
      services: { execute: vi.fn() } as unknown as MockServicesHost,
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
  });
});
