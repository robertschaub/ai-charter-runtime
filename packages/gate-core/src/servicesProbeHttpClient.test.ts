// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it, vi } from 'vitest';

import { ServicesProbeHttpClient } from './servicesProbeHttpClient.js';

const key = 'a'.repeat(64);

function recordedProbe(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    state: 'recorded',
    boot_id: 'services_boot_2',
    ledger_id: 'ledger_1',
    record: {
      version: 1,
      world_id: 'w-demo',
      services_host_boot_id: 'services_boot_1',
      services_ledger_id: 'ledger_1',
      effect_id: 'eff_1',
      idempotency_key: key,
      ruling_id: 'rul_1',
      frozen_proposal_hash: 'd'.repeat(64),
      effect_request_digest: 'b'.repeat(64),
      service: 'filing',
      action_class: 'grant-filing',
      intent: {
        world_id: 'w-demo',
        ruling_id: 'rul_1',
        frozen_proposal_hash: 'd'.repeat(64),
        service: 'filing',
        action_class: 'grant-filing',
        target: { recipient: 'synthetic-office', resource: 'synthetic-record' },
        exact_parameters: { amount_minor_units: 1 },
        data_to_be_disclosed: [],
      },
      outcome: 'success',
      recorded_at: '2026-08-02T09:00:00.000Z',
      ...overrides,
    },
  };
}

describe('services reconciliation probe client', () => {
  it('returns the closed commitment projection from a bound ledger response', async () => {
    const client = new ServicesProbeHttpClient({
      origin: 'http://127.0.0.1:7803',
      token: '1'.repeat(64),
      worldId: 'w-demo',
      fetchImplementation: vi.fn(async () => new Response(JSON.stringify(recordedProbe()), { status: 200 })),
    });

    await expect(client.probe(key)).resolves.toMatchObject({
      state: 'recorded',
      boot_id: 'services_boot_2',
      record: { world_id: 'w-demo', idempotency_key: key, services_ledger_id: 'ledger_1' },
    });
  });

  it('fails closed when the returned world, key, or ledger identity does not bind to the probe', async () => {
    for (const overrides of [
      { world_id: 'other-world' },
      { idempotency_key: 'c'.repeat(64) },
      { services_ledger_id: 'ledger_other' },
    ]) {
      const client = new ServicesProbeHttpClient({
        origin: 'http://127.0.0.1:7803',
        token: '1'.repeat(64),
        worldId: 'w-demo',
        fetchImplementation: vi.fn(
          async () => new Response(JSON.stringify(recordedProbe(overrides)), { status: 200 }),
        ),
      });
      await expect(client.probe(key)).rejects.toThrow('did not match');
    }
  });

  it('accepts only the exact cited synthetic registry retrieval', async () => {
    const fetchImplementation = vi.fn(async (input: string | URL | Request) => {
      expect(String(input)).toContain('/w/w-demo/registry-records/reg%3ACH-0042');
      return new Response(
        JSON.stringify({
          kind: 'registry_record',
          id: 'reg:CH-0042',
          retrieved_at: '2026-08-01T09:14:02.000Z',
          resolved_at: '2026-08-03T10:00:00.000Z',
          content_digest: 'd'.repeat(64),
        }),
        { status: 200 },
      );
    });
    const client = new ServicesProbeHttpClient({
      origin: 'http://127.0.0.1:7803',
      token: '1'.repeat(64),
      worldId: 'w-demo',
      fetchImplementation,
    });
    await expect(
      client.resolveRegistryEvidence({
        kind: 'registry_record',
        id: 'reg:CH-0042',
        retrieved_at: '2026-08-01T09:14:02.000Z',
      }),
    ).resolves.toMatchObject({ id: 'reg:CH-0042', content_digest: 'd'.repeat(64) });

    const mismatch = new ServicesProbeHttpClient({
      origin: 'http://127.0.0.1:7803',
      token: '1'.repeat(64),
      worldId: 'w-demo',
      fetchImplementation: vi.fn(async () =>
        new Response(
          JSON.stringify({
            kind: 'registry_record',
            id: 'reg:CH-0042',
            retrieved_at: '2026-08-01T09:14:03.000Z',
            resolved_at: '2026-08-03T10:00:00.000Z',
            content_digest: 'd'.repeat(64),
          }),
          { status: 200 },
        ),
      ),
    });
    await expect(
      mismatch.resolveRegistryEvidence({
        kind: 'registry_record',
        id: 'reg:CH-0042',
        retrieved_at: '2026-08-01T09:14:02.000Z',
      }),
    ).resolves.toBeNull();
  });
});
