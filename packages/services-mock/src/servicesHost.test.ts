// SPDX-License-Identifier: MIT
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  commitToken,
  createEmbeddedMac,
  digestFor,
  Keyring,
  type AuthorizationCore,
  type EffectIntent,
} from 'gate-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { EffectLedger } from './effectLedger.js';
import { MockServicesHost } from './servicesHost.js';

const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('mock services process facade', () => {
  it('keeps the commit token out of its response and serves same-process retries without re-execution', async () => {
    const root = mkdtempSync(join(tmpdir(), 'services-host-m3-'));
    roots.push(root);
    let now = '2026-08-01T09:00:00.000Z';
    const keyring = new Keyring(new Map([['hmac-test', 'a'.repeat(64)]]), 'hmac-test');
    const intent: EffectIntent = {
      world_id: 'w-demo',
      ruling_id: 'rul_1',
      frozen_proposal_hash: 'b'.repeat(64),
      service: 'filing',
      action_class: 'grant-filing',
      target: { recipient: 'grant-office', resource: 'application-42' },
      exact_parameters: { amount_minor_units: 50 },
      data_to_be_disclosed: ['applicant_name'],
    };
    const token = commitToken.parse(
      createEmbeddedMac(
        keyring,
        'commit-token',
        {
          world_id: intent.world_id,
          effect_id: 'eff_1',
          ruling_id: intent.ruling_id,
          frozen_proposal_hash: intent.frozen_proposal_hash,
          effect_request_digest: digestFor('proposal', intent),
          idempotency_key: 'c'.repeat(64),
          service: intent.service,
          action_class: intent.action_class,
          expires_at: '2026-08-01T09:00:05.000Z',
        },
        'mac',
      ),
    );
    const commitVerify = vi.fn(async () => ({
      ok: true as const,
      token,
      commitmentId: 'cmt_1',
      recordEntryId: 'rec_1',
    }));
    const reportEffectOutcome = vi.fn(async () => ({
      accepted: true as const,
      status: 'recorded' as const,
      recordEntryId: 'rec_2',
    }));
    const authorization = { commitVerify, reportEffectOutcome } as unknown as Pick<
      AuthorizationCore,
      'commitVerify' | 'reportEffectOutcome'
    >;
    const handler = vi.fn(() => ({ outcome: 'success' as const, detail: 'synthetic' }));
    const host = new MockServicesHost(
      new EffectLedger({
        recordsRoot: root,
        worldId: 'w-demo',
        bootId: 'services_boot_1',
        keyring,
        now: () => now,
      }),
      authorization,
      { 'filing:grant-filing': handler },
    );

    const first = await host.execute('rul_1', intent);
    now = '2026-08-01T09:01:00.000Z';
    const retry = await host.execute('rul_1', intent);

    expect(first).toMatchObject({ ok: true, delivery: 'executed' });
    expect(retry).toMatchObject({ ok: true, delivery: 'retry' });
    expect(first).not.toHaveProperty('token');
    expect(retry).not.toHaveProperty('token');
    expect(commitVerify).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledOnce();
    expect(reportEffectOutcome).toHaveBeenCalledTimes(2);
  });

  it('recovers when the authorization service disappears after the durable effect but before outcome reporting', async () => {
    const root = mkdtempSync(join(tmpdir(), 'services-host-crash-m3-'));
    roots.push(root);
    const keyring = new Keyring(new Map([['hmac-test', 'a'.repeat(64)]]), 'hmac-test');
    const intent: EffectIntent = {
      world_id: 'w-demo',
      ruling_id: 'rul_2',
      frozen_proposal_hash: 'd'.repeat(64),
      service: 'filing',
      action_class: 'grant-filing',
      target: { recipient: 'grant-office', resource: 'application-42' },
      exact_parameters: { amount_minor_units: 50 },
      data_to_be_disclosed: ['applicant_name'],
    };
    const token = commitToken.parse(
      createEmbeddedMac(
        keyring,
        'commit-token',
        {
          world_id: intent.world_id,
          effect_id: 'eff_2',
          ruling_id: intent.ruling_id,
          frozen_proposal_hash: intent.frozen_proposal_hash,
          effect_request_digest: digestFor('proposal', intent),
          idempotency_key: 'e'.repeat(64),
          service: intent.service,
          action_class: intent.action_class,
          expires_at: '2026-08-01T09:00:05.000Z',
        },
        'mac',
      ),
    );
    const commitVerify = vi.fn(async () => ({
      ok: true as const,
      token,
      commitmentId: 'cmt_2',
      recordEntryId: 'rec_3',
    }));
    const reportEffectOutcome = vi
      .fn()
      .mockRejectedValueOnce(new Error('simulated authorization-service crash'))
      .mockResolvedValue({ accepted: true, status: 'retry-recorded', recordEntryId: 'rec_4' });
    const authorization = { commitVerify, reportEffectOutcome } as unknown as Pick<
      AuthorizationCore,
      'commitVerify' | 'reportEffectOutcome'
    >;
    const handler = vi.fn(() => ({ outcome: 'success' as const }));
    const ledger = new EffectLedger({
      recordsRoot: root,
      worldId: 'w-demo',
      bootId: 'services_boot_1',
      keyring,
      now: () => '2026-08-01T09:00:00.000Z',
    });
    const host = new MockServicesHost(ledger, authorization, { 'filing:grant-filing': handler });

    await expect(host.execute('rul_2', intent)).rejects.toThrow('simulated authorization-service crash');
    expect(ledger.probe(token.idempotency_key).state).toBe('recorded');
    await expect(host.execute('rul_2', intent)).resolves.toMatchObject({ ok: true, delivery: 'retry' });
    expect(commitVerify).toHaveBeenCalledOnce();
    expect(handler).toHaveBeenCalledOnce();
    expect(reportEffectOutcome).toHaveBeenCalledTimes(2);
  });
});
