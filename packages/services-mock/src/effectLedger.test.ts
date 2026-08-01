// SPDX-License-Identifier: MIT
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  commitToken,
  createEmbeddedMac,
  digestFor,
  Keyring,
  type CommitToken,
  type EffectIntent,
} from 'gate-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { EffectLedger, EffectLedgerError } from './effectLedger.js';

const KEY_ID = 'hmac-test';
const KEY = 'a'.repeat(64);
const HASH = 'b'.repeat(64);
const IDEMPOTENCY_KEY = 'c'.repeat(64);
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function intent(overrides: Partial<EffectIntent> = {}): EffectIntent {
  return {
    world_id: 'w-demo',
    ruling_id: 'rul_1',
    frozen_proposal_hash: HASH,
    service: 'filing',
    action_class: 'grant-filing',
    target: { recipient: 'grant-office', resource: 'application-42' },
    exact_parameters: { amount_minor_units: 50, reference: 'case-1' },
    data_to_be_disclosed: ['applicant_name'],
    ...overrides,
  };
}

function tokenFor(keyring: Keyring, value: EffectIntent, overrides: Partial<CommitToken> = {}): CommitToken {
  const unsigned = {
    world_id: value.world_id,
    effect_id: 'eff_1',
    ruling_id: value.ruling_id,
    frozen_proposal_hash: value.frozen_proposal_hash,
    effect_request_digest: digestFor('effect-intent', value),
    idempotency_key: IDEMPOTENCY_KEY,
    service: value.service,
    action_class: value.action_class,
    expires_at: '2026-08-01T09:00:05.000Z',
    ...overrides,
  };
  return commitToken.parse(createEmbeddedMac(keyring, 'commit-token', unsigned, 'mac'));
}

function harness() {
  const root = mkdtempSync(join(tmpdir(), 'services-mock-m3-'));
  roots.push(root);
  let now = '2026-08-01T09:00:00.000Z';
  const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);
  const ledger = new EffectLedger({
    recordsRoot: root,
    worldId: 'w-demo',
    bootId: 'services_boot_1',
    keyring,
    now: () => now,
  });
  return { root, keyring, ledger, setNow: (value: string) => (now = value) };
}

describe('services-host effect ledger', () => {
  it('rejects bypass and post-allow mutation before invoking the mock effect', () => {
    const value = harness();
    const requested = intent();
    const token = tokenFor(value.keyring, requested);
    const execute = vi.fn(() => ({ outcome: 'success' as const }));

    expect(value.ledger.execute({}, requested, execute)).toEqual({ accepted: false, reason: 'malformed' });
    expect(
      value.ledger.execute(token, intent({ exact_parameters: { amount_minor_units: 51 } }), execute),
    ).toEqual({ accepted: false, reason: 'binding-mismatch' });
    expect(execute).not.toHaveBeenCalled();
    expect(value.ledger.probe(IDEMPOTENCY_KEY)).toEqual({
      state: 'absent',
      boot_id: 'services_boot_1',
      ledger_id: value.ledger.ledgerId,
    });
  });

  it('commits the effect once and serves the identical result on retry, even after token expiry', () => {
    const value = harness();
    const requested = intent();
    const token = tokenFor(value.keyring, requested);
    const execute = vi.fn(() => ({ outcome: 'success' as const, detail: 'synthetic filing accepted' }));

    const first = value.ledger.execute(token, requested, execute);
    expect(first.accepted && first.delivery).toBe('executed');
    expect(execute).toHaveBeenCalledOnce();
    value.setNow('2026-08-01T09:01:00.000Z');
    const retry = value.ledger.execute(token, requested, execute);
    expect(retry).toEqual({ ...(first as object), delivery: 'retry' });
    expect(execute).toHaveBeenCalledOnce();
    expect(value.ledger.probe(IDEMPOTENCY_KEY)).toEqual({
      state: 'recorded',
      boot_id: 'services_boot_1',
      ledger_id: value.ledger.ledgerId,
      record: first.accepted ? first.record : undefined,
    });
  });

  it('denies a new effect at the exact token expiry boundary', () => {
    const value = harness();
    const requested = intent();
    const token = tokenFor(value.keyring, requested);
    value.setNow('2026-08-01T09:00:05.000Z');

    expect(value.ledger.execute(token, requested, () => ({ outcome: 'success' }))).toEqual({
      accepted: false,
      reason: 'expired',
    });
    expect(value.ledger.probe(IDEMPOTENCY_KEY).state).toBe('absent');
  });

  it('removes an uncommitted torn temp at startup without inventing an effect', () => {
    const root = mkdtempSync(join(tmpdir(), 'services-mock-crash-'));
    roots.push(root);
    const directory = join(root, 'w-demo', 'effects');
    mkdirSync(directory, { recursive: true });
    const stale = join(directory, `${IDEMPOTENCY_KEY}.crashed.tmp`);
    writeFileSync(stale, '{"partial":');
    const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);

    const ledger = new EffectLedger({
      recordsRoot: root,
      worldId: 'w-demo',
      bootId: 'services_boot_2',
      keyring,
      now: () => '2026-08-01T09:00:00.000Z',
    });

    expect(existsSync(stale)).toBe(false);
    expect(ledger.probe(IDEMPOTENCY_KEY)).toEqual({
      state: 'absent',
      boot_id: 'services_boot_2',
      ledger_id: ledger.ledgerId,
    });
  });

  it('preserves ledger identity across restart and changes it after storage replacement', () => {
    const root = mkdtempSync(join(tmpdir(), 'services-mock-ledger-id-'));
    roots.push(root);
    const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);
    const first = new EffectLedger({
      recordsRoot: root,
      worldId: 'w-demo',
      bootId: 'services_boot_1',
      keyring,
    });
    const restarted = new EffectLedger({
      recordsRoot: root,
      worldId: 'w-demo',
      bootId: 'services_boot_2',
      keyring,
    });
    expect(restarted.ledgerId).toBe(first.ledgerId);

    const effectsDirectory = join(root, 'w-demo', 'effects');
    rmSync(effectsDirectory, { recursive: true });
    const replaced = new EffectLedger({
      recordsRoot: root,
      worldId: 'w-demo',
      bootId: 'services_boot_3',
      keyring,
    });
    expect(replaced.ledgerId).not.toBe(first.ledgerId);
  });

  it('fails closed on a corrupt committed ledger entry', () => {
    const value = harness();
    const path = join(value.root, 'w-demo', 'effects', `${IDEMPOTENCY_KEY}.json`);
    writeFileSync(path, '{"partial":');

    expect(() => value.ledger.probe(IDEMPOTENCY_KEY)).toThrowError(
      expect.objectContaining<Partial<EffectLedgerError>>({ code: 'corrupt-ledger' }),
    );
  });

  it('rejects an unsafe world id before resolving an effects directory', () => {
    const root = mkdtempSync(join(tmpdir(), 'services-mock-world-'));
    roots.push(root);
    const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);

    expect(
      () =>
        new EffectLedger({
          recordsRoot: root,
          worldId: '../escaped',
          bootId: 'services_boot_1',
          keyring,
        }),
    ).toThrow();
  });
});
