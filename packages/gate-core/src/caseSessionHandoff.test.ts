// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import {
  CaseSessionHandoffError,
  CaseSessionHandoffService,
} from './caseSessionHandoff.js';
import { sha256Hex } from './hash.js';
import { WalStore, type TransactionActor } from './walStore.js';

const roots: string[] = [];
const stores: WalStore[] = [];
const CASE_OFFICER: TransactionActor = { credential: 'role:case_officer', claimed_role: 'case_officer' };
const ORCHESTRATOR: TransactionActor = { credential: 'proc:orchestrator', claimed_role: null };

afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function openStore(root: string, bootId: string, now: () => string): WalStore {
  const store = WalStore.open({
    recordsRoot: root,
    worldId: 'w-demo',
    runId: `run_${bootId}`,
    bootId,
    policyVersion: 'policy-test',
    policyContentDigest: 'a'.repeat(64),
    evaluatorBuildDigest: 'b'.repeat(64),
    now,
  });
  stores.push(store);
  return store;
}

function setup(options: { readonly bootId?: string; readonly ttlMs?: number } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'case-handoff-'));
  roots.push(root);
  let at = '2026-08-03T10:00:00.000Z';
  let next = 0;
  const store = openStore(root, options.bootId ?? 'authz_boot_one', () => at);
  const service = new CaseSessionHandoffService({
    store,
    worldId: 'w-demo',
    authorizationBootId: options.bootId ?? 'authz_boot_one',
    targetOrigin: 'http://127.0.0.1:7802',
    caseExists: (caseId) => caseId === 'case_demo',
    ttlMs: options.ttlMs,
    randomCode: () => `${(++next).toString(16).padStart(64, '0')}`,
    nextHandoffId: () => `handoff_${next + 1}`,
  });
  return { root, store, service, setAt: (value: string) => (at = value) };
}

function redeemInput(minted: Awaited<ReturnType<CaseSessionHandoffService['mint']>>) {
  const { expires_at: ignored, ...input } = minted;
  void ignored;
  return { ...input, session_id: `session_${minted.handoff_id}` };
}

describe('ADR-002 durable case-session handoffs', () => {
  it('persists only the code digest and consumes the exact binding once', async () => {
    const { root, store, service } = setup();
    const minted = await service.mint('case_demo', CASE_OFFICER);
    const stored = store.snapshot().caseSessionHandoffs.get(minted.handoff_id);
    expect(stored).toMatchObject({
      world_id: 'w-demo',
      case_id: 'case_demo',
      role: 'case_officer',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_one',
      code_digest: sha256Hex(minted.handoff_code),
      state: 'issued',
      consumed_at: null,
    });
    expect(JSON.stringify(stored)).not.toContain(minted.handoff_code);
    expect(readFileSync(join(root, 'w-demo', 'wal.jsonl'), 'utf8')).not.toContain(minted.handoff_code);

    await expect(service.redeem(redeemInput(minted), ORCHESTRATOR)).resolves.toMatchObject({
      handoff_id: minted.handoff_id,
      world_id: 'w-demo',
      case_id: 'case_demo',
      role: 'case_officer',
    });
    expect(store.snapshot().caseSessionHandoffs.get(minted.handoff_id)).toMatchObject({
      state: 'consumed',
      consumed_at: '2026-08-03T10:00:00.000Z',
    });
    await expect(service.redeem(redeemInput(minted), ORCHESTRATOR)).rejects.toMatchObject({
      code: 'handoff-refused',
    });
  });

  it('refuses every actor or binding expansion without consuming the handoff', async () => {
    const { store, service } = setup();
    await expect(
      service.mint('case_demo', { credential: 'proc:orchestrator', claimed_role: null }),
    ).rejects.toBeInstanceOf(CaseSessionHandoffError);
    await expect(service.mint('case_unknown', CASE_OFFICER)).rejects.toMatchObject({ code: 'case-refused' });
    const minted = await service.mint('case_demo', CASE_OFFICER);
    const base = redeemInput(minted);
    const mismatches = [
      { ...base, handoff_code: 'f'.repeat(64) },
      { ...base, world_id: 'w-other' },
      { ...base, case_id: 'case_other' },
      { ...base, target_origin: 'http://127.0.0.1:9999' },
      { ...base, authorization_boot_id: 'authz_boot_other' },
    ];
    for (const input of mismatches) {
      await expect(service.redeem(input, ORCHESTRATOR)).rejects.toMatchObject({ code: 'handoff-refused' });
    }
    await expect(service.redeem(base, CASE_OFFICER)).rejects.toMatchObject({ code: 'actor-refused' });
    expect(store.snapshot().caseSessionHandoffs.get(minted.handoff_id)?.state).toBe('issued');
  });

  it('serializes concurrent redemption so exactly one caller receives a claim', async () => {
    const { service } = setup();
    const minted = await service.mint('case_demo', CASE_OFFICER);
    const results = await Promise.allSettled([
      service.redeem(redeemInput(minted), ORCHESTRATOR),
      service.redeem(redeemInput(minted), ORCHESTRATOR),
    ]);
    expect(results.filter((result) => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter((result) => result.status === 'rejected')).toHaveLength(1);
  });

  it('does not consume a handoff when its requested session provenance id collides', async () => {
    const { store, service } = setup();
    const first = await service.mint('case_demo', CASE_OFFICER);
    const second = await service.mint('case_demo', CASE_OFFICER);
    const sessionId = 'session_collision';
    await expect(service.redeem({ ...redeemInput(first), session_id: sessionId }, ORCHESTRATOR)).resolves.toMatchObject({
      handoff_id: first.handoff_id,
    });
    await expect(
      service.redeem({ ...redeemInput(second), session_id: sessionId }, ORCHESTRATOR),
    ).rejects.toMatchObject({ code: 'handoff-refused' });
    expect(store.snapshot().caseSessionHandoffs.get(second.handoff_id)).toMatchObject({
      state: 'issued',
      consumed_at: null,
    });
    expect(store.snapshot().caseSessionProvenance.get(sessionId)).toMatchObject({
      handoff_id: first.handoff_id,
      state: 'active',
    });
  });

  it('durably closes the authorization-owned session receipt exactly once', async () => {
    const { store, service } = setup();
    const minted = await service.mint('case_demo', CASE_OFFICER);
    const input = redeemInput(minted);
    await service.redeem(input, ORCHESTRATOR);
    await expect(service.closeSession(input.session_id, CASE_OFFICER)).rejects.toMatchObject({ code: 'actor-refused' });
    await expect(service.closeSession(input.session_id, ORCHESTRATOR)).resolves.toEqual({
      session_id: input.session_id,
      state: 'closed',
      closed_at: '2026-08-03T10:00:00.000Z',
    });
    expect(store.snapshot().caseSessionProvenance.get(input.session_id)?.state).toBe('expired');
    await expect(service.closeSession(input.session_id, ORCHESTRATOR)).rejects.toMatchObject({
      code: 'handoff-refused',
    });
  });

  it('expires elapsed handoffs lazily and prior-boot handoffs before a new listener can bind', async () => {
    const elapsed = setup({ ttlMs: 1_000 });
    const elapsedMint = await elapsed.service.mint('case_demo', CASE_OFFICER);
    elapsed.setAt('2026-08-03T10:00:01.000Z');
    await expect(elapsed.service.redeem(redeemInput(elapsedMint), ORCHESTRATOR)).rejects.toMatchObject({
      code: 'handoff-refused',
    });
    expect(elapsed.store.snapshot().caseSessionHandoffs.get(elapsedMint.handoff_id)?.state).toBe('expired');

    const prior = setup();
    const priorMint = await prior.service.mint('case_demo', CASE_OFFICER);
    prior.store.close();
    stores.splice(stores.indexOf(prior.store), 1);
    const restartedStore = openStore(prior.root, 'authz_boot_two', () => '2026-08-03T10:00:00.001Z');
    const restarted = new CaseSessionHandoffService({
      store: restartedStore,
      worldId: 'w-demo',
      authorizationBootId: 'authz_boot_two',
      targetOrigin: 'http://127.0.0.1:7802',
      caseExists: () => true,
    });
    await expect(restarted.expireIssued()).resolves.toBe(1);
    expect(restartedStore.snapshot().caseSessionHandoffs.get(priorMint.handoff_id)?.state).toBe('expired');
  });
});
