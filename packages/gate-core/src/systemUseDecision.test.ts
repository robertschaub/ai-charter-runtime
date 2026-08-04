// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { bindMandate } from './authorizationCore.js';
import { Keyring } from './keyring.js';
import type { Mandate, SystemUseDecisionRecord } from './schemas/index.js';
import { modelCallBeginRequest, systemUseDecisionRecord } from './schemas/index.js';
import { applyWorldTransaction, createWorldState } from './state.js';
import {
  SystemUseDecisionError,
  SystemUseDecisionService,
  resolveCurrentSystemUseDecision,
  systemUseDecisionDigest,
  type SystemUseEnvironment,
} from './systemUseDecision.js';
import { WalStore } from './walStore.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const DEMO = join(ROOT, 'fixtures', 'demo');
const KEYRING = new Keyring(new Map([['hmac-test', 'a'.repeat(64)]]), 'hmac-test');
const AUTHZ = { credential: 'proc:authz', claimed_role: null } as const;
const AT = '2026-08-04T09:00:00.000Z';
const POLICY_VERSION = '2026-08-02.1';
const ENVIRONMENT: SystemUseEnvironment = {
  systemId: 'ai-charter-runtime-poc',
  useCaseId: 'public-grant-decision',
  jurisdictions: ['synthetic-demo'],
  hardConditions: { 'no-external-effect': true, 'synthetic-data-only': true },
};
const roots: string[] = [];
const stores: WalStore[] = [];

afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function json(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

function fixture(): SystemUseDecisionRecord {
  return systemUseDecisionRecord.parse(json(join(DEMO, 'system-use-decision.json')));
}

function demoMandate(): Mandate {
  return bindMandate(KEYRING, json(join(DEMO, 'mandate.json')) as Omit<Mandate, 'binding'>);
}

function resign(value: SystemUseDecisionRecord): SystemUseDecisionRecord {
  const unsigned = systemUseDecisionRecord.parse({
    ...value,
    trace: { ...value.trace, record_digest: '0'.repeat(64) },
  });
  return systemUseDecisionRecord.parse({
    ...unsigned,
    trace: { ...unsigned.trace, record_digest: systemUseDecisionDigest(unsigned) },
  });
}

function withRecord(record: SystemUseDecisionRecord) {
  const state = createWorldState('w-demo');
  applyWorldTransaction(state, [{ op: 'system_use_decision.issue', decision: record }], record.trace.created_at);
  return state;
}

function openStore(root = mkdtempSync(join(tmpdir(), 'system-use-decision-')), runId = 'run_1'): WalStore {
  if (!roots.includes(root)) roots.push(root);
  const store = WalStore.open({
    recordsRoot: root,
    worldId: 'w-demo',
    runId,
    bootId: `authz_boot_${runId}`,
    policyVersion: POLICY_VERSION,
    policyContentDigest: 'c'.repeat(64),
    evaluatorBuildDigest: 'b'.repeat(64),
    now: () => AT,
  });
  stores.push(store);
  return store;
}

describe('ADR-008 authorization-owned system-use decision', () => {
  it('resolves the exact checked-in fixture and exposes only the bounded governance allowlist', async () => {
    const record = fixture();
    expect(systemUseDecisionDigest(record)).toBe(record.trace.record_digest);
    const store = openStore();
    const service = new SystemUseDecisionService(store, ENVIRONMENT);
    await service.installFixture(record, AUTHZ);

    expect(service.resolve(store.snapshot(), demoMandate(), POLICY_VERSION, AT)).toEqual({
      decision_id: record.decision_id,
      version: record.version,
      record_digest: record.trace.record_digest,
      status: 'approved_with_conditions',
      conditions: [
        { id: 'no-external-effect', satisfied: true },
        { id: 'synthetic-data-only', satisfied: true },
      ],
    });
    const state = store.snapshot();
    expect(state.mandates.size).toBe(0);
    expect(state.rulings.size).toBe(0);
    expect(state.commitments.size).toBe(0);
    expect(state.effects.size).toBe(0);

    const projection = JSON.stringify(service.governanceProjection(AT));
    for (const permitted of ['synthetic_fixture', 'self_declared', 'probe_tested', 'not_assessed']) {
      expect(projection).toContain(permitted);
    }
    expect(projection).toContain('not_available_in_poc');
    for (const forbidden of [
      record.trace.evidence_pack_ref,
      record.evidence_refs[0]?.ref as string,
      'credential',
      'prompt',
      'output',
      'certification-result',
    ]) {
      expect(projection).not.toContain(forbidden);
    }
  });

  it('fails closed for every inactive state, expiry, condition failure, and integrity defect', () => {
    const base = fixture();
    for (const status of ['rejected', 'suspended', 'withdrawn', 'expired'] as const) {
      const record = resign({ ...base, decision: { ...base.decision, status } });
      expect(() => resolveCurrentSystemUseDecision(withRecord(record), demoMandate(), POLICY_VERSION, AT, ENVIRONMENT)).toThrow(
        expect.objectContaining({ code: 'inactive' }),
      );
    }
    expect(() =>
      resolveCurrentSystemUseDecision(
        withRecord(base),
        demoMandate(),
        POLICY_VERSION,
        base.validity.expires_at,
        ENVIRONMENT,
      ),
    ).toThrow(expect.objectContaining({ code: 'inactive' }));
    expect(() =>
      resolveCurrentSystemUseDecision(withRecord(base), demoMandate(), POLICY_VERSION, AT, {
        ...ENVIRONMENT,
        hardConditions: { ...ENVIRONMENT.hardConditions, 'synthetic-data-only': false },
      }),
    ).toThrow(expect.objectContaining({ code: 'condition-unsatisfied' }));

    const invalid = { ...base, trace: { ...base.trace, record_digest: 'f'.repeat(64) } };
    const state = createWorldState('w-demo');
    expect(() =>
      applyWorldTransaction(state, [{ op: 'system_use_decision.issue', decision: invalid }], AT),
    ).toThrow(expect.objectContaining({ code: 'system-use-integrity' }));
    expect(JSON.stringify(state)).not.toContain(base.trace.evidence_pack_ref);
  });

  it('rejects every exact-scope mismatch instead of accepting caller assertions', () => {
    const record = fixture();
    const state = withRecord(record);
    const baseMandate = demoMandate();
    const bindChanged = (change: (body: Omit<Mandate, 'binding'>) => void): Mandate => {
      const { binding: ignored, ...body } = baseMandate;
      void ignored;
      const copy = structuredClone(body);
      change(copy);
      return bindMandate(KEYRING, copy);
    };
    const mismatches: Array<readonly [Mandate, string, SystemUseEnvironment]> = [
      [baseMandate, 'other-policy', ENVIRONMENT],
      [baseMandate, POLICY_VERSION, { ...ENVIRONMENT, useCaseId: 'other-use' }],
      [baseMandate, POLICY_VERSION, { ...ENVIRONMENT, systemId: 'other-system' }],
      [baseMandate, POLICY_VERSION, { ...ENVIRONMENT, jurisdictions: ['other-jurisdiction'] }],
      [
        bindChanged((body) => {
          body.approved_models[0] = { ...body.approved_models[0]!, card_digest: '1'.repeat(64) };
        }),
        POLICY_VERSION,
        ENVIRONMENT,
      ],
      [
        bindChanged((body) => {
          body.approved_models[0] = {
            ...body.approved_models[0]!,
            roles: ['screening'],
            data_classes: { screening: ['conf:public', 'purpose:grant-assessment'] },
          };
        }),
        POLICY_VERSION,
        ENVIRONMENT,
      ],
      [
        bindChanged((body) => {
          body.approved_models[0] = {
            ...body.approved_models[0]!,
            data_classes: {
              acting: ['conf:case', 'conf:public', 'conf:sensitive', 'purpose:grant-assessment'],
            },
          };
        }),
        POLICY_VERSION,
        ENVIRONMENT,
      ],
    ];
    for (const [mandateValue, policyVersion, environment] of mismatches) {
      expect(() => resolveCurrentSystemUseDecision(state, mandateValue, policyVersion, AT, environment)).toThrow(
        expect.objectContaining({ code: 'missing' }),
      );
    }

    const wrongConfiguration = resign({
      ...record,
      subject: { ...record.subject, configuration_digest: '2'.repeat(64) },
    });
    expect(() =>
      resolveCurrentSystemUseDecision(withRecord(wrongConfiguration), baseMandate, POLICY_VERSION, AT, ENVIRONMENT),
    ).toThrow(expect.objectContaining({ code: 'missing' }));
    expect(() =>
      applyWorldTransaction(
        createWorldState('w-demo'),
        [{ op: 'system_use_decision.issue', decision: resign({ ...record, world_id: 'w-other' }) }],
        AT,
      ),
    ).toThrow();
    expect(() =>
      applyWorldTransaction(
        createWorldState('w-demo'),
        [{ op: 'system_use_decision.issue', decision: resign({ ...record, version: 2 }) }],
        AT,
      ),
    ).toThrow(expect.objectContaining({ code: 'system-use-version' }));
  });

  it('replays an exact successor and refuses terminal-version restoration, reuse, and rollback', async () => {
    const root = mkdtempSync(join(tmpdir(), 'system-use-replay-'));
    const firstStore = openStore(root, 'run_1');
    const firstService = new SystemUseDecisionService(firstStore, ENVIRONMENT);
    const first = fixture();
    await firstService.installFixture(first, AUTHZ);
    const successor = resign({
      ...first,
      version: 2,
      decision: { ...first.decision, basis_summary: 'synthetic-poc-use-only-successor' },
      trace: {
        ...first.trace,
        record_digest: '0'.repeat(64),
        created_at: '2026-08-04T09:01:00.000Z',
        supersedes: { decision_id: first.decision_id, version: 1 },
      },
    });
    await firstService.replace(successor, AUTHZ);
    const before = firstStore.snapshot();
    expect(before.systemUseDecisionStatus.get(`${first.decision_id}@1`)?.status).toBe('superseded');
    expect(firstService.resolve(before, demoMandate(), POLICY_VERSION, '2026-08-04T09:02:00.000Z').version).toBe(2);
    await expect(firstService.transition(first.decision_id, 1, 'approved', AUTHZ)).rejects.toThrow();
    await expect(
      firstStore.transact('rollback-attempt', AUTHZ, [{ op: 'system_use_decision.issue', decision: first }]),
    ).rejects.toThrow();

    firstStore.close();
    stores.splice(stores.indexOf(firstStore), 1);
    const replayed = openStore(root, 'run_2');
    const replayedService = new SystemUseDecisionService(replayed, ENVIRONMENT);
    expect(replayed.snapshot().systemUseDecisionStatus).toEqual(before.systemUseDecisionStatus);
    expect(replayedService.resolve(replayed.snapshot(), demoMandate(), POLICY_VERSION, '2026-08-04T09:02:00.000Z')).toEqual(
      firstService.resolve(before, demoMandate(), POLICY_VERSION, '2026-08-04T09:02:00.000Z'),
    );
  });

  it('accepts idempotent startup only from authorization and rejects a second lineage', async () => {
    const store = openStore();
    const service = new SystemUseDecisionService(store, ENVIRONMENT);
    const record = fixture();
    await expect(
      service.installFixture(record, { credential: 'role:principal', claimed_role: 'principal' }),
    ).rejects.toEqual(expect.objectContaining({ code: 'forbidden' }));
    await service.installFixture(record, AUTHZ);
    await service.installFixture(record, AUTHZ);
    const other = resign({ ...record, decision_id: 'sud_other' });
    await expect(service.installFixture(other, AUTHZ)).rejects.toThrow();
    expect(store.snapshot().systemUseDecisions.size).toBe(1);
    expect(
      modelCallBeginRequest.safeParse({
        turn_id: 'turn_override',
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: 'publicai-apertus-v1.5-70b',
        card_version: 1,
        requested_id: 'swiss-ai/apertus-v1.5-70b',
        system_use_status: 'approved',
        system_use_version: 99,
        system_use_conditions: [],
      }).success,
    ).toBe(false);
  });
});
