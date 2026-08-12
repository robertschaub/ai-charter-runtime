// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

import { afterEach, describe, expect, it } from 'vitest';

import { AuthorizationReadSide, AuthorizationReadSideError } from './authorizationReadSide.js';
import { CardRegistry } from './cardRegistry.js';
import { RecordVerificationError, type RecordsVerificationReport } from './checkpoint.js';
import { WalStore } from './walStore.js';

const roots: string[] = [];
const stores: WalStore[] = [];
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;
const APPLICANT = { credential: 'role:applicant', claimed_role: 'applicant' } as const;

afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(verifyRecordLayer: () => Promise<RecordsVerificationReport>) {
  const recordsRoot = mkdtempSync(join(tmpdir(), 'runtime-read-side-'));
  roots.push(recordsRoot);
  const store = WalStore.open({
    recordsRoot,
    worldId: 'w-demo',
    runId: 'run_read_side',
    bootId: 'boot_read_side',
    policyVersion: 'policy-test',
    policyContentDigest: 'a'.repeat(64),
    evaluatorBuildDigest: 'b'.repeat(64),
    now: () => '2026-08-03T08:00:00.000Z',
  });
  stores.push(store);
  return {
    recordsRoot,
    store,
    reads: new AuthorizationReadSide({
      store,
      cards: CardRegistry.load(resolve('docs/cards')),
      recordsRoot,
      worldId: 'w-demo',
      verifyRecordLayer,
    }),
  };
}

describe('authorization read side', () => {
  it('permits the principal to request the fixed approved-model projection', () => {
    const { reads } = harness(async () => {
      throw new Error('verification is not used by the model-card route');
    });
    expect(reads.approvedModels('mdt_missing', PRINCIPAL)).toBeNull();
    expect(() => reads.approvedModels('mdt_missing', APPLICANT)).toThrowError(
      expect.objectContaining<Partial<AuthorizationReadSideError>>({ code: 'forbidden' }),
    );
  });

  it.each(['rollback', 'remote-rollback', 'remote-acknowledgment-ambiguous'] as const)(
    'projects the %s record-verification alarm and keeps the route role-scoped',
    async (code) => {
      const { reads } = harness(async () => {
        throw new RecordVerificationError(code, 'synthetic rollback detail');
      });

      await expect(reads.verification(PRINCIPAL)).resolves.toEqual({
        body: {
          status: 'alarm',
          code,
          message: 'record verification detected a divergence',
        },
        readLengths: {},
      });
      await expect(reads.verification(APPLICANT)).rejects.toMatchObject({
        code: 'forbidden',
      });
    },
  );

  it('returns verified chain envelopes and refuses in-line tamper or valid-prefix rollback', async () => {
    const { reads, recordsRoot, store } = harness(async () => {
      throw new Error('verification is not used by the record-view route');
    });
    await store.transact(
      'synthetic_access',
      { credential: 'proc:authz', claimed_role: null },
      [
        {
          op: 'record.access.append',
          entry: {
            world_id: 'w-demo',
            entry_id: 'acc_read_side',
            at: '2026-08-03T08:00:00.000Z',
            route: 'GET /w/{world_id}/records/*',
            authenticated_actor: 'role:principal',
            claimed_actor: { role: 'principal' },
            outcome: 'served',
            http_status: 200,
          },
        },
      ],
    );

    expect(reads.records(PRINCIPAL).body).toMatchObject({
      access_chain: {
        length: 1,
        entries: [
          {
            seq: 0,
            prev_hash: '0'.repeat(64),
            entry_hash: expect.stringMatching(/^[0-9a-f]{64}$/),
            entry: { entry_id: 'acc_read_side', outcome: 'served' },
          },
        ],
      },
    });

    const accessFile = join(recordsRoot, 'w-demo', 'access.jsonl');
    const original = readFileSync(accessFile, 'utf8');
    writeFileSync(accessFile, original.replace('"served"', '"forbidden"'), 'utf8');
    expect(() => reads.records(PRINCIPAL)).toThrowError(
      expect.objectContaining<Partial<AuthorizationReadSideError>>({ code: 'record-integrity-alarm' }),
    );
    writeFileSync(accessFile, '', 'utf8');
    expect(() => reads.records(PRINCIPAL)).toThrowError(
      expect.objectContaining<Partial<AuthorizationReadSideError>>({ code: 'record-integrity-alarm' }),
    );
  });
});
