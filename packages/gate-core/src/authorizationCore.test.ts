// SPDX-License-Identifier: AGPL-3.0-only
import { appendFileSync, existsSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  AuthorizationCore,
  bindMandate,
  freezeProposal,
  type IdFactory,
} from './authorizationCore.js';
import { verifyChain } from './chain.js';
import { Keyring, verifyEmbeddedMac } from './keyring.js';
import { loadPolicyFile, type LoadedPolicy } from './policyLoader.js';
import type { EffectIntent, FrozenProposal, Mandate } from './schemas/index.js';
import { applyWorldTransaction, cloneWorldState, counterValue } from './state.js';
import { runSweeper } from './sweeper.js';
import { verifyCommitTokenForIntent } from './tokenVerifier.js';
import { WalStore } from './walStore.js';

const KEY_ID = 'hmac-test';
const KEY = 'a'.repeat(64);
const CARD_DIGEST = 'c'.repeat(64);
const BUILD_DIGEST = 'b'.repeat(64);
const POLICY_FILE = fileURLToPath(new URL('../policy/v1.yaml', import.meta.url));
const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: 'case_officer' } as const;
const SERVICES_HOST = { credential: 'proc:services_host', claimed_role: null } as const;
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;

class SequentialIds implements IdFactory {
  #next = 0;
  next(prefix: Parameters<IdFactory['next']>[0]): string {
    this.#next += 1;
    return `${prefix}_${this.#next}`;
  }
}

interface Harness {
  readonly root: string;
  readonly keyring: Keyring;
  readonly policy: LoadedPolicy;
  readonly ids: SequentialIds;
  readonly store: WalStore;
  readonly core: AuthorizationCore;
  setNow(value: string): void;
}

const roots: string[] = [];
const openStores: WalStore[] = [];

afterEach(() => {
  for (const store of openStores.splice(0)) {
    try {
      store.close();
    } catch {}
  }
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function harness(initialNow = '2026-08-01T09:00:00.000Z'): Harness {
  const root = mkdtempSync(join(tmpdir(), 'gate-core-m2-'));
  roots.push(root);
  let now = initialNow;
  const policy = loadPolicyFile(POLICY_FILE, BUILD_DIGEST);
  const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);
  const ids = new SequentialIds();
  const store = WalStore.open({
    recordsRoot: root,
    worldId: 'w-demo',
    runId: 'run_1',
    bootId: 'authz_boot_1',
    policyVersion: policy.policy.policy_version,
    policyContentDigest: policy.policyContentDigest,
    evaluatorBuildDigest: policy.evaluatorBuildDigest,
    now: () => now,
  });
  openStores.push(store);
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
    ids,
    resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
    resolveModelEvidence: () => ({
      servedModelAccepted: true,
      cardStatus: 'current',
      cardKeyId: 'card-test',
      cardDigest: CARD_DIGEST,
    }),
  });
  return { root, keyring, policy, ids, store, core, setNow: (value) => (now = value) };
}

function mandateBody(
  overrides: Partial<Omit<Mandate, 'binding'>> = {},
): Omit<Mandate, 'binding'> {
  return {
    world_id: 'w-demo',
    mandate_id: 'mdt_demo',
    version: 1,
    state: 'active',
    ordering_rule: 'latest-version-wins',
    principal: { id: 'principal' },
    authorized_agent: { id: 'agent_demo' },
    authority_chain: [
      { hop: 0, delegator: 'principal', delegate: 'agent_demo', subdelegation_scope: ['grant-filing'] },
    ],
    action_class: 'grant-filing',
    connected_service: 'filing',
    target: { recipient: 'grant-office', resource: 'application-42' },
    permitted_data_fields: ['applicant_name'],
    disclosure_destinations: ['filing'],
    limits: {
      amount_minor_units: 100,
      frequency_per_day: 10,
      notification_volume: 5,
      geographic: ['CH'],
      time_window: { not_before: '2026-08-01T00:00:00.000Z', not_after: '2026-08-02T00:00:00.000Z' },
    },
    declared_purpose: 'Process the synthetic grant.',
    user_objective: 'File the synthetic grant.',
    issued_at: '2026-08-01T08:00:00.000Z',
    expires_at: '2026-08-02T00:00:00.000Z',
    revocation_endpoint: '/w/w-demo/mandates/mdt_demo/revoke',
    replay_protection: { scheme: 'per-ruling-nonce' },
    substitution_rules: { model_substitution: 'approved-set-only', service_substitution: 'named-services-only' },
    risk_class: 'medium',
    reversibility_class: 'partially-reversible',
    approved_models: [
      {
        card_id: 'model-demo',
        card_version: 1,
        card_digest: CARD_DIGEST,
        requested_id: 'model-demo-v1',
        roles: ['acting'],
        data_classes: { acting: ['conf:case', 'purpose:grant-assessment'] },
      },
    ],
    ...overrides,
  };
}

function proposal(
  sequence: number,
  overrides: Partial<Omit<FrozenProposal, 'proposal_hash'>> = {},
): FrozenProposal {
  return freezeProposal({
    world_id: 'w-demo',
    proposal_id: `prp_${sequence}`,
    revision: 1,
    action_id: `act_${sequence}`,
    created_at: '2026-08-01T09:00:00.000Z',
    declared_objective: 'File the synthetic grant.',
    proposed_action: 'Submit the grant filing.',
    target: { recipient: 'grant-office', resource: 'application-42' },
    exact_parameters: { amount_minor_units: 50, reference: `case-${sequence}` },
    material_inputs: [],
    derived_claims: [],
    data_to_be_disclosed: ['applicant_name'],
    cost_obligation: { amount_minor_units: 50, description: 'Synthetic amount.' },
    material_consequences: ['Synthetic public-funds commitment.'],
    reversibility_class: 'partially-reversible',
    commercial_influence: { applicable: false, note: 'n/a' },
    acting_model: {
      requested_id: 'model-demo-v1',
      served_id: 'model-demo-v1',
      card_id: 'model-demo',
      card_version: 1,
    },
    mandate_ref: { mandate_id: 'mdt_demo', version: 1 },
    ...overrides,
  });
}

function ruleInput(value: FrozenProposal, overrides: Record<string, unknown> = {}) {
  return {
    gate: 'commit' as const,
    proposal: value,
    service: 'filing',
    actionClass: 'grant-filing',
    actor: ORCHESTRATOR,
    ...overrides,
  };
}

function intentFor(value: FrozenProposal, rulingId: string, service = 'filing', actionClass = 'grant-filing'): EffectIntent {
  return {
    world_id: value.world_id,
    ruling_id: rulingId,
    frozen_proposal_hash: value.proposal_hash,
    service,
    action_class: actionClass,
    target: value.target,
    exact_parameters: value.exact_parameters,
    data_to_be_disclosed: value.data_to_be_disclosed,
  };
}

async function initialize(value: Harness, body = mandateBody()): Promise<Mandate> {
  await value.core.activatePolicy();
  const bound = bindMandate(value.keyring, body);
  await value.core.grantMandate(bound, PRINCIPAL);
  return bound;
}

describe('M2 authorization transactions', () => {
  it('rejects an unsafe world id before creating any path outside the records root', () => {
    const root = mkdtempSync(join(tmpdir(), 'gate-core-world-'));
    roots.push(root);
    const escaped = `${root}-escaped`;
    expect(() =>
      WalStore.open({
        recordsRoot: root,
        worldId: `../${basename(escaped)}`,
        runId: 'run_1',
        bootId: 'authz_boot_1',
        policyVersion: 'test',
        policyContentDigest: 'c'.repeat(64),
        evaluatorBuildDigest: BUILD_DIGEST,
      }),
    ).toThrow();
    expect(existsSync(escaped)).toBe(false);
  });

  it('seals an exact commitment before returning a token, rejects replay, and replays from WAL', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(1);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    expect(ruled.ruling.verdict).toBe('allow');
    expect(ruled.ruling.counter_reservations.map((value) => value.counter).sort()).toEqual(['actions', 'amount']);
    await h.core.activatePolicy();
    expect(h.store.snapshot().rulings.get(ruled.ruling.ruling_id)?.status).toBe('issued');

    const committed = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      actor: SERVICES_HOST,
    });
    expect(committed.ok).toBe(true);
    if (!committed.ok) throw new Error('expected commitment');
    expect(
      verifyEmbeddedMac(h.keyring, 'commit-token', committed.token as unknown as Record<string, unknown>, 'mac'),
    ).toBe('valid');
    expect(
      verifyCommitTokenForIntent(
        h.keyring,
        committed.token,
        intentFor(frozen, ruled.ruling.ruling_id),
        '2026-08-01T09:00:01.000Z',
      ).valid,
    ).toBe(true);
    expect(
      verifyCommitTokenForIntent(
        h.keyring,
        committed.token,
        {
          ...intentFor(frozen, ruled.ruling.ruling_id),
          target: { recipient: 'different-recipient', resource: frozen.target.resource },
        },
        '2026-08-01T09:00:01.000Z',
      ),
    ).toEqual({ valid: false, reason: 'binding-mismatch' });
    expect(
      verifyCommitTokenForIntent(
        h.keyring,
        committed.token,
        intentFor(frozen, ruled.ruling.ruling_id),
        committed.token.expires_at,
      ),
    ).toEqual({ valid: false, reason: 'expired' });

    const replay = await h.core.commitVerify({
      rulingId: ruled.ruling.ruling_id,
      intent: intentFor(frozen, ruled.ruling.ruling_id),
      servicesHostBootId: 'services_boot_1',
      actor: SERVICES_HOST,
    });
    expect(replay).toEqual({ ok: false, defect: 'replayed-ruling' });

    const before = h.store.snapshot();
    expect(before.nonces.get(ruled.ruling.binding.nonce)?.state).toBe('consumed');
    expect([...before.commitments.values()][0]?.state).toBe('bound');
    expect(before.actionRecords).toHaveLength(2);
    h.store.close();
    openStores.splice(openStores.indexOf(h.store), 1);

    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_2',
      bootId: 'authz_boot_2',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.policy.evaluatorBuildDigest,
      now: () => '2026-08-01T09:01:00.000Z',
    });
    openStores.push(reopened);
    const after = reopened.snapshot();
    expect(after.commitments).toEqual(before.commitments);
    expect(after.rulings).toEqual(before.rulings);
    expect(verifyChain(join(h.root, 'w-demo', 'wal.jsonl'), 'wal-entry').ok).toBe(true);
    expect(verifyChain(join(h.root, 'w-demo', 'action.jsonl'), 'record-entry').ok).toBe(true);
  });

  it('denies missing, expired, revoked, broadened, and substituted authority', async () => {
    const missing = harness();
    await missing.core.activatePolicy();
    expect((await missing.core.ruleProposal(ruleInput(proposal(1)))).ruling.reason).toContain('missing-mandate');

    const expired = harness('2026-08-03T09:00:00.000Z');
    await initialize(expired);
    expect((await expired.core.ruleProposal(ruleInput(proposal(2)))).ruling.reason).toContain('expired-mandate');

    const revoked = harness();
    await initialize(revoked);
    await revoked.core.revokeMandate('mdt_demo', 1, PRINCIPAL);
    expect((await revoked.core.ruleProposal(ruleInput(proposal(3)))).ruling.reason).toContain('revoked-mandate');

    const broadened = harness();
    await initialize(broadened);
    const tooLarge = proposal(4, { cost_obligation: { amount_minor_units: 101, description: 'Too large.' } });
    expect((await broadened.core.ruleProposal(ruleInput(tooLarge))).ruling.reason).toContain('broadened-request');

    const substituted = harness();
    await initialize(substituted);
    const mismatchedCore = new AuthorizationCore({
      store: substituted.store,
      keyring: substituted.keyring,
      policy: substituted.policy,
      ids: substituted.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveModelEvidence: () => ({
        servedModelAccepted: false,
        cardStatus: 'current',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const result = await mismatchedCore.ruleProposal(ruleInput(proposal(5)));
    expect(result.ruling.reason).toContain('substituted-model');
  });

  it('routes ordinary card supersession to re-confirmation but fails a withdrawal closed', async () => {
    const superseded = harness();
    await initialize(superseded);
    const supersededCore = new AuthorizationCore({
      store: superseded.store,
      keyring: superseded.keyring,
      policy: superseded.policy,
      ids: superseded.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus: 'superseded',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    expect((await supersededCore.ruleProposal(ruleInput(proposal(6)))).ruling).toMatchObject({
      verdict: 'escalate',
      matched_rule_id: 'default:model-card-reconfirmation',
    });

    const withdrawn = harness();
    await initialize(withdrawn);
    const withdrawnCore = new AuthorizationCore({
      store: withdrawn.store,
      keyring: withdrawn.keyring,
      policy: withdrawn.policy,
      ids: withdrawn.ids,
      resolveAuthorizedAgent: () => 'agent_demo',
      resolveModelEvidence: () => ({
        servedModelAccepted: true,
        cardStatus: 'withdrawn',
        cardKeyId: 'card-test',
        cardDigest: CARD_DIGEST,
      }),
    });
    const denied = await withdrawnCore.ruleProposal(ruleInput(proposal(7)));
    expect(denied.ruling.verdict).toBe('deny');
    expect(denied.ruling.reason).toContain('stale-card');
  });

  it('serializes a counter race so only one request reserves below the ceiling', async () => {
    const h = harness();
    await initialize(
      h,
      mandateBody({
        action_class: 'notification',
        connected_service: 'notification',
        disclosure_destinations: ['notification'],
      }),
    );
    const first = proposal(10, {
      cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
      exact_parameters: { amount_minor_units: 0, reference: 'case-10', notification_volume: 3 },
      mandate_ref: { mandate_id: 'mdt_demo', version: 1 },
    });
    const second = proposal(11, {
      cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
      exact_parameters: { amount_minor_units: 0, reference: 'case-11', notification_volume: 3 },
      mandate_ref: { mandate_id: 'mdt_demo', version: 1 },
    });
    const results = await Promise.all([
      h.core.ruleProposal(
        ruleInput(first, {
          service: 'notification',
          actionClass: 'notification',
        }),
      ),
      h.core.ruleProposal(
        ruleInput(second, {
          service: 'notification',
          actionClass: 'notification',
        }),
      ),
    ]);
    expect(results.map((value) => value.ruling.verdict).sort()).toEqual(['allow', 'escalate']);
    expect(counterValue(h.store.snapshot(), 'mdt_demo', 'notification_volume')).toBe(3);
  });

  it('applies latest-version-wins and atomically invalidates rulings from the superseded mandate', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(15);
    const first = await h.core.ruleProposal(ruleInput(frozen));
    const amended = bindMandate(
      h.keyring,
      mandateBody({ version: 2, issued_at: '2026-08-01T09:00:01.000Z', user_objective: 'Amended objective.' }),
    );
    await h.core.amendMandate(amended, PRINCIPAL);
    const afterAmendment = h.store.snapshot();
    expect(afterAmendment.rulings.get(first.ruling.ruling_id)?.status).toBe('invalidated');
    for (const reservation of first.ruling.counter_reservations) {
      expect(afterAmendment.reservations.get(reservation.id)?.state).toBe('released');
    }
    const reruled = await h.core.ruleProposal(ruleInput(frozen));
    expect(reruled.ruling).toMatchObject({ verdict: 'deny' });
    expect(reruled.ruling.reason).toContain('invalid-mandate-binding');
  });

  it('blocks mutation after allow without consuming the ruling, then accepts only the exact frozen intent', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(16);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const exact = intentFor(frozen, ruled.ruling.ruling_id);
    const mutated = {
      ...exact,
      exact_parameters: { ...exact.exact_parameters, amount_minor_units: 99 },
    };
    expect(
      await h.core.commitVerify({
        rulingId: ruled.ruling.ruling_id,
        intent: mutated,
        servicesHostBootId: 'services_boot_1',
        actor: SERVICES_HOST,
      }),
    ).toEqual({ ok: false, defect: 'proposal-mismatch' });
    expect(h.store.snapshot().rulings.get(ruled.ruling.ruling_id)?.status).toBe('issued');
    expect(
      (
        await h.core.commitVerify({
          rulingId: ruled.ruling.ruling_id,
          intent: exact,
          servicesHostBootId: 'services_boot_1',
          actor: SERVICES_HOST,
        })
      ).ok,
    ).toBe(true);
  });

  it('linearizes revocation before or after commit-verify with no interleaved third state', async () => {
    const revokeFirst = harness();
    await initialize(revokeFirst);
    const firstProposal = proposal(17);
    const firstRuling = await revokeFirst.core.ruleProposal(ruleInput(firstProposal));
    const [, denied] = await Promise.all([
      revokeFirst.core.revokeMandate('mdt_demo', 1, PRINCIPAL),
      revokeFirst.core.commitVerify({
        rulingId: firstRuling.ruling.ruling_id,
        intent: intentFor(firstProposal, firstRuling.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        actor: SERVICES_HOST,
      }),
    ]);
    expect(denied).toEqual({ ok: false, defect: 'replayed-ruling' });
    expect(revokeFirst.store.snapshot().commitments.size).toBe(0);

    const commitFirst = harness();
    await initialize(commitFirst);
    const secondProposal = proposal(18);
    const secondRuling = await commitFirst.core.ruleProposal(ruleInput(secondProposal));
    const [bound] = await Promise.all([
      commitFirst.core.commitVerify({
        rulingId: secondRuling.ruling.ruling_id,
        intent: intentFor(secondProposal, secondRuling.ruling.ruling_id),
        servicesHostBootId: 'services_boot_1',
        actor: SERVICES_HOST,
      }),
      commitFirst.core.revokeMandate('mdt_demo', 1, PRINCIPAL),
    ]);
    expect(bound.ok).toBe(true);
    expect([...commitFirst.store.snapshot().commitments.values()][0]?.state).toBe('bound');
    expect(commitFirst.store.snapshot().mandateStatus.get('mdt_demo')?.state).toBe('revoked');
  });

  it('turns the recurring-escalation threshold into a suspended mandate version', async () => {
    const h = harness();
    await initialize(
      h,
      mandateBody({
        action_class: 'notification',
        connected_service: 'notification',
        disclosure_destinations: ['notification'],
      }),
    );
    const results = [];
    for (let index = 20; index < 23; index += 1) {
      results.push(
        await h.core.ruleProposal(
          ruleInput(
            proposal(index, {
              cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
              exact_parameters: { amount_minor_units: 0, reference: `case-${index}`, notification_volume: 6 },
            }),
            {
              service: 'notification',
              actionClass: 'notification',
            },
          ),
        ),
      );
    }
    expect(results.map((value) => value.ruling.verdict)).toEqual(['escalate', 'escalate', 'escalate']);
    expect(results[2]?.mandateNarrowed).toBe(true);
    const status = h.store.snapshot().mandateStatus.get('mdt_demo');
    expect(status).toMatchObject({ version: 2, state: 'suspended' });
    const narrowed = h.store.snapshot().mandates.get('mdt_demo@2');
    expect(narrowed).toBeDefined();
    expect(
      verifyEmbeddedMac(h.keyring, 'mandate-binding', narrowed as unknown as Record<string, unknown>, 'binding'),
    ).toBe('valid');
  });

  it('sweeps ruling expiry and escalation timeout and repairs a torn WAL tail on restart', async () => {
    const h = harness();
    await initialize(
      h,
      mandateBody({
        action_class: 'notification',
        connected_service: 'notification',
        disclosure_destinations: ['notification'],
      }),
    );
    const frozen = proposal(30, {
      cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
      exact_parameters: { amount_minor_units: 0, reference: 'case-30', notification_volume: 6 },
    });
    const ruled = await h.core.ruleProposal(
      ruleInput(frozen, {
        service: 'notification',
        actionClass: 'notification',
      }),
    );
    expect(ruled.ruling.verdict).toBe('escalate');
    h.setNow('2026-08-01T09:16:00.000Z');
    const swept = await runSweeper(h.store, h.keyring, h.policy, h.ids);
    expect(swept).toMatchObject({ changed: true, expiredRulings: 1, timedOutEscalations: 1 });
    expect(h.store.snapshot().escalations.get(ruled.escalationId ?? '')?.state).toBe('timed_out');

    h.store.close();
    openStores.splice(openStores.indexOf(h.store), 1);
    appendFileSync(join(h.root, 'w-demo', 'wal.jsonl'), '{"partial":', 'utf8');
    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_2',
      bootId: 'authz_boot_2',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.policy.evaluatorBuildDigest,
      now: () => '2026-08-01T09:17:00.000Z',
    });
    openStores.push(reopened);
    expect(verifyChain(join(h.root, 'w-demo', 'wal.jsonl'), 'wal-entry').ok).toBe(true);
    expect(reopened.snapshot().escalations.get(ruled.escalationId ?? '')?.state).toBe('timed_out');
  });

  it('rejects illegal lifecycle transitions and non-contiguous proposal revisions during replay', async () => {
    const h = harness();
    await initialize(h);
    const frozen = proposal(40);
    const ruled = await h.core.ruleProposal(ruleInput(frozen));
    const state = h.store.snapshot();

    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [{ op: 'ruling.consume', ruling_id: ruled.ruling.ruling_id }],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/consumed nonce/);
    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [{ op: 'reservation.settle', reservation_id: ruled.ruling.counter_reservations[0]?.id ?? '' }],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/consumed allow nonce/);

    const skipped = proposal(41, { action_id: frozen.action_id, revision: 3 });
    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [{ op: 'proposal.freeze', proposal: skipped }],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/must be revision 2/);

    const recorded = state.actionRecords[0];
    if (recorded === undefined) throw new Error('expected ruling record');
    expect(() =>
      applyWorldTransaction(
        cloneWorldState(state),
        [
          {
            op: 'record.action.append',
            entry: { ...recorded, entry_id: 'rec_tampered', proposed_action: 'Different action.' },
          },
        ],
        '2026-08-01T09:00:01.000Z',
      ),
    ).toThrow(/differs from its ruling or proposal/);
  });
});
