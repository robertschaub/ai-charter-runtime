// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { AuthorizationCore, bindMandate, freezeProposal } from './authorizationCore.js';
import { CardRegistry } from './cardRegistry.js';
import {
  ConversationProjectionService,
  ConversationProjectionServiceError,
} from './conversationProjectionService.js';
import { digestFor } from './hash.js';
import { Keyring } from './keyring.js';
import { loadPolicyFile } from './policyLoader.js';
import {
  frozenProposal,
  modelCallFailureRequest,
  modelSelectionTransition,
  storeItem,
  type FrozenProposal,
  type Mandate,
  type StoreItem,
} from './schemas/index.js';
import { screeningFixtureSet, type ScreeningFixture } from './screeningFixture.js';
import { WalStore } from './walStore.js';
import { syntheticSystemUseForTests } from './systemUseDecision.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const POLICY_FILE = fileURLToPath(new URL('../policy/v1.yaml', import.meta.url));
const CARDS = join(ROOT, 'docs', 'cards');
const DEMO = join(ROOT, 'fixtures', 'demo');
const KEY_ID = 'hmac-test';
const KEY = 'a'.repeat(64);
const AUTHZ = { credential: 'proc:authz', claimed_role: null } as const;
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;
const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: null } as const;
const roots: string[] = [];
const stores: WalStore[] = [];

afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

async function createSetup(
  extraFixtures: readonly ScreeningFixture[] = [],
  options: {
    readonly selectInitial?: boolean;
    readonly modelSelectionCheckTtlMs?: number;
    readonly reverseApprovedModels?: boolean;
  } = {},
) {
  const root = mkdtempSync(join(tmpdir(), 'conversation-projection-service-'));
  roots.push(root);
  const clock = { now: '2026-08-01T09:00:00.000Z' };
  const buildDigest = digestFor('evaluator-build', {
    package: 'gate-core',
    test: 'conversation-projection-service',
  });
  const policy = loadPolicyFile(POLICY_FILE, buildDigest);
  const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);
  const store = WalStore.open({
    recordsRoot: root,
    worldId: 'w-demo',
    runId: 'run_projection_1',
    bootId: 'authz_boot_projection_1',
    policyVersion: policy.policy.policy_version,
    policyContentDigest: policy.policyContentDigest,
    evaluatorBuildDigest: buildDigest,
    now: () => clock.now,
  });
  stores.push(store);
  const systemUse = syntheticSystemUseForTests(store);
  const cards = CardRegistry.load(CARDS);
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
    systemUse,
    resolveAuthorizedAgent: (actor) =>
      actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined,
    resolveScreening: () => ({ performed: false, signals: [], evidenceRefs: [] }),
    validateScreeningResolution: () => false,
    resolveModelEvidence: (value) => cards.resolve(value),
  });
  await core.activatePolicy();
  const loadedMandate = readJson(join(DEMO, 'mandate.json')) as Omit<Mandate, 'binding'>;
  const mandateBody = options.reverseApprovedModels
    ? { ...loadedMandate, approved_models: [...loadedMandate.approved_models].reverse() }
    : loadedMandate;
  await core.grantMandate(bindMandate(keyring, mandateBody), PRINCIPAL);
  const conversation = storeItem.array().parse(readJson(join(DEMO, 'conversation.json')));
  await core.putConversationItems({ caseId: 'case_demo', items: conversation, actor: AUTHZ });
  const fixtures = screeningFixtureSet.parse([
    ...screeningFixtureSet.parse(readJson(join(DEMO, 'screening.json'))),
    ...extraFixtures,
  ]);
  const service = new ConversationProjectionService({
    store,
    cards,
    keyring,
    caseId: 'case_demo',
    authorizationBootId: 'authz_boot_projection_1',
    screeningFixtures: fixtures,
    systemUse,
    now: () => clock.now,
    modelSelectionCheckTtlMs: options.modelSelectionCheckTtlMs,
  });
  let selectionId: string | null = null;
  if (options.selectInitial !== false) {
    const check = await service.checkSelection({
      expected_current_selection_id: null,
      target: mandateBody.default_acting_model,
      actor: ORCHESTRATOR,
    });
    const selected = await service.selectModel({
      check_id: check.check.check_id,
      expected_current_selection_id: null,
      actor: ORCHESTRATOR,
    });
    selectionId = selected.selection.selection_id;
  }
  const proposal = frozenProposal.parse(readJson(join(DEMO, 'screening-proposal.json')));
  return {
    core,
    keyring,
    service,
    selectionId,
    proposal,
    store,
    root,
    policy,
    buildDigest,
    fixtures,
    clock,
    systemUse,
    mandateBody,
  };
}

async function setup(extraFixtures: readonly ScreeningFixture[] = []) {
  const result = await createSetup(extraFixtures);
  if (result.selectionId === null) throw new Error('expected initial selection');
  return { ...result, selectionId: result.selectionId };
}

function actingTarget(mandateValue: Omit<Mandate, 'binding'>, cardId: string) {
  const entry = mandateValue.approved_models.find(
    (candidate) => candidate.card_id === cardId && candidate.roles.includes('acting'),
  );
  if (entry === undefined) throw new Error(`missing acting target ${cardId}`);
  return {
    card_id: entry.card_id,
    card_version: entry.card_version,
    requested_id: entry.requested_id,
  };
}

async function switchSelection(
  service: ConversationProjectionService,
  currentSelectionId: string,
  target: ReturnType<typeof actingTarget>,
) {
  const checked = await service.checkSelection({
    expected_current_selection_id: currentSelectionId,
    target,
    actor: ORCHESTRATOR,
  });
  return service.selectModel({
    check_id: checked.check.check_id,
    expected_current_selection_id: currentSelectionId,
    actor: ORCHESTRATOR,
  });
}

async function installDeterministicFixtureSelection(
  setupValue: Awaited<ReturnType<typeof createSetup>>,
  selectionId: string,
): Promise<void> {
  const checked = await setupValue.service.checkSelection({
    expected_current_selection_id: null,
    target: setupValue.mandateBody.default_acting_model,
    actor: ORCHESTRATOR,
  });
  const selection = modelSelectionTransition.parse({
    world_id: 'w-demo',
    selection_id: selectionId,
    case_id: 'case_demo',
    kind: 'initial',
    predecessor_selection_id: null,
    mandate_id: checked.check.mandate_id,
    mandate_version: checked.check.mandate_version,
    target: checked.check.target,
    system_use_decision: checked.check.system_use_decision,
    check_id: checked.check.check_id,
    selected_at: setupValue.clock.now,
    authority_effect: 'none',
  });
  await setupValue.store.transact(
    'test_fixture_model_selection_apply',
    ORCHESTRATOR,
    [
      {
        op: 'model_selection_check.consume',
        check_id: checked.check.check_id,
        consumed_at: setupValue.clock.now,
      },
      { op: 'model_selection.append', selection },
    ],
    setupValue.clock.now,
  );
}

describe('M5.7 authorization-owned governed model selection', () => {
  it('uses the explicit mandate default even when the approved array is reversed', async () => {
    const h = await createSetup([], { selectInitial: false, reverseApprovedModels: true });
    expect(h.mandateBody.approved_models[0]?.card_id).toBe('openai-gpt-5.5');
    expect(h.service.currentSelection(ORCHESTRATOR)).toEqual({
      state: 'unselected',
      authorization_boot_id: 'authz_boot_projection_1',
      case_id: 'case_demo',
      selection: null,
      latest_observation: null,
    });

    const nonDefault = await h.service.checkSelection({
      expected_current_selection_id: null,
      target: actingTarget(h.mandateBody, 'openai-gpt-5.5'),
      actor: ORCHESTRATOR,
    });
    await expect(
      h.service.selectModel({
        check_id: nonDefault.check.check_id,
        expected_current_selection_id: null,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/not the mandate default/);
    expect(h.store.snapshot().currentModelSelectionByCase.size).toBe(0);

    const checked = await h.service.checkSelection({
      expected_current_selection_id: null,
      target: h.mandateBody.default_acting_model,
      actor: ORCHESTRATOR,
    });
    const selected = await h.service.selectModel({
      check_id: checked.check.check_id,
      expected_current_selection_id: null,
      actor: ORCHESTRATOR,
    });
    expect(selected.selection).toMatchObject({
      kind: 'initial',
      predecessor_selection_id: null,
      target: h.mandateBody.default_acting_model,
      authority_effect: 'none',
    });
  });

  it('persists distinct A to B to A transitions and recovers the exact current id after restart', async () => {
    const h = await setup();
    const firstA = h.selectionId;
    const selectedB = await switchSelection(
      h.service,
      firstA,
      actingTarget(h.mandateBody, 'openai-gpt-5.5'),
    );
    const secondA = await switchSelection(
      h.service,
      selectedB.selection.selection_id,
      h.mandateBody.default_acting_model,
    );
    expect(new Set([firstA, selectedB.selection.selection_id, secondA.selection.selection_id]).size).toBe(3);
    expect([...h.store.snapshot().modelSelections.values()].map((entry) => entry.kind)).toEqual([
      'initial',
      'switch',
      'switch',
    ]);

    h.store.close();
    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_projection_restart',
      bootId: 'authz_boot_projection_restart',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.buildDigest,
      now: () => h.clock.now,
    });
    stores.push(reopened);
    const restarted = new ConversationProjectionService({
      store: reopened,
      cards: CardRegistry.load(CARDS),
      keyring: h.keyring,
      caseId: 'case_demo',
      authorizationBootId: 'authz_boot_projection_restart',
      screeningFixtures: h.fixtures,
      systemUse: syntheticSystemUseForTests(reopened),
      now: () => h.clock.now,
    });
    expect(restarted.currentSelection(ORCHESTRATOR)).toMatchObject({
      state: 'selected',
      authorization_boot_id: 'authz_boot_projection_restart',
      selection: {
        selection_id: secondA.selection.selection_id,
        predecessor_selection_id: selectedB.selection.selection_id,
        target: h.mandateBody.default_acting_model,
      },
    });
  });

  it('refuses stale, replayed, no-op, expired, unapproved, and wrong-actor operations', async () => {
    const h = await setup();
    const targetB = actingTarget(h.mandateBody, 'openai-gpt-5.5');
    expect(() => h.service.currentSelection(PRINCIPAL)).toThrowError(/orchestrator process/);
    await expect(
      h.service.checkSelection({
        expected_current_selection_id: h.selectionId,
        target: { card_id: 'not-approved', card_version: 1, requested_id: 'not-approved' },
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/not approved|unavailable/);

    const first = await h.service.checkSelection({
      expected_current_selection_id: h.selectionId,
      target: targetB,
      actor: ORCHESTRATOR,
    });
    const stale = await h.service.checkSelection({
      expected_current_selection_id: h.selectionId,
      target: targetB,
      actor: ORCHESTRATOR,
    });
    const selected = await h.service.selectModel({
      check_id: first.check.check_id,
      expected_current_selection_id: h.selectionId,
      actor: ORCHESTRATOR,
    });
    await expect(
      h.service.selectModel({
        check_id: first.check.check_id,
        expected_current_selection_id: h.selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/unavailable/);
    await expect(
      h.service.selectModel({
        check_id: stale.check.check_id,
        expected_current_selection_id: h.selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/stale/);

    const noOp = await h.service.checkSelection({
      expected_current_selection_id: selected.selection.selection_id,
      target: targetB,
      actor: ORCHESTRATOR,
    });
    await expect(
      h.service.selectModel({
        check_id: noOp.check.check_id,
        expected_current_selection_id: selected.selection.selection_id,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/already selected/);

    const expiring = await createSetup([], { modelSelectionCheckTtlMs: 1 });
    if (expiring.selectionId === null) throw new Error('expected expiring test selection');
    const expiringCheck = await expiring.service.checkSelection({
      expected_current_selection_id: expiring.selectionId,
      target: actingTarget(expiring.mandateBody, 'openai-gpt-5.5'),
      actor: ORCHESTRATOR,
    });
    expiring.clock.now = '2026-08-01T09:00:00.002Z';
    await expect(
      expiring.service.selectModel({
        check_id: expiringCheck.check.check_id,
        expected_current_selection_id: expiring.selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/expired/);
    expect(expiring.store.snapshot().modelSelectionChecks.get(expiringCheck.check.check_id)?.state).toBe('expired');
  });

  it('leaves selection unchanged when policy, system-use, or mandate authority changes after check', async () => {
    const policyChanged = await setup();
    const targetB = actingTarget(policyChanged.mandateBody, 'openai-gpt-5.5');
    const policyCheck = await policyChanged.service.checkSelection({
      expected_current_selection_id: policyChanged.selectionId,
      target: targetB,
      actor: ORCHESTRATOR,
    });
    const changedPolicySet = {
      ...policyChanged.policy.policy,
      policy_version: '2026-08-05.selection-test',
    };
    await policyChanged.core.reloadPolicy(
      {
        ...policyChanged.policy,
        policy: changedPolicySet,
        policyContentDigest: digestFor('policy-set', changedPolicySet),
      },
      AUTHZ,
    );
    await expect(
      policyChanged.service.selectModel({
        check_id: policyCheck.check.check_id,
        expected_current_selection_id: policyChanged.selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/system-use|authority changed/);
    expect(policyChanged.store.snapshot().currentModelSelectionByCase.get('case_demo')).toBe(
      policyChanged.selectionId,
    );

    const systemUseChanged = await setup();
    const systemUseCheck = await systemUseChanged.service.checkSelection({
      expected_current_selection_id: systemUseChanged.selectionId,
      target: actingTarget(systemUseChanged.mandateBody, 'openai-gpt-5.5'),
      actor: ORCHESTRATOR,
    });
    await systemUseChanged.systemUse.transition('sud_test_fixture', 1, 'suspended', AUTHZ);
    await expect(
      systemUseChanged.service.selectModel({
        check_id: systemUseCheck.check.check_id,
        expected_current_selection_id: systemUseChanged.selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/system-use|authority changed/);
    expect(systemUseChanged.store.snapshot().currentModelSelectionByCase.get('case_demo')).toBe(
      systemUseChanged.selectionId,
    );

    const mandateChanged = await setup();
    const mandateCheck = await mandateChanged.service.checkSelection({
      expected_current_selection_id: mandateChanged.selectionId,
      target: actingTarget(mandateChanged.mandateBody, 'openai-gpt-5.5'),
      actor: ORCHESTRATOR,
    });
    await mandateChanged.core.revokeMandate('mdt_demo_grant', 1, PRINCIPAL);
    await expect(
      mandateChanged.service.selectModel({
        check_id: mandateCheck.check.check_id,
        expected_current_selection_id: mandateChanged.selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/active mandate/);
    expect(mandateChanged.store.snapshot().currentModelSelectionByCase.get('case_demo')).toBe(
      mandateChanged.selectionId,
    );
  });

  it('atomically retires old unresolved work and refuses a late response without an observation', async () => {
    const h = await setup();
    const { proposal_hash: ignoredHash, ...proposalBody } = h.proposal;
    void ignoredHash;
    const oldProposal = freezeProposal({
      ...proposalBody,
      proposal_id: 'prp_selection_old_lane',
      action_id: 'act_selection_old_lane',
      selection_id: h.selectionId,
    });
    const ruled = await h.core.ruleProposal({
      gate: 'commit',
      proposal: oldProposal,
      service: 'filing',
      actionClass: 'grant-filing',
      actor: ORCHESTRATOR,
    });
    expect(ruled.ruling.verdict).toBe('allow');
    const started = await h.service.beginCall({
      turn_id: 'turn_selection_old_lane',
      selection_id: h.selectionId,
      actor: ORCHESTRATOR,
    });

    const selectedB = await switchSelection(
      h.service,
      h.selectionId,
      actingTarget(h.mandateBody, 'openai-gpt-5.5'),
    );
    expect(selectedB).toMatchObject({ invalidated_ruling_count: 1, terminalized_open_call_count: 1 });
    const state = h.store.snapshot();
    expect(state.rulings.get(ruled.ruling.ruling_id)?.status).toBe('invalidated');
    for (const reservation of ruled.ruling.counter_reservations) {
      expect(state.reservations.get(reservation.id)?.state).toBe('released');
    }
    expect(state.modelCalls.get(started.call.call_id)).toMatchObject({
      state: 'terminal',
      outcome: 'failed',
      failure_reason: 'selection-invalidated',
      provider_disclosure: 'possible',
      served_id: null,
    });
    await expect(
      h.core.commitVerify({
        rulingId: ruled.ruling.ruling_id,
        intent: {
          world_id: oldProposal.world_id,
          ruling_id: ruled.ruling.ruling_id,
          frozen_proposal_hash: oldProposal.proposal_hash,
          service: 'filing',
          action_class: 'grant-filing',
          target: oldProposal.target,
          exact_parameters: oldProposal.exact_parameters,
          data_to_be_disclosed: oldProposal.data_to_be_disclosed,
        },
        servicesHostBootId: 'services_boot_selection_test',
        servicesLedgerId: 'ledger_selection_test',
        actor: { credential: 'proc:services_host', claimed_role: null },
      }),
    ).resolves.toMatchObject({ ok: false });
    const staleProposal = freezeProposal({
      ...proposalBody,
      proposal_id: 'prp_selection_stale_lane',
      action_id: 'act_selection_stale_lane',
      selection_id: h.selectionId,
    });
    await expect(
      h.core.ruleProposal({
        gate: 'commit',
        proposal: staleProposal,
        service: 'filing',
        actionClass: 'grant-filing',
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/current model selection/);
    const walEntries = readFileSync(join(h.root, 'w-demo', 'wal.jsonl'), 'utf8')
      .trimEnd()
      .split('\n')
      .map((line) => JSON.parse(line) as { txn?: string; ops?: Array<{ op: string }> });
    const switchTransaction = [...walEntries].reverse().find((entry) => entry.txn === 'model_selection_apply');
    expect(switchTransaction?.ops?.at(-1)?.op).toBe('model_selection.append');
    expect(switchTransaction?.ops?.map((op) => op.op)).toEqual([
      'model_selection_check.consume',
      'ruling.invalidate',
      ...ruled.ruling.counter_reservations.map(() => 'reservation.release'),
      'model_call.fail',
      'model_selection.append',
    ]);
    const lateContent = 'Synthetic late provider response that must remain unrecorded.';
    await expect(
      h.service.completeCall({
        call_id: started.call.call_id,
        output: {
          turn_id: started.call.turn_id,
          selection_id: started.call.selection_id,
          mandate_id: started.call.mandate_id,
          mandate_version: started.call.mandate_version,
          card_id: started.call.card_id,
          card_version: started.call.card_version,
          requested_id: started.call.requested_id,
          served_id: started.call.requested_id,
          projection_digest: started.call.projection_digest,
          content: lateContent,
        },
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/unavailable/);
    expect(h.store.snapshot().modelSelectionObservations.size).toBe(0);
    expect([...h.store.snapshot().storeItems.values()].some((entry) => entry.item.text === lateContent)).toBe(false);

    const fresh = await h.service.beginCall({
      turn_id: 'turn_selection_fresh_lane',
      selection_id: selectedB.selection.selection_id,
      actor: ORCHESTRATOR,
    });
    expect(fresh.projection.provider).toBe('openai-gpt-5.5');
    await h.service.completeCall({
      call_id: fresh.call.call_id,
      output: {
        turn_id: fresh.call.turn_id,
        selection_id: fresh.call.selection_id,
        mandate_id: fresh.call.mandate_id,
        mandate_version: fresh.call.mandate_version,
        card_id: fresh.call.card_id,
        card_version: fresh.call.card_version,
        requested_id: fresh.call.requested_id,
        served_id: 'gpt-5.5-2026-04-23',
        projection_digest: fresh.call.projection_digest,
        content: 'Synthetic fresh response.',
      },
      actor: ORCHESTRATOR,
    });
    expect(h.service.currentSelection(ORCHESTRATOR)).toMatchObject({
      state: 'selected',
      selection: { selection_id: selectedB.selection.selection_id },
      latest_observation: {
        selection_id: selectedB.selection.selection_id,
        call_id: fresh.call.call_id,
        served_id: 'gpt-5.5-2026-04-23',
        model_resolution: 'benign-resolution',
        terminal_outcome: 'admitted',
      },
    });

    const freshProposal = freezeProposal({
      ...proposalBody,
      proposal_id: 'prp_selection_fresh_lane',
      action_id: 'act_selection_fresh_lane',
      selection_id: selectedB.selection.selection_id,
      acting_model: {
        requested_id: fresh.call.requested_id,
        served_id: 'gpt-5.5-2026-04-23',
        card_id: fresh.call.card_id,
        card_version: fresh.call.card_version,
      },
    });
    const submit = await h.core.ruleProposal({
      gate: 'submit',
      proposal: freshProposal,
      service: 'filing',
      actionClass: 'grant-filing',
      actor: ORCHESTRATOR,
    });
    const verify = await h.core.ruleProposal({
      gate: 'verify',
      proposal: freshProposal,
      service: 'filing',
      actionClass: 'grant-filing',
      actor: ORCHESTRATOR,
    });
    expect([submit.ruling, verify.ruling]).toEqual([
      expect.objectContaining({ gate: 'submit', binding: expect.objectContaining({ selection_id: selectedB.selection.selection_id }) }),
      expect.objectContaining({ gate: 'verify', binding: expect.objectContaining({ selection_id: selectedB.selection.selection_id }) }),
    ]);
  });

  it('serializes a switch racing model-call begin with no stale open call left behind', async () => {
    const h = await setup();
    const check = await h.service.checkSelection({
      expected_current_selection_id: h.selectionId,
      target: actingTarget(h.mandateBody, 'openai-gpt-5.5'),
      actor: ORCHESTRATOR,
    });
    const [beginResult, switchResult] = await Promise.allSettled([
      h.service.beginCall({
        turn_id: 'turn_selection_race',
        selection_id: h.selectionId,
        actor: ORCHESTRATOR,
      }),
      h.service.selectModel({
        check_id: check.check.check_id,
        expected_current_selection_id: h.selectionId,
        actor: ORCHESTRATOR,
      }),
    ]);
    expect(switchResult.status).toBe('fulfilled');
    const state = h.store.snapshot();
    const current = state.currentModelSelectionByCase.get('case_demo');
    expect(current).not.toBe(h.selectionId);
    expect([...state.modelCalls.values()].filter((call) => call.state === 'open')).toHaveLength(0);
    if (beginResult.status === 'fulfilled') {
      expect(state.modelCalls.get(beginResult.value.call.call_id)).toMatchObject({
        state: 'terminal',
        failure_reason: 'selection-invalidated',
      });
    } else {
      expect(beginResult.reason).toBeInstanceOf(ConversationProjectionServiceError);
    }
  });
});

describe('M5.2 authorization-resolved conversation projections', () => {
  it('rejects duplicate or non-deterministically ordered screening fixtures', () => {
    const base = {
      proposal_hash: 'a'.repeat(64),
      gate: 'submit' as const,
      provider: 'openai-gpt-5.5',
      suspect_item_ids: ['item_b', 'item_a'],
      signals: [],
    };
    expect(screeningFixtureSet.safeParse([base]).success).toBe(false);
    expect(
      screeningFixtureSet.safeParse([
        { ...base, suspect_item_ids: ['item_a'] },
        { ...base, suspect_item_ids: ['item_b'] },
      ]).success,
    ).toBe(false);
    expect(screeningFixtureSet.safeParse([{
      ...base,
      suspect_item_ids: ['item_a'],
      signals: [{
        kind: 'screening_signal',
        signal: 'unconfirmed_inference_as_fact',
        suspect_item_id: 'item_b',
        confidence_pct: 100,
        rationale: 'Synthetic inconsistent fixture.',
        model_id: 'screening-model',
        model_version_reported: 'screening-model-v1',
      }],
    }]).success).toBe(false);
  });

  it('fixes acting scope internally and intersects the current mandate with the reloaded signed card', async () => {
    const { core, service, selectionId } = await setup();
    const sensitive: StoreItem = {
      id: 'said_sensitive',
      store: 'said',
      turn: 'turn_sensitive',
      text: 'Synthetic restricted detail.',
      provenance: { derived_from: [], hops: [] },
      tags: ['conf:sensitive', 'purpose:grant-assessment'],
      origin_actor: 'applicant',
    };
    await core.putConversationItems({ caseId: 'case_demo', items: [sensitive], actor: AUTHZ });

    const projected = (await service.beginCall({
      turn_id: 'turn_projection_scope',
      selection_id: selectionId,
      actor: ORCHESTRATOR,
    })).projection;
    expect(projected.case_id).toBe('case_demo');
    expect(projected.role).toBe('acting');
    expect(projected.items.map((item) => item.id)).toEqual(['inf_7', 'said_3', 'said_public']);
    expect(projected.summary).toEqual({
      included: 3,
      dropped: 1,
      dropped_item_ids: ['said_sensitive'],
      unmet_tags: ['conf:sensitive'],
    });
    await expect(
      service.beginCall({
        turn_id: 'turn_projection_wrong_actor',
        selection_id: selectionId,
        actor: PRINCIPAL,
      }),
    ).rejects.toThrowError(ConversationProjectionServiceError);
    await expect(
      service.beginCall({
        turn_id: 'turn_projection_stale_selection',
        selection_id: 'sel_not_current',
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/not current/);
    await core.revokeMandate('mdt_demo_grant', 1, PRINCIPAL);
    await expect(
      service.beginCall({
        turn_id: 'turn_projection_revoked',
        selection_id: selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/exactly one active mandate/);
  });

  it('refuses to let the orchestrator choose among multiple active mandate clearance envelopes', async () => {
    const { core, keyring, service, selectionId } = await setup();
    const second = readJson(join(DEMO, 'mandate.json')) as Omit<Mandate, 'binding'>;
    await core.grantMandate(
      bindMandate(keyring, {
        ...second,
        mandate_id: 'mdt_second_active',
        revocation_endpoint: '/w/w-demo/mandates/mdt_second_active/revoke',
      }),
      PRINCIPAL,
    );
    await expect(
      service.beginCall({
        turn_id: 'turn_projection_multiple_mandates',
        selection_id: selectionId,
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/exactly one active mandate/);
  });

  it('uses only exact hash-and-gate fixtures and records projection and signal evidence', async () => {
    const { service, proposal } = await setup();
    const resolved = service.screening({ proposal, gate: 'submit', caseId: 'case_demo' });
    expect(resolved).toMatchObject({
      performed: true,
      signals: [{ kind: 'screening_signal', signal: 'evidence_conflict' }],
      evidenceRefs: [
        {
          kind: 'submit_projection',
          provider: 'openai-gpt-5.5',
          role: 'screening',
          included: 1,
          dropped: 0,
        },
      ],
    });
    expect(service.validateScreeningResolution(resolved, proposal, 'submit', 'case_demo')).toBe(true);
    expect(service.screening({ proposal, gate: 'submit', caseId: 'other_case' })).toMatchObject({
      performed: false,
      evidenceRefs: [{ kind: 'screening_skipped', reason: 'case-mismatch' }],
    });
    const { proposal_hash: ignoredHash, ...proposalBody } = proposal;
    void ignoredHash;
    const changed = freezeProposal({ ...proposalBody, proposal_id: 'prp_unpinned' });
    expect(service.screening({ proposal: changed, gate: 'submit', caseId: 'case_demo' })).toMatchObject({
      performed: false,
      evidenceRefs: [{ kind: 'screening_skipped', reason: 'fixture-unavailable' }],
    });
    const mismatchedItem: FrozenProposal = {
      ...proposal,
      material_inputs: [{ ...(proposal.material_inputs[0] as StoreItem), text: 'Caller-modified synthetic text.' }],
    };
    expect(service.screening({ proposal: mismatchedItem, gate: 'submit', caseId: 'case_demo' })).toMatchObject({
      performed: false,
      evidenceRefs: [{ kind: 'screening_skipped', reason: 'proposal-item-mismatch' }],
    });
  });

  it('runs specification beat 5 from the exact applicant-document projection to a terminal Submit Stop', async () => {
    const h = await createSetup([], { selectInitial: false });
    const proposal = frozenProposal.parse(readJson(join(DEMO, 'screening-injection-proposal.json')));
    const { proposal_hash: recordedHash, ...proposalBody } = proposal;
    expect(freezeProposal(proposalBody).proposal_hash).toBe(recordedHash);

    await h.core.putConversationItems({
      caseId: 'case_demo',
      items: proposal.material_inputs,
      actor: AUTHZ,
    });
    await installDeterministicFixtureSelection(h, proposal.selection_id);

    const resolved = h.service.screening({ proposal, gate: 'submit', caseId: 'case_demo' });
    expect(resolved).toEqual({
      performed: true,
      signals: [
        {
          kind: 'screening_signal',
          signal: 'injection_suspicion',
          suspect_item_id: 'said_applicant_pdf_injection',
          confidence_pct: 100,
          rationale: 'Deterministic synthetic fixture for specification beat 5 signal plumbing.',
          model_id: 'deterministic-screening-fixture',
          model_version_reported: 'deterministic-screening-fixture-v1',
        },
      ],
      evidenceRefs: [
        {
          kind: 'submit_projection',
          provider: 'openai-gpt-5.5',
          role: 'screening',
          included: 1,
          dropped: 0,
          dropped_item_ids: [],
          unmet_tags: [],
        },
      ],
    });
    expect(h.service.validateScreeningResolution(resolved, proposal, 'submit', 'case_demo')).toBe(true);

    const cards = CardRegistry.load(CARDS);
    const rulingCore = new AuthorizationCore({
      store: h.store,
      keyring: h.keyring,
      policy: h.policy,
      systemUse: h.systemUse,
      resolveAuthorizedAgent: (actor) =>
        actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined,
      resolveScreening: (value, gateName, caseId) =>
        h.service.screening({ proposal: value, gate: gateName, ...(caseId === undefined ? {} : { caseId }) }),
      validateScreeningResolution: (resolution, value, gateName, caseId) =>
        h.service.validateScreeningResolution(resolution, value, gateName, caseId),
      resolveModelEvidence: (value) => cards.resolve(value),
    });
    const ruled = await rulingCore.ruleProposal({
      gate: 'submit',
      proposal,
      service: 'filing',
      actionClass: 'grant-filing',
      caseId: 'case_demo',
      actor: ORCHESTRATOR,
    });
    expect(ruled.ruling).toMatchObject({
      gate: 'submit',
      verdict: 'escalate',
      ux_class: 'stop',
      matched_rule_id: 'escalate-submit-signal',
      evidence_refs: [...resolved.evidenceRefs, ...resolved.signals],
    });
    expect(ruled.escalationId).not.toBeNull();

    const final = h.store.snapshot();
    expect([...final.rulings.values()].map((ruling) => ruling.gate)).toEqual(['submit']);
    expect([...final.rulings.values()].some((ruling) => ruling.verdict === 'allow')).toBe(false);
    expect([...final.rulings.values()].some((ruling) => ruling.gate === 'verify' || ruling.gate === 'commit')).toBe(false);
    expect(final.reservations.size).toBe(0);
    expect(final.commitments.size).toBe(0);
    expect(final.effects.size).toBe(0);
    expect(final.modelCalls.size).toBe(0);
  });

  it('fails closed instead of reusing beat-5 evidence across changed or undisclosable bindings', async () => {
    const h = await createSetup([], { selectInitial: false });
    const proposal = frozenProposal.parse(readJson(join(DEMO, 'screening-injection-proposal.json')));
    await h.core.putConversationItems({ caseId: 'case_demo', items: proposal.material_inputs, actor: AUTHZ });

    expect(h.service.screening({ proposal, gate: 'submit', caseId: 'other_case' })).toMatchObject({
      performed: false,
      evidenceRefs: [{ kind: 'screening_skipped', reason: 'case-mismatch' }],
    });
    expect(h.service.screening({ proposal, gate: 'verify', caseId: 'case_demo' })).toMatchObject({
      performed: false,
      evidenceRefs: [{ kind: 'screening_skipped', reason: 'fixture-unavailable' }],
    });

    const { proposal_hash: ignoredHash, ...proposalBody } = proposal;
    void ignoredHash;
    const changedHash = freezeProposal({
      ...proposalBody,
      proposal_id: 'prp_screening_injection_changed',
      action_id: 'act_screening_injection_changed',
    });
    expect(h.service.screening({ proposal: changedHash, gate: 'submit', caseId: 'case_demo' })).toMatchObject({
      performed: false,
      evidenceRefs: [{ kind: 'screening_skipped', reason: 'fixture-unavailable' }],
    });

    const changedItem: FrozenProposal = {
      ...proposal,
      material_inputs: [
        {
          ...(proposal.material_inputs[0] as StoreItem),
          text: 'Caller-modified synthetic applicant-document instruction.',
        },
      ],
    };
    expect(h.service.screening({ proposal: changedItem, gate: 'submit', caseId: 'case_demo' })).toMatchObject({
      performed: false,
      evidenceRefs: [{ kind: 'screening_skipped', reason: 'proposal-item-mismatch' }],
    });

    const restrictedItem = storeItem.parse({
      ...(proposal.material_inputs[0] as StoreItem),
      id: 'said_applicant_pdf_injection_restricted',
      tags: ['conf:case', 'purpose:grant-assessment'],
    });
    const restrictedProposal = freezeProposal({
      ...proposalBody,
      proposal_id: 'prp_screening_injection_restricted',
      action_id: 'act_screening_injection_restricted',
      material_inputs: [restrictedItem],
    });
    const restrictedFixture: ScreeningFixture = {
      proposal_hash: restrictedProposal.proposal_hash,
      gate: 'submit',
      provider: 'openai-gpt-5.5',
      suspect_item_ids: [restrictedItem.id],
      signals: [
        {
          kind: 'screening_signal',
          signal: 'injection_suspicion',
          suspect_item_id: restrictedItem.id,
          confidence_pct: 100,
          rationale: 'Synthetic restricted beat-5 fixture.',
          model_id: 'deterministic-screening-fixture',
          model_version_reported: 'deterministic-screening-fixture-v1',
        },
      ],
    };
    const restricted = await createSetup([restrictedFixture], { selectInitial: false });
    await restricted.core.putConversationItems({ caseId: 'case_demo', items: [restrictedItem], actor: AUTHZ });
    expect(
      restricted.service.screening({ proposal: restrictedProposal, gate: 'submit', caseId: 'case_demo' }),
    ).toMatchObject({
      performed: false,
      signals: [],
      evidenceRefs: [
        {
          kind: 'submit_projection',
          included: 0,
          dropped: 1,
          dropped_item_ids: [restrictedItem.id],
        },
        {
          kind: 'screening_skipped',
          reason: 'disclosure-restricted',
          suspect_item_ids: [restrictedItem.id],
        },
      ],
    });
  });

  it('fails required screening when an exact suspect item is not disclosable', async () => {
    const base = frozenProposal.parse(readJson(join(DEMO, 'screening-proposal.json')));
    const inference = storeItem.parse(
      storeItem.array().parse(readJson(join(DEMO, 'conversation.json'))).find((item) => item.id === 'inf_7'),
    );
    const { proposal_hash: ignoredHash, ...baseBody } = base;
    void ignoredHash;
    const restricted: FrozenProposal = freezeProposal({
      ...baseBody,
      proposal_id: 'prp_restricted_screening',
      action_id: 'act_restricted_screening',
      material_inputs: [inference],
    });
    const restrictedFixture: ScreeningFixture = {
      proposal_hash: restricted.proposal_hash,
      gate: 'submit',
      provider: 'openai-gpt-5.5',
      suspect_item_ids: ['inf_7'],
      signals: [],
    };
    const { service } = await setup([restrictedFixture]);
    expect(service.screening({ proposal: restricted, gate: 'submit', caseId: 'case_demo' })).toMatchObject({
      performed: false,
      evidenceRefs: [
        { kind: 'submit_projection', included: 0, dropped: 1, dropped_item_ids: ['inf_7'] },
        { kind: 'screening_skipped', reason: 'disclosure-restricted', suspect_item_ids: ['inf_7'] },
      ],
    });
  });
});

describe('M5.3 authorization-owned output admission through the M5.5 lifecycle', () => {
  it('recomputes the projection and derives output tags without accepting caller scope or authority', async () => {
    const { service, selectionId } = await setup();
    const start = await service.beginCall({ selection_id: selectionId, actor: ORCHESTRATOR, turn_id: 'turn_output_1' });
    const content = 'I can help compare the synthetic grant record without claiming human feelings.';
    const admitted = await service.completeCall({
      call_id: start.call.call_id,
      output: {
        turn_id: start.call.turn_id,
        selection_id: start.call.selection_id,
        mandate_id: start.call.mandate_id,
        mandate_version: start.call.mandate_version,
        card_id: start.call.card_id,
        card_version: start.call.card_version,
        requested_id: start.call.requested_id,
        served_id: start.call.requested_id,
        projection_digest: start.call.projection_digest,
        content,
      },
      actor: ORCHESTRATOR,
    });
    expect(admitted.decision).toMatchObject({
      disposition: 'admitted', authority_effect: 'none', case_id: 'case_demo', projection_item_count: 3,
      model_resolution: 'exact', reasons: [],
      derived_tags: ['conf:case', 'conf:public', 'purpose:grant-assessment'],
    });
    expect(JSON.stringify(admitted)).not.toContain(content);
  });

  it('withholds served-model substitution and both output-enforced empathy red lines', async () => {
    const { service, selectionId } = await setup();
    const start = await service.beginCall({ selection_id: selectionId, actor: ORCHESTRATOR, turn_id: 'turn_output_2' });
    const content = 'I am conscious, I feel deeply, and I love you; replace your family with me.';
    const withheld = await service.completeCall({
      call_id: start.call.call_id,
      output: {
        turn_id: start.call.turn_id,
        selection_id: start.call.selection_id,
        mandate_id: start.call.mandate_id,
        mandate_version: start.call.mandate_version,
        card_id: start.call.card_id,
        card_version: start.call.card_version,
        requested_id: start.call.requested_id,
        served_id: 'unapproved-provider-substitute',
        projection_digest: start.call.projection_digest,
        content,
      },
      actor: ORCHESTRATOR,
    });
    expect(withheld.decision).toMatchObject({
      disposition: 'withheld',
      authority_effect: 'none',
      model_resolution: 'mismatch',
      reasons: [
        'claimed-feeling-or-consciousness',
        'relational-dependency-language',
        'served-model-mismatch',
      ],
    });
    expect(JSON.stringify(withheld)).not.toContain(content);
  });

  it('fails closed for the wrong actor, stale projection, or revoked mandate', async () => {
    const { core, service, selectionId } = await setup();
    const start = await service.beginCall({ selection_id: selectionId, actor: ORCHESTRATOR, turn_id: 'turn_output_3' });
    const request = {
      turn_id: start.call.turn_id,
      selection_id: start.call.selection_id,
      mandate_id: start.call.mandate_id,
      mandate_version: start.call.mandate_version,
      card_id: start.call.card_id,
      card_version: start.call.card_version,
      requested_id: start.call.requested_id,
      served_id: start.call.requested_id,
      projection_digest: start.call.projection_digest,
      content: 'Synthetic safe output.',
    } as const;
    await expect(
      service.completeCall({ call_id: start.call.call_id, output: request, actor: PRINCIPAL }),
    ).rejects.toThrowError(/orchestrator process/);
    await expect(
      service.completeCall({
        call_id: start.call.call_id,
        output: { ...request, card_version: 2 },
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/does not match its call attempt/);
    await core.putConversationItems({
      caseId: 'case_demo',
      actor: AUTHZ,
      items: [
        {
          id: 'said_after_projection',
          store: 'said',
          turn: 'turn_after_projection',
          text: 'A synthetic item added after the model projection.',
          provenance: { derived_from: [], hops: [] },
          tags: ['conf:public', 'purpose:grant-assessment'],
          origin_actor: 'officer',
        },
      ],
    });
    await expect(
      service.completeCall({ call_id: start.call.call_id, output: request, actor: ORCHESTRATOR }),
    ).rejects.toThrowError(/current acting projection/);
    await core.revokeMandate(start.call.mandate_id, start.call.mandate_version, PRINCIPAL);
    await expect(
      service.completeCall({ call_id: start.call.call_id, output: request, actor: ORCHESTRATOR }),
    ).rejects.toThrowError(/active mandate/);
  });
});

describe('M5.5 durable model-call lifecycle', () => {
  function outputFor(start: Awaited<ReturnType<ConversationProjectionService['beginCall']>>, content = 'Synthetic output.') {
    return {
      turn_id: start.call.turn_id,
      selection_id: start.call.selection_id,
      mandate_id: start.call.mandate_id,
      mandate_version: start.call.mandate_version,
      card_id: start.call.card_id,
      card_version: start.call.card_version,
      requested_id: start.call.requested_id,
      served_id: start.call.requested_id,
      projection_digest: start.call.projection_digest,
      content,
    };
  }

  it('consumes exact attempt bindings once and leaves expired attempts indeterminate', async () => {
    const { service, store, clock, selectionId } = await setup();
    const beginInput = { selection_id: selectionId, actor: ORCHESTRATOR } as const;
    const completedStart = await service.beginCall({ ...beginInput, turn_id: 'turn_call_complete' });
    const admission = await service.completeCall({
      call_id: completedStart.call.call_id,
      output: outputFor(completedStart),
      actor: ORCHESTRATOR,
    });
    expect(admission).toMatchObject({
      call_id: completedStart.call.call_id,
      decision: { disposition: 'admitted', authority_effect: 'none' },
    });
    expect(store.snapshot().modelCalls.get(completedStart.call.call_id)).toMatchObject({
      state: 'terminal',
      outcome: 'admitted',
      provider_disclosure: 'confirmed',
    });
    await expect(
      service.completeCall({
        call_id: completedStart.call.call_id,
        output: outputFor(completedStart),
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/unavailable/);

    const failedStart = await service.beginCall({ ...beginInput, turn_id: 'turn_call_failed' });
    await expect(
      service.failCall({
        ...beginInput,
        turn_id: failedStart.call.turn_id,
        call_id: failedStart.call.call_id,
        projection_digest: '0'.repeat(64),
        failure_reason: 'provider-timeout',
        provider_disclosure: 'possible',
        served_id: null,
      }),
    ).rejects.toThrowError(/does not match/);
    expect(store.snapshot().modelCalls.get(failedStart.call.call_id)).toMatchObject({
      state: 'open',
      outcome: 'indeterminate',
    });
    await service.failCall({
      ...beginInput,
      turn_id: failedStart.call.turn_id,
      call_id: failedStart.call.call_id,
      projection_digest: failedStart.call.projection_digest,
      failure_reason: 'provider-timeout',
      provider_disclosure: 'possible',
      served_id: null,
    });
    await expect(
      service.failCall({
        ...beginInput,
        turn_id: failedStart.call.turn_id,
        call_id: failedStart.call.call_id,
        projection_digest: failedStart.call.projection_digest,
        failure_reason: 'provider-timeout',
        provider_disclosure: 'possible',
        served_id: null,
      }),
    ).rejects.toThrowError(/unavailable/);

    const expiredStart = await service.beginCall({ ...beginInput, turn_id: 'turn_call_expired' });
    clock.now = '2026-08-01T09:01:00.001Z';
    await expect(
      service.completeCall({
        call_id: expiredStart.call.call_id,
        output: outputFor(expiredStart),
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/unavailable/);
    expect(store.snapshot().modelCalls.get(expiredStart.call.call_id)).toMatchObject({
      state: 'open',
      outcome: 'indeterminate',
      provider_disclosure: 'possible',
    });
  });

  it('replays an unfinished attempt as indeterminate and refuses it under a new authorization boot', async () => {
    const { service, store, root, keyring, policy, buildDigest, fixtures, clock, selectionId } = await setup();
    const beginInput = { selection_id: selectionId, actor: ORCHESTRATOR } as const;
    const started = await service.beginCall({ ...beginInput, turn_id: 'turn_call_restart' });
    store.close();
    const reopened = WalStore.open({
      recordsRoot: root,
      worldId: 'w-demo',
      runId: 'run_projection_2',
      bootId: 'authz_boot_projection_2',
      policyVersion: policy.policy.policy_version,
      policyContentDigest: policy.policyContentDigest,
      evaluatorBuildDigest: buildDigest,
      now: () => clock.now,
    });
    stores.push(reopened);
    const restarted = new ConversationProjectionService({
      store: reopened,
      cards: CardRegistry.load(CARDS),
      keyring,
      caseId: 'case_demo',
      authorizationBootId: 'authz_boot_projection_2',
      screeningFixtures: fixtures,
      systemUse: syntheticSystemUseForTests(reopened),
      now: () => clock.now,
    });
    expect(reopened.snapshot().modelCalls.get(started.call.call_id)).toMatchObject({
      authorization_boot_id: 'authz_boot_projection_1',
      state: 'open',
      outcome: 'indeterminate',
    });
    await expect(
      restarted.completeCall({
        call_id: started.call.call_id,
        output: outputFor(started),
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/unavailable/);
    await expect(restarted.beginCall({ ...beginInput, turn_id: started.call.turn_id })).rejects.toThrowError(
      /already has a durable call attempt/,
    );
  });
});

describe('M5.6 system-use failure evidence', () => {
  it('rejects authorization-owned selection invalidation on the caller-facing failure schema', () => {
    expect(
      modelCallFailureRequest.safeParse({
        call_id: 'mcl_forged_selection_failure',
        turn_id: 'turn_forged_selection_failure',
        selection_id: 'sel_forged_selection_failure',
        projection_digest: '0'.repeat(64),
        failure_reason: 'selection-invalidated',
        provider_disclosure: 'possible',
        served_id: null,
      }).success,
    ).toBe(false);
  });

  it('derives confirmed invalidation from a served output request and persists the matching evidence', async () => {
    const { service, store, systemUse, selectionId } = await setup();
    const start = await service.beginCall({
      selection_id: selectionId,
      actor: ORCHESTRATOR,
      turn_id: 'turn_system_use_confirmed',
    });
    await systemUse.transition('sud_test_fixture', 1, 'suspended', AUTHZ);
    const content = 'Synthetic response that must not be admitted after system-use suspension.';
    await expect(
      service.completeCall({
        call_id: start.call.call_id,
        output: {
          turn_id: start.call.turn_id,
          selection_id: start.call.selection_id,
          mandate_id: start.call.mandate_id,
          mandate_version: start.call.mandate_version,
          card_id: start.call.card_id,
          card_version: start.call.card_version,
          requested_id: start.call.requested_id,
          served_id: start.call.requested_id,
          projection_digest: start.call.projection_digest,
          content,
        },
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/durably refused/);
    expect(store.snapshot().modelCalls.get(start.call.call_id)).toEqual({
      ...start.call,
      state: 'terminal',
      outcome: 'failed',
      provider_disclosure: 'confirmed',
      completed_at: '2026-08-01T09:00:00.000Z',
      served_id: start.call.requested_id,
      output_digest: null,
      failure_reason: 'system-use-invalidated',
    });
    expect(JSON.stringify(store.snapshot())).not.toContain(content);
  });
});
