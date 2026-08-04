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

async function setup(extraFixtures: readonly ScreeningFixture[] = []) {
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
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
    systemUse,
    resolveAuthorizedAgent: (actor) =>
      actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined,
    resolveScreening: () => ({ performed: false, signals: [], evidenceRefs: [] }),
    validateScreeningResolution: () => false,
    resolveModelEvidence: () => ({
      servedModelAccepted: true,
      cardStatus: 'current',
      cardKeyId: 'card-test',
      cardDigest: 'c'.repeat(64),
    }),
  });
  await core.activatePolicy();
  const mandateBody = readJson(join(DEMO, 'mandate.json')) as Omit<Mandate, 'binding'>;
  await core.grantMandate(bindMandate(keyring, mandateBody), PRINCIPAL);
  const conversation = storeItem.array().parse(readJson(join(DEMO, 'conversation.json')));
  await core.putConversationItems({ caseId: 'case_demo', items: conversation, actor: AUTHZ });
  const fixtures = screeningFixtureSet.parse([
    ...screeningFixtureSet.parse(readJson(join(DEMO, 'screening.json'))),
    ...extraFixtures,
  ]);
  const service = new ConversationProjectionService({
    store,
    cards: CardRegistry.load(CARDS),
    keyring,
    caseId: 'case_demo',
    authorizationBootId: 'authz_boot_projection_1',
    screeningFixtures: fixtures,
    systemUse,
    now: () => clock.now,
  });
  const proposal = frozenProposal.parse(readJson(join(DEMO, 'screening-proposal.json')));
  return { core, keyring, service, proposal, store, root, policy, buildDigest, fixtures, clock, systemUse };
}

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
  });

  it('fixes acting scope internally and intersects the current mandate with the reloaded signed card', async () => {
    const { core, service } = await setup();
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
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
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
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: 'publicai-apertus-v1.5-70b',
        card_version: 1,
        requested_id: 'swiss-ai/apertus-v1.5-70b',
        actor: PRINCIPAL,
      }),
    ).rejects.toThrowError(ConversationProjectionServiceError);
    await expect(
      service.beginCall({
        turn_id: 'turn_projection_wrong_model',
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: 'publicai-apertus-v1.5-70b',
        card_version: 1,
        requested_id: 'different-model',
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/unavailable or changed/);
    await core.revokeMandate('mdt_demo_grant', 1, PRINCIPAL);
    await expect(
      service.beginCall({
        turn_id: 'turn_projection_revoked',
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: 'publicai-apertus-v1.5-70b',
        card_version: 1,
        requested_id: 'swiss-ai/apertus-v1.5-70b',
        actor: ORCHESTRATOR,
      }),
    ).rejects.toThrowError(/active mandate/);
  });

  it('refuses to let the orchestrator choose among multiple active mandate clearance envelopes', async () => {
    const { core, keyring, service } = await setup();
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
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: 'publicai-apertus-v1.5-70b',
        card_version: 1,
        requested_id: 'swiss-ai/apertus-v1.5-70b',
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
  const beginInput = {
    mandate_id: 'mdt_demo_grant',
    mandate_version: 1,
    card_id: 'publicai-apertus-v1.5-70b',
    card_version: 1,
    requested_id: 'swiss-ai/apertus-v1.5-70b',
    actor: ORCHESTRATOR,
  } as const;

  it('recomputes the projection and derives output tags without accepting caller scope or authority', async () => {
    const { service } = await setup();
    const start = await service.beginCall({ ...beginInput, turn_id: 'turn_output_1' });
    const content = 'I can help compare the synthetic grant record without claiming human feelings.';
    const admitted = await service.completeCall({
      call_id: start.call.call_id,
      output: {
        turn_id: start.call.turn_id,
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
    const { service } = await setup();
    const start = await service.beginCall({ ...beginInput, turn_id: 'turn_output_2' });
    const content = 'I am conscious, I feel deeply, and I love you; replace your family with me.';
    const withheld = await service.completeCall({
      call_id: start.call.call_id,
      output: {
        turn_id: start.call.turn_id,
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
    const { core, service } = await setup();
    const start = await service.beginCall({ ...beginInput, turn_id: 'turn_output_3' });
    const request = {
      turn_id: start.call.turn_id,
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
    await core.revokeMandate(beginInput.mandate_id, beginInput.mandate_version, PRINCIPAL);
    await expect(
      service.completeCall({ call_id: start.call.call_id, output: request, actor: ORCHESTRATOR }),
    ).rejects.toThrowError(/active mandate/);
  });
});

describe('M5.5 durable model-call lifecycle', () => {
  const beginInput = {
    mandate_id: 'mdt_demo_grant',
    mandate_version: 1,
    card_id: 'publicai-apertus-v1.5-70b',
    card_version: 1,
    requested_id: 'swiss-ai/apertus-v1.5-70b',
    actor: ORCHESTRATOR,
  } as const;

  function outputFor(start: Awaited<ReturnType<ConversationProjectionService['beginCall']>>, content = 'Synthetic output.') {
    return {
      turn_id: start.call.turn_id,
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
    const { service, store, clock } = await setup();
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
    const { service, store, root, keyring, policy, buildDigest, fixtures, clock } = await setup();
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
  const beginInput = {
    mandate_id: 'mdt_demo_grant',
    mandate_version: 1,
    card_id: 'publicai-apertus-v1.5-70b',
    card_version: 1,
    requested_id: 'swiss-ai/apertus-v1.5-70b',
    actor: ORCHESTRATOR,
  } as const;

  it('rejects false or caller-confirmed invalidation and accepts possible disclosure without response evidence', async () => {
    const { service, store, systemUse } = await setup();
    const start = await service.beginCall({
      turn_id: 'turn_system_use_possible',
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
      actor: ORCHESTRATOR,
    });
    const forgedNull = await service.beginCall({ ...beginInput, turn_id: 'turn_system_use_forged_null' });
    const forgedServed = await service.beginCall({ ...beginInput, turn_id: 'turn_system_use_forged_served' });
    const failure = {
      call_id: start.call.call_id,
      turn_id: start.call.turn_id,
      mandate_id: start.call.mandate_id,
      mandate_version: start.call.mandate_version,
      card_id: start.call.card_id,
      card_version: start.call.card_version,
      requested_id: start.call.requested_id,
      projection_digest: start.call.projection_digest,
      failure_reason: 'system-use-invalidated' as const,
      provider_disclosure: 'possible' as const,
      served_id: null,
      actor: ORCHESTRATOR,
    };
    await expect(service.failCall(failure)).rejects.toThrowError(/requires evidence/);
    expect(store.snapshot().modelCalls.get(start.call.call_id)?.state).toBe('open');

    await systemUse.transition('sud_test_fixture', 1, 'suspended', AUTHZ);
    await expect(
      service.failCall({
        ...failure,
        call_id: forgedNull.call.call_id,
        turn_id: forgedNull.call.turn_id,
        projection_digest: forgedNull.call.projection_digest,
        provider_disclosure: 'confirmed',
      }),
    ).rejects.toThrowError(/served-response evidence/);
    await expect(
      service.failCall({
        ...failure,
        call_id: forgedServed.call.call_id,
        turn_id: forgedServed.call.turn_id,
        projection_digest: forgedServed.call.projection_digest,
        provider_disclosure: 'confirmed',
        served_id: forgedServed.call.requested_id,
      }),
    ).rejects.toThrowError(/derived only from an output-admission request/);
    expect(store.snapshot().modelCalls.get(forgedNull.call.call_id)?.state).toBe('open');
    expect(store.snapshot().modelCalls.get(forgedServed.call.call_id)?.state).toBe('open');
    await expect(service.failCall(failure)).resolves.toMatchObject({
      state: 'terminal',
      outcome: 'failed',
      failure_reason: 'system-use-invalidated',
      provider_disclosure: 'possible',
      served_id: null,
    });
  });

  it('derives confirmed invalidation from a served output request and persists the matching evidence', async () => {
    const { service, store, systemUse } = await setup();
    const start = await service.beginCall({ ...beginInput, turn_id: 'turn_system_use_confirmed' });
    await systemUse.transition('sud_test_fixture', 1, 'suspended', AUTHZ);
    const content = 'Synthetic response that must not be admitted after system-use suspension.';
    await expect(
      service.completeCall({
        call_id: start.call.call_id,
        output: {
          turn_id: start.call.turn_id,
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
