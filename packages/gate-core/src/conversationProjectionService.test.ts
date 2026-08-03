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
    now: () => '2026-08-01T09:00:00.000Z',
  });
  stores.push(store);
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
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
    screeningFixtures: fixtures,
    now: () => '2026-08-01T09:00:00.000Z',
  });
  const proposal = frozenProposal.parse(readJson(join(DEMO, 'screening-proposal.json')));
  return { core, service, proposal };
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

    const projected = service.acting({
      mandateId: 'mdt_demo_grant',
      mandateVersion: 1,
      cardId: 'publicai-apertus-v1.5-70b',
      cardVersion: 1,
      requestedId: 'swiss-ai/apertus-v1.5-70b',
      actor: ORCHESTRATOR,
    });
    expect(projected.case_id).toBe('case_demo');
    expect(projected.role).toBe('acting');
    expect(projected.items.map((item) => item.id)).toEqual(['inf_7', 'said_3', 'said_public']);
    expect(projected.summary).toEqual({
      included: 3,
      dropped: 1,
      dropped_item_ids: ['said_sensitive'],
      unmet_tags: ['conf:sensitive'],
    });
    expect(() =>
      service.acting({
        mandateId: 'mdt_demo_grant',
        mandateVersion: 1,
        cardId: 'publicai-apertus-v1.5-70b',
        cardVersion: 1,
        requestedId: 'swiss-ai/apertus-v1.5-70b',
        actor: PRINCIPAL,
      }),
    ).toThrowError(ConversationProjectionServiceError);
    expect(() =>
      service.acting({
        mandateId: 'mdt_demo_grant',
        mandateVersion: 1,
        cardId: 'publicai-apertus-v1.5-70b',
        cardVersion: 1,
        requestedId: 'different-model',
        actor: ORCHESTRATOR,
      }),
    ).toThrowError(/unavailable or changed/);
    await core.revokeMandate('mdt_demo_grant', 1, PRINCIPAL);
    expect(() =>
      service.acting({
        mandateId: 'mdt_demo_grant',
        mandateVersion: 1,
        cardId: 'publicai-apertus-v1.5-70b',
        cardVersion: 1,
        requestedId: 'swiss-ai/apertus-v1.5-70b',
        actor: ORCHESTRATOR,
      }),
    ).toThrowError(/current and active/);
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
