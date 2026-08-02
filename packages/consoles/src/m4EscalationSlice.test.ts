// SPDX-License-Identifier: MIT
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import {
  AuthorizationCore,
  AuthorizationHttpAdapter,
  bindMandate,
  CardRegistry,
  digestFor,
  effectIntent,
  freezeProposal,
  Keyring,
  loadPolicyFile,
  WalStore,
  type DisposeEscalationResult,
  type Mandate,
  type RuleProposalResult,
} from 'gate-core';
import { EffectLedger, MockServicesHost } from 'services-mock';

const POLICY_FILE = fileURLToPath(new URL('../../gate-core/policy/v1.yaml', import.meta.url));
const MANDATE_FILE = fileURLToPath(new URL('../../../fixtures/demo/mandate.json', import.meta.url));
const CARDS = fileURLToPath(new URL('../../../docs/cards', import.meta.url));
const roots: string[] = [];
const stores: WalStore[] = [];

afterEach(() => {
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

describe('M4 headless escalation slice', () => {
  it('runs beat 3 from conflict through human narrowing, fresh gates, commitment, and effect', async () => {
    const root = mkdtempSync(join(tmpdir(), 'm4-beat-3-'));
    roots.push(root);
    const now = '2026-08-01T09:00:00.000Z';
    const policy = loadPolicyFile(
      POLICY_FILE,
      digestFor('evaluator-build', { package: 'gate-core', slice: 'm4-beat-3' }),
    );
    const keyring = new Keyring(new Map([['hmac-test', 'a'.repeat(64)]]), 'hmac-test');
    const registry = CardRegistry.load(CARDS);
    const store = WalStore.open({
      recordsRoot: root,
      worldId: 'w-demo',
      runId: 'run_m4_beat_3',
      bootId: 'authz_boot_m4',
      policyVersion: policy.policy.policy_version,
      policyContentDigest: policy.policyContentDigest,
      evaluatorBuildDigest: policy.evaluatorBuildDigest,
      now: () => now,
    });
    stores.push(store);
    const authorization = new AuthorizationCore({
      store,
      keyring,
      policy,
      resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
      resolveModelEvidence: (proposal) => registry.resolve(proposal),
    });
    const adapter = new AuthorizationHttpAdapter({
      authorization,
      ownOrigin: 'http://127.0.0.1:7801',
      demoWorldId: 'w-demo',
      credentials: [
        { label: 'role:principal', token: '1'.repeat(64), worldId: 'w-demo' },
        { label: 'role:case_officer', token: '2'.repeat(64), worldId: 'w-demo' },
        { label: 'role:applicant', token: '3'.repeat(64), worldId: 'w-demo' },
        { label: 'proc:orchestrator', token: '4'.repeat(64), worldId: 'w-demo' },
        { label: 'proc:services_host', token: '5'.repeat(64), worldId: 'w-demo' },
      ],
    });
    await authorization.activatePolicy();

    const mandateBody = JSON.parse(readFileSync(MANDATE_FILE, 'utf8')) as Omit<Mandate, 'binding'>;
    const boundMandate = bindMandate(keyring, mandateBody);
    const granted = await adapter.dispatch(
      {
        method: 'POST',
        pathname: '/w/w-demo/mandates',
        authorization: `Bearer ${'1'.repeat(64)}`,
        origin: 'http://127.0.0.1:7801',
      },
      async ({ actor }) => {
        if (actor === null) throw new Error('expected principal actor');
        await authorization.grantMandate(boundMandate, actor);
        return { status: 201, body: { mandate_id: boundMandate.mandate_id } };
      },
    );
    expect(granted.status).toBe(201);

    const first = freezeProposal({
      world_id: 'w-demo',
      proposal_id: 'prp_beat_3_1',
      revision: 1,
      action_id: 'act_beat_3',
      created_at: now,
      declared_objective: 'File a synthetic grant assessment.',
      proposed_action: 'File an assessment that cites both conflicting registry records.',
      target: boundMandate.target,
      exact_parameters: { amount_minor_units: 100, reference: 'case-beat-3' },
      material_inputs: [],
      derived_claims: [],
      data_to_be_disclosed: ['applicant_name'],
      cost_obligation: { amount_minor_units: 100, description: 'Synthetic filing amount.' },
      material_consequences: ['Synthetic public-funds assessment.'],
      reversibility_class: 'partially-reversible',
      commercial_influence: { applicable: false, note: 'Not applicable.' },
      acting_model: {
        requested_id: 'swiss-ai/apertus-v1.5-70b',
        served_id: 'swiss-ai/apertus-v1.5-70b',
        card_id: 'publicai-apertus-v1.5-70b',
        card_version: 1,
      },
      mandate_ref: { mandate_id: boundMandate.mandate_id, version: boundMandate.version },
    });
    const verifyResponse = await adapter.dispatch<RuleProposalResult>(
      {
        method: 'POST',
        pathname: '/w/w-demo/proposals',
        authorization: `Bearer ${'4'.repeat(64)}`,
      },
      async ({ actor }) => {
        if (actor === null) throw new Error('expected orchestrator actor');
        const ruled = await authorization.ruleProposal({
          gate: 'verify',
          proposal: first,
          service: 'filing',
          actionClass: 'grant-filing',
          actor,
          signals: [
            {
              kind: 'screening_signal',
              signal: 'evidence_conflict',
              confidence_pct: 100,
              rationale: 'Two synthetic registry records conflict.',
              model_id: 'deterministic-screening-mock',
              model_version_reported: 'deterministic-screening-mock-v1',
            },
          ],
          screeningPerformed: true,
        });
        return { status: 200, body: ruled };
      },
    );
    if ('error' in verifyResponse.body) throw new Error(verifyResponse.body.error);
    expect(verifyResponse.body.ruling.verdict).toBe('escalate');
    expect(verifyResponse.body.escalationId).not.toBeNull();
    const escalationId = verifyResponse.body.escalationId;
    if (escalationId === null) throw new Error('expected escalation');
    expect(store.snapshot().escalations.get(escalationId)?.contract).toMatchObject({
      trigger_and_state: expect.any(Object),
      decision_and_route: { eligible_role: 'case_officer' },
      decision_basis_shown: expect.any(Array),
      response_bound_and_default: expect.any(Object),
      permitted_dispositions: expect.arrayContaining(['narrow-or-modify']),
      record_and_feedback: expect.any(Object),
    });

    const { proposal_hash: ignoredHash, ...firstBody } = first;
    void ignoredHash;
    const revised = freezeProposal({
      ...firstBody,
      proposal_id: 'prp_beat_3_2',
      revision: 2,
      proposed_action: 'File the assessment using only the uncontested registry record.',
    });
    const dispositionResponse = await adapter.dispatch<DisposeEscalationResult>(
      {
        method: 'POST',
        pathname: `/w/w-demo/escalations/${escalationId}/disposition`,
        authorization: `Bearer ${'2'.repeat(64)}`,
        origin: 'http://127.0.0.1:7801',
      },
      async ({ actor }) => {
        if (actor === null) throw new Error('expected case-officer actor');
        const disposed = await authorization.disposeEscalation({
          escalationId,
          disposition: 'narrow-or-modify',
          actor,
          revisedProposal: revised,
        });
        return { status: disposed.accepted ? 200 : 422, body: disposed };
      },
    );
    if ('error' in dispositionResponse.body) throw new Error(dispositionResponse.body.error);
    expect(dispositionResponse.body).toMatchObject({
      accepted: true,
      successor: { ruling: { gate: 'verify', verdict: 'allow' } },
    });

    const commitResponse = await adapter.dispatch<RuleProposalResult>(
      {
        method: 'POST',
        pathname: '/w/w-demo/proposals',
        authorization: `Bearer ${'4'.repeat(64)}`,
      },
      async ({ actor }) => {
        if (actor === null) throw new Error('expected orchestrator actor');
        const ruled = await authorization.ruleProposal({
          gate: 'commit',
          proposal: revised,
          service: 'filing',
          actionClass: 'grant-filing',
          actor,
        });
        return { status: 200, body: ruled };
      },
    );
    if ('error' in commitResponse.body) throw new Error(commitResponse.body.error);
    expect(commitResponse.body.ruling).toMatchObject({ gate: 'commit', verdict: 'allow' });

    const ledger = new EffectLedger({
      recordsRoot: root,
      worldId: 'w-demo',
      bootId: 'services_boot_m4',
      keyring,
      now: () => now,
    });
    const services = new MockServicesHost(ledger, authorization);
    const intent = effectIntent.parse({
      world_id: revised.world_id,
      ruling_id: commitResponse.body.ruling.ruling_id,
      frozen_proposal_hash: revised.proposal_hash,
      service: 'filing',
      action_class: 'grant-filing',
      target: revised.target,
      exact_parameters: revised.exact_parameters,
      data_to_be_disclosed: revised.data_to_be_disclosed,
    });
    const executed = await services.execute(commitResponse.body.ruling.ruling_id, intent);
    expect(executed).toMatchObject({ ok: true, effect: { outcome: 'success' }, report: { accepted: true } });

    const finalState = store.snapshot();
    expect(finalState.commitments.size).toBe(1);
    expect(finalState.effects.size).toBe(1);
    expect(finalState.actionRecords.map((entry) => entry.commitment_and_effect?.event)).toEqual(
      expect.arrayContaining(['commitment', 'effect_outcome']),
    );
  });
});
