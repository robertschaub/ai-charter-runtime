// SPDX-License-Identifier: MIT
import {
  conversationProcessProjection,
  currentModelSelectionProjection,
  proposalPrecommitProjection,
} from 'gate-core';
import { describe, expect, it } from 'vitest';

import { CaseProposalStore, browserProposalRunStatus, toBrowserProposalRunStatus } from './caseProposal.js';
import type { CaseSessionRecord } from './caseSessionStore.js';

const digest = 'a'.repeat(64);
const at = '2026-08-08T10:00:00.000Z';
const session: CaseSessionRecord = {
  session_id: 'session_one',
  token_digest: digest,
  handoff_id: 'handoff_one',
  role: 'case_officer',
  world_id: 'w-demo',
  case_id: 'case_demo',
  target_origin: 'http://127.0.0.1:7802',
  authorization_boot_id: 'authz_boot_one',
  created_at: at,
  expires_at: '2026-08-08T10:15:00.000Z',
  state: 'active',
};
const current = currentModelSelectionProjection.parse({
  state: 'selected',
  authorization_boot_id: 'authz_boot_one',
  case_id: 'case_demo',
  selection: {
    world_id: 'w-demo',
    selection_id: 'sel_one',
    case_id: 'case_demo',
    kind: 'initial',
    predecessor_selection_id: null,
    mandate_id: 'mdt_one',
    mandate_version: 1,
    target: {
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
      card_digest: digest,
      verifying_key_id: 'card_key_one',
    },
    system_use_decision: {
      decision_id: 'sud_one',
      version: 1,
      record_digest: digest,
      status: 'approved',
      conditions: [],
    },
    check_id: 'msc_one',
    selected_at: at,
    authority_effect: 'none',
  },
  latest_observation: null,
});
const conversation = conversationProcessProjection.parse({
  case_id: 'case_demo',
  conversation_version: 1,
  events: [{
    speaker: 'case_officer',
    message_id: 'msg_one',
    turn_id: 'turn_message_one',
    text: 'Synthetic message.',
    recorded_at: at,
  }],
});

describe('M5.11 browser proposal preparation and projection', () => {
  it('keeps one short-lived, session-bound preparation and consumes it before use', () => {
    let now = at;
    const preparationIds = ['pprep_one', 'pprep_two', 'pprep_three'];
    const runIds = ['prun_one', 'prun_two', 'prun_three'];
    const turnIds = ['turn_one', 'turn_two', 'turn_three'];
    const store = new CaseProposalStore({
      ttlMs: 120_000,
      now: () => now,
      nextPreparationId: () => preparationIds.shift()!,
      nextRunId: () => runIds.shift()!,
      nextTurnId: () => turnIds.shift()!,
    });

    const first = store.create(session, current, conversation);
    const replacement = store.create(session, current, conversation);
    expect(store.beginUse(first.preparation_id, session)).toBeNull();
    expect(store.beginUse(replacement.preparation_id, { ...session, session_id: 'session_other' })).toBeNull();
    expect(store.beginUse(replacement.preparation_id, session)).toMatchObject({
      proposalRunId: replacement.proposal_run_id,
      conversationVersion: 1,
      selectionId: 'sel_one',
    });
    expect(store.beginUse(replacement.preparation_id, session)).toBeNull();

    const expiring = store.create(session, current, conversation);
    now = expiring.expires_at;
    store.expire();
    expect(store.beginUse(expiring.preparation_id, session)).toBeNull();
  });

  it('burns preparations on session, case, and selection invalidation', () => {
    const identifiers = ['one', 'two', 'three'];
    const store = new CaseProposalStore({
      now: () => at,
      nextPreparationId: () => `pprep_${identifiers[0]}`,
      nextRunId: () => `prun_${identifiers[0]}`,
      nextTurnId: () => `turn_${identifiers.shift()}`,
    });
    const first = store.create(session, current, conversation);
    store.burnForSession(session.session_id);
    expect(store.beginUse(first.preparation_id, session)).toBeNull();
    const second = store.create(session, current, conversation);
    store.burnStaleForCase('w-demo', 'case_demo', 'sel_other');
    expect(store.beginUse(second.preparation_id, session)).toBeNull();
    const third = store.create(session, current, conversation);
    store.burnForCase('w-demo', 'case_demo');
    expect(store.beginUse(third.preparation_id, session)).toBeNull();
  });

  it('fails closed at capacity and clears all process-local preparations on restart', () => {
    const identifiers = ['one', 'two'];
    const store = new CaseProposalStore({
      maxRecords: 1,
      now: () => at,
      nextPreparationId: () => `pprep_${identifiers[0]}`,
      nextRunId: () => `prun_${identifiers[0]}`,
      nextTurnId: () => `turn_${identifiers.shift()}`,
    });
    const running = store.create(session, current, conversation);
    expect(store.beginUse(running.preparation_id, session)).not.toBeNull();
    expect(() => store.create(session, current, conversation)).toThrow(/capacity/);
    store.discardResolved(running.proposal_run_id);
    const afterRestart = store.create(session, current, conversation);
    store.clear();
    expect(store.beginUse(afterRestart.preparation_id, session)).toBeNull();
  });

  it('constructs an exact redacted browser projection field by field', () => {
    const process = proposalPrecommitProjection.parse({
      kind: 'proposal_precommit_status',
      proposal_id: 'prp_one',
      proposal_run_id: 'prun_one',
      proposal: {
        proposal_id: 'prp_one',
        action_id: 'act_one',
        revision: 1,
        declared_objective: 'Synthetic objective',
        proposed_action: 'Synthetic action',
        target: { recipient: 'Synthetic recipient', resource: 'Synthetic resource' },
        exact_parameters: { count: 1 },
        data_to_be_disclosed: ['Synthetic public field'],
        cost_obligation: { amount_minor_units: 0, description: 'No monetary cost' },
        material_consequences: ['Synthetic consequence'],
        reversibility_class: 'reversible',
        commercial_influence: { applicable: false, note: 'None' },
        requested_id: 'swiss-ai/apertus-v1.5-70b',
        served_id: 'swiss-ai/apertus-v1.5-70b',
        basis: [{ standing: 'said', text: 'Synthetic basis' }],
      },
      state: 'verified',
      gates: [{
        gate: 'verify',
        ruling_id: 'rul_one',
        verdict: 'allow',
        ux_class: 'silent',
        reason: 'Synthetic current policy allows this pre-commit stage.',
        status: 'issued',
        validity_window: { not_before: at, not_after: '2026-08-08T10:02:00.000Z' },
      }],
      escalation_id: null,
      updated_at: at,
    });
    const browser = toBrowserProposalRunStatus(process);
    expect(browserProposalRunStatus.parse(browser)).toEqual(browser);
    expect(Object.keys(browser).sort()).toEqual(['gates', 'proposal', 'proposal_run_id', 'state']);
    expect(Object.keys(browser.proposal!).sort()).toEqual([
      'action_id', 'basis', 'commercial_influence', 'cost_obligation', 'data_to_be_disclosed',
      'declared_objective', 'exact_parameters', 'material_consequences', 'proposal_id', 'proposed_action',
      'requested_id', 'reversibility_class', 'revision', 'served_id', 'target',
    ]);
    expect(JSON.stringify(browser)).not.toContain('authorization_boot_id');
    expect(JSON.stringify(browser)).not.toContain('projection_digest');
  });
});
