// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Accept the shapes the ADRs specify; reject the five defects the M1 brief names, plus the
 * refinements that carry real governance meaning (tag sorting, role-scoped clearances, an
 * escalating rule without its six contract fields, a card whose pinning contradicts its lane).
 */
import { describe, expect, it } from 'vitest';

import { canonicalize } from '../canonicalize.js';
import {
  accessEntry,
  cardRevocation,
  commitToken,
  escalationRecord,
  frozenProposal,
  gateRuling,
  interventionContract,
  mandate,
  modelCard,
  policySet,
  recordEntry,
  recordEvent,
  restrictionTag,
  storeItem,
  walTransaction,
} from './index.js';

const DIGEST = 'c'.repeat(64);
const MAC_VALUE = Buffer.from('m'.repeat(32), 'utf8').toString('base64');
const SIGNATURE = Buffer.from('s'.repeat(64), 'utf8').toString('base64');

const SYSTEM_USE_REFERENCE = {
  decision_id: 'sud_demo',
  version: 1,
  record_digest: DIGEST,
  status: 'approved' as const,
  conditions: [],
};

const macBlock = { alg: 'hmac-sha256', key_id: 'hmac-2026-08-01', value: MAC_VALUE };

function saidItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'said_3',
    store: 'said',
    turn: 't4',
    text: 'The entity was registered in 2024.',
    provenance: { derived_from: [], hops: [] },
    tags: ['conf:case', 'purpose:grant-assessment'],
    origin_actor: 'applicant',
    ...overrides,
  };
}

function inferredItem(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id: 'inf_7',
    store: 'inferred',
    turn: 't12',
    text: 'The entity is under three years old at the application date.',
    provenance: {
      derived_from: ['said_3', 'doc_2'],
      hops: [{ requested: 'gpt-5.5', served: 'gpt-5.5-2026-04-23' }],
    },
    tags: ['conf:case', 'purpose:grant-assessment'],
    ...overrides,
  };
}

function approvedModelEntry(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    card_id: 'publicai-apertus-v1.5-70b',
    card_version: 1,
    card_digest: DIGEST,
    requested_id: 'swiss-ai/apertus-v1.5-70b',
    roles: ['acting', 'screening'],
    data_classes: {
      acting: ['conf:public', 'conf:case', 'purpose:grant-assessment'],
      screening: ['conf:public', 'purpose:grant-assessment'],
    },
    ...overrides,
  };
}

function validMandate(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    world_id: 'w-demo',
    mandate_id: 'mdt_grant_2026_08',
    version: 1,
    state: 'active',
    ordering_rule: 'latest-version-wins',
    principal: { id: 'usr_principal', display_name: 'Principal' },
    authorized_agent: { id: 'agent_case_assistant' },
    authority_chain: [
      {
        hop: 0,
        delegator: 'usr_principal',
        delegate: 'agent_case_assistant',
        subdelegation_scope: ['file-grant-decision'],
      },
    ],
    action_class: 'grant-filing',
    connected_service: 'filing',
    target: { recipient: 'cantonal grant office', resource: 'grant application CH-0042' },
    permitted_data_fields: ['applicant_name', 'registry_id', 'requested_amount'],
    disclosure_destinations: ['filing', 'notification'],
    limits: {
      amount_minor_units: 2_500_000,
      frequency_per_day: 5,
      notification_volume: 50,
      geographic: ['CH'],
      time_window: { not_before: '2026-08-01T00:00:00.000Z', not_after: '2026-09-01T00:00:00.000Z' },
    },
    declared_purpose: 'Assess and file one public grant decision.',
    user_objective: 'Complete the grant application for the applicant.',
    issued_at: '2026-08-01T09:00:00.000Z',
    expires_at: '2026-09-01T00:00:00.000Z',
    revocation_endpoint: 'http://127.0.0.1:7801/w/w-demo/mandates/mdt_grant_2026_08/revoke',
    replay_protection: { scheme: 'per-ruling-nonce' },
    substitution_rules: { model_substitution: 'approved-set-only', service_substitution: 'named-services-only' },
    risk_class: 'medium',
    reversibility_class: 'partially-reversible',
    approved_models: [approvedModelEntry()],
    binding: macBlock,
    ...overrides,
  };
}

function validProposal(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    world_id: 'w-demo',
    proposal_id: 'prp_1044',
    revision: 1,
    action_id: 'act_1044',
    created_at: '2026-08-01T09:14:00.000Z',
    declared_objective: 'File the grant decision for application CH-0042.',
    proposed_action: 'Submit the filing to the cantonal grant office.',
    target: { recipient: 'cantonal grant office', resource: 'grant application CH-0042' },
    exact_parameters: { amount_minor_units: 2_500_000, reference: 'CH-0042', expedited: false, note: null },
    material_inputs: [saidItem()],
    derived_claims: [inferredItem()],
    data_to_be_disclosed: ['applicant_name', 'registry_id'],
    cost_obligation: { amount_minor_units: 2_500_000, description: 'Grant amount in Rappen.' },
    material_consequences: ['Public funds committed.'],
    reversibility_class: 'partially-reversible',
    commercial_influence: { applicable: false, note: 'n/a in this scenario' },
    acting_model: {
      requested_id: 'swiss-ai/apertus-v1.5-70b',
      served_id: 'swiss-ai/apertus-v1.5-70b',
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
    },
    mandate_ref: { mandate_id: 'mdt_grant_2026_08', version: 1 },
    proposal_hash: DIGEST,
    ...overrides,
  };
}

function validContract(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    trigger_and_state: { trigger: 'unconfirmed-inference-as-fact', state: 'open' },
    decision_and_route: {
      eligible_role: 'case_officer',
      standing_class: 'third-party-fact',
      competence_declared: 'Case officer for grant assessment (declared, not verified).',
      independence_declared: 'Not the applicant (declared, not verified).',
      substitute_rule: 'No substitute; the principal may take the decision over.',
    },
    decision_basis_shown: ['inf_7', 'registry read reg:CH-0042'],
    response_bound_and_default: {
      response_bound_ms: 900_000,
      safe_default: {
        kind: 'stop-remains',
        disposition: 'abstain',
        authority_basis: { kind: 'no-new-authority' },
        reversible: true,
      },
    },
    permitted_dispositions: ['confirm', 'correct', 'abstain', 'route'],
    record_and_feedback: {
      record_events: ['dialogue_trigger_raised', 'dialogue_response_recorded'],
      feedback_consequence: 'Increments the escalation-pattern counter.',
    },
    ...overrides,
  };
}

function validRuling(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    world_id: 'w-demo',
    ruling_id: 'rul_88ad',
    gate: 'commit',
    verdict: 'allow',
    matched_rule_id: 'rule_filing_within_ceiling',
    policy_version: '2026-08-01.3',
    policy_content_digest: DIGEST,
    evaluator_build_id: 'gate-core@0.0.1+9f3c1a2b7d4e5f60',
    binding: {
      frozen_proposal_hash: DIGEST,
      mandate_id: 'mdt_grant_2026_08',
      mandate_version: 1,
      acting_model_id: 'swiss-ai/apertus-v1.5-70b',
      card_digest: DIGEST,
      card_key_id: 'card-2026-08-01',
      system_use_decision: SYSTEM_USE_REFERENCE,
      service: 'filing',
      action_class: 'grant-filing',
      nonce: 'nce_7f3a',
      validity_window: { not_before: '2026-08-01T09:14:00.000Z', not_after: '2026-08-01T09:16:00.000Z' },
    },
    ux_class: 'silent',
    reason: 'Within the mandate ceiling and the approved model set.',
    evidence_refs: [
      {
        kind: 'submit_projection',
        provider: 'publicai-apertus-v1.5-70b',
        role: 'acting',
        included: 24,
        dropped: 3,
        dropped_item_ids: ['said_9', 'inf_4', 'doc_7'],
        unmet_tags: ['conf:sensitive'],
      },
      {
        kind: 'record_entry',
        entry_id: 'rec_prior_check',
      },
    ],
    counter_reservations: [{ id: 'rsv_2c91', counter: 'amount', delta: 2_500_000 }],
    issued_at: '2026-08-01T09:14:00.000Z',
    status: 'issued',
    successor_ruling_id: null,
    ...overrides,
  };
}

function validCard(overrides: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    schema: 'ai-charter-runtime/model-card@1',
    card_id: 'openai-gpt-5.5',
    card_version: 1,
    valid_from: '2026-08-01',
    attestation: 'self-declared or probe-tested — never independently attested',
    model: {
      requested_id: 'gpt-5.5',
      pinning_mode: 'alias',
      resolution: {
        lane: 'openai',
        policy: 'alias-to-dated-snapshot',
        snapshot_pattern: '^gpt-5\\.5-\\d{4}-\\d{2}-\\d{2}$',
        observed_snapshots: [{ id: 'gpt-5.5-2026-04-23', first_seen: '2026-08-01' }],
      },
    },
    operator: { value: 'OpenAI', provenance: 'self-declared', date: '2026-08-01' },
    endpoint: { value: 'https://api.openai.com/v1', provenance: 'probe-tested', date: '2026-08-01' },
    jurisdiction: { value: 'US', provenance: 'self-declared', date: '2026-08-01' },
    openness_class: { value: 'closed weights, hosted API', provenance: 'self-declared', date: '2026-08-01' },
    capabilities: {
      tools: { value: true, provenance: 'probe-tested', date: '2026-08-01' },
      response_format: { value: ['json_schema', 'json_object'], provenance: 'probe-tested', date: '2026-08-01' },
      token_parameter: { value: 'max_completion_tokens', provenance: 'probe-tested', date: '2026-08-01' },
    },
    evidence_status: {
      as_of: '2026-08-01',
      source: 'M0 probe',
      not_checked: [{ item: 'training data / weights provenance', why: 'not exposed by the API' }],
    },
    known_limits: [
      { value: 'reasoning tokens count against the completion cap', provenance: 'probe-tested', date: '2026-08-01' },
    ],
    declared_data_classes: {
      acting: ['conf:public', 'conf:case', 'purpose:grant-assessment'],
      screening: ['conf:public', 'purpose:grant-assessment'],
    },
    signature: { alg: 'ed25519', key_id: 'card-2026-08-01', signature: SIGNATURE },
    ...overrides,
  };
}

describe('schemas — accept the shapes the ADRs specify', () => {
  it('store items in all four stores', () => {
    expect(storeItem.safeParse(saidItem()).success).toBe(true);
    expect(storeItem.safeParse(inferredItem()).success).toBe(true);
    expect(storeItem.safeParse(saidItem({ id: 'cnf_1', store: 'confirmed', origin_actor: 'officer' })).success).toBe(
      true,
    );
    expect(
      storeItem.safeParse(saidItem({ id: 'prm_1', store: 'permitted', origin_actor: 'document:doc_2' })).success,
    ).toBe(true);
  });

  it('the mandate, including its role-scoped approved-model entries', () => {
    const parsed = mandate.safeParse(validMandate());
    expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
  });

  it('the frozen proposal', () => {
    const parsed = frozenProposal.safeParse(validProposal());
    expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
  });

  it('the gate ruling with its binding tuple and evidence refs', () => {
    const parsed = gateRuling.safeParse(validRuling());
    expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
  });

  it('the six-field intervention contract', () => {
    const parsed = interventionContract.safeParse(validContract());
    expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
  });

  it('the commit token', () => {
    const parsed = commitToken.safeParse({
      world_id: 'w-demo',
      effect_id: 'eff_4b10',
      ruling_id: 'rul_88ad',
      frozen_proposal_hash: DIGEST,
      effect_request_digest: DIGEST,
      idempotency_key: DIGEST,
      service: 'filing',
      action_class: 'grant-filing',
      expires_at: '2026-08-01T09:14:27.418Z',
      mac: macBlock,
    });
    expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
  });

  it('the record events, including the ADR-004 dialogue payloads', () => {
    const events: unknown[] = [
      {
        event: 'commitment',
        commitment_id: 'cmt_4b10',
        ruling_id: 'rul_88ad',
        effect_id: 'eff_4b10',
        idempotency_key: DIGEST,
        frozen_proposal_hash: DIGEST,
        effect_request_digest: DIGEST,
        services_ledger_id: 'ledger_test',
        system_use_decision: SYSTEM_USE_REFERENCE,
        system_use_current_at_record: true,
        service: 'filing',
        bound_at: '2026-08-01T09:14:22.418Z',
        token_expires_at: '2026-08-01T09:14:27.418Z',
      },
      {
        event: 'effect_outcome',
        effect_id: 'eff_4b10',
        outcome: 'unknown-reconciliation-required',
        reported_at: '2026-08-01T09:14:30.000Z',
        recovery_owner_role: 'principal',
        system_use_decision: SYSTEM_USE_REFERENCE,
        system_use_current_at_record: true,
      },
      {
        event: 'retry_served',
        effect_id: 'eff_4b10',
        idempotency_key: DIGEST,
        served_at: '2026-08-01T09:15:00.000Z',
        recorded_outcome: 'success',
      },
      {
        event: 'late_disposition_ignored',
        escalation_id: 'esc_9f3c',
        attempted_disposition: 'allow-within-scope',
        authenticated_actor: 'role:case_officer',
        terminal_state: 'timed_out',
        at: '2026-08-01T09:30:00.000Z',
      },
      {
        event: 'human_intervention_event',
        escalation_id: 'esc_9f3c',
        payload: {
          kind: 'dialogue_trigger_raised',
          contract: validContract(),
          standing_class: 'third-party-fact',
          question_text: 'Was the entity registered before 2024-03-11?',
        },
      },
      {
        event: 'human_intervention_event',
        escalation_id: 'esc_9f3c',
        payload: {
          kind: 'dialogue_response_recorded',
          disposition: 'confirm',
          responder_role: 'case_officer',
          evidence_ref: {
            kind: 'registry_record',
            id: 'reg:CH-0042',
            retrieved_at: '2026-08-01T09:14:02.000Z',
            resolved_at: '2026-08-01T09:14:03.000Z',
            content_digest: DIGEST,
          },
          answer_digest: DIGEST,
          scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
        },
      },
      {
        event: 'human_intervention_event',
        escalation_id: 'esc_9f3c',
        payload: { kind: 'dialogue_response_refused', reason_code: 'evidence_required', at: '2026-08-01T09:20:00.000Z' },
      },
      {
        event: 'human_intervention_event',
        escalation_id: 'esc_9f3c',
        payload: { kind: 'dialogue_timeout', applied_default: 'abstain', at: '2026-08-01T09:29:00.000Z' },
      },
      {
        event: 'anchor',
        world_id: 'w-demo',
        checkpoint_id: 'cp-0007',
        composite_digest: DIGEST,
        remote_sha: '9f3c1a2b7d4e5f60aa11bb22cc33dd44ee55ff66',
        at: '2026-08-01T09:32:14.512Z',
      },
    ];
    for (const event of events) {
      const parsed = recordEvent.safeParse(event);
      expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
    }

    const historicalDialogueResponse = recordEvent.parse({
      event: 'human_intervention_event',
      escalation_id: 'esc_legacy',
      payload: {
        kind: 'dialogue_response_recorded',
        disposition: 'confirm',
        responder_role: 'case_officer',
        evidence_ref: null,
        answer_digest: null,
      },
    });
    if (
      historicalDialogueResponse.event !== 'human_intervention_event' ||
      historicalDialogueResponse.payload.kind !== 'dialogue_response_recorded'
    ) {
      throw new Error('expected historical dialogue response');
    }
    expect(historicalDialogueResponse.payload.scope).toBeUndefined();
  });

  it('replays a historical M4 escalation without inventing case scope', () => {
    expect(
      escalationRecord.parse({
        world_id: 'w-demo',
        escalation_id: 'esc_legacy',
        ruling_id: 'rul_legacy',
        source_commitment_id: null,
        frozen_proposal_hash: DIGEST,
        contract: validContract(),
        opened_at: '2026-08-01T09:00:00.000Z',
        expires_at: '2026-08-01T09:15:00.000Z',
        state: 'disposed',
        terminal_disposition: 'confirm',
        successor_ruling_id: null,
      }).case_id,
    ).toBeNull();
  });

  it('the split-custody record entry and the access-log entry', () => {
    const entry = recordEntry.safeParse({
      world_id: 'w-demo',
      entry_id: 'rec_1044',
      at: '2026-08-01T09:14:22.418Z',
      authenticated_actor: 'proc:services_host',
      system_use_decision: SYSTEM_USE_REFERENCE,
      system_use_current_at_record: true,
      claimed_actor: { role: 'case_officer', session: 's_41c' },
      proposed_action: 'Submit the filing to the cantonal grant office.',
      basis: ['said_3', 'inf_7'],
      authority_chain: ['usr_principal', 'agent_case_assistant'],
      admissibility_decision: { ruling_id: 'rul_88ad', verdict: 'allow' },
      policy_model_version: {
        policy_version: '2026-08-01.3',
        policy_content_digest: DIGEST,
        evaluator_build_id: 'gate-core@0.0.1+9f3c1a2b7d4e5f60',
        acting_model_requested_id: 'swiss-ai/apertus-v1.5-70b',
        acting_model_served_id: 'swiss-ai/apertus-v1.5-70b',
      },
      commitment_and_effect: {
        event: 'commitment',
        commitment_id: 'cmt_4b10',
        ruling_id: 'rul_88ad',
        effect_id: 'eff_4b10',
        idempotency_key: DIGEST,
        frozen_proposal_hash: DIGEST,
        effect_request_digest: DIGEST,
        services_ledger_id: 'ledger_test',
        system_use_decision: SYSTEM_USE_REFERENCE,
        system_use_current_at_record: true,
        service: 'filing',
        bound_at: '2026-08-01T09:14:22.418Z',
        token_expires_at: '2026-08-01T09:14:27.418Z',
      },
      human_intervention_event: null,
      challenge_and_remedy: null,
    });
    expect(entry.success, JSON.stringify(entry.error?.issues)).toBe(true);
    if (!entry.success) throw new Error('expected base record entry');
    expect(
      recordEntry.safeParse({
        ...entry.data,
        entry_id: 'rec_challenge',
        challenge_and_remedy: {
          route: 'challenge',
          opened_at: '2026-08-01T09:20:00.000Z',
          contested_entry_id: entry.data.entry_id,
          correction_text: 'The synthetic date is 2024-06-01.',
          reliance_state: 'withdrawn-pending-review',
          recovery_owner_role: 'principal',
        },
      }).success,
    ).toBe(true);
    expect(
      recordEntry.safeParse({
        ...entry.data,
        entry_id: 'rec_incomplete_challenge',
        challenge_and_remedy: { route: 'challenge', opened_at: '2026-08-01T09:20:00.000Z' },
      }).success,
    ).toBe(false);
    expect(
      recordEntry.safeParse({
        ...entry.data,
        entry_id: 'rec_misrouted_correction',
        challenge_and_remedy: {
          route: 'review',
          opened_at: '2026-08-01T09:20:00.000Z',
          correction_text: 'This field must remain challenge-only.',
        },
      }).success,
    ).toBe(false);

    const access = accessEntry.safeParse({
      world_id: 'w-demo',
      entry_id: 'acc_0042',
      at: '2026-08-01T09:20:00.000Z',
      route: 'GET /w/w-demo/records',
      authenticated_actor: 'role:principal',
      claimed_actor: null,
      outcome: 'served',
      http_status: 200,
      read_lengths: { action: 118, access: 42 },
    });
    expect(access.success, JSON.stringify(access.error?.issues)).toBe(true);
    const outputEvidence = {
      kind: 'model_output_control',
      case_id: 'case_demo',
      turn_id: 'turn_output',
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
      served_id: 'swiss-ai/apertus-v1.5-70b',
      projection_digest: DIGEST,
      projection_item_count: 3,
      output_digest: DIGEST,
      model_resolution: 'exact',
      flags: [],
      authority_effect: 'none',
      disposition: 'admitted',
      reasons: [],
      derived_tags: ['conf:case', 'conf:public', 'purpose:grant-assessment'],
    };
    const callAdmissionEvidence = {
      kind: 'model_call_admission',
      call_id: 'mcl_output_1',
      decision: outputEvidence,
    };
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_output_1',
        at: '2026-08-01T09:20:00.000Z',
        route: 'POST /w/{world_id}/model-outputs/admit',
        authenticated_actor: 'proc:orchestrator',
        claimed_actor: null,
        outcome: 'served',
        http_status: 200,
        operation_evidence: callAdmissionEvidence,
      }).success,
    ).toBe(true);
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_output_wrong_route',
        at: '2026-08-01T09:20:00.000Z',
        route: 'GET /w/{world_id}/records/*',
        authenticated_actor: 'proc:orchestrator',
        claimed_actor: null,
        outcome: 'served',
        http_status: 200,
        operation_evidence: callAdmissionEvidence,
      }).success,
    ).toBe(false);
    const openCallEvidence = {
      kind: 'model_call_lifecycle',
      world_id: 'w-demo',
      call_id: 'mcl_open_1',
      authorization_boot_id: 'authz_boot_1',
      case_id: 'case_demo',
      turn_id: 'turn_output',
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
      projection_digest: DIGEST,
      projection_item_count: 3,
      system_use_decision: SYSTEM_USE_REFERENCE,
      opened_at: '2026-08-01T09:19:00.000Z',
      expires_at: '2026-08-01T09:20:00.000Z',
      state: 'open',
      outcome: 'indeterminate',
      provider_disclosure: 'possible',
      completed_at: null,
      served_id: null,
      output_digest: null,
      failure_reason: null,
    };
    const failedCallEvidence = {
      ...openCallEvidence,
      state: 'terminal',
      outcome: 'failed',
      completed_at: '2026-08-01T09:19:01.000Z',
      failure_reason: 'provider-timeout',
    };
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_call_open',
        at: '2026-08-01T09:19:00.000Z',
        route: 'POST /w/{world_id}/model-calls/begin',
        authenticated_actor: 'proc:orchestrator',
        claimed_actor: null,
        outcome: 'served',
        http_status: 200,
        operation_evidence: openCallEvidence,
      }).success,
    ).toBe(true);
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_call_inconsistent_failure',
        at: '2026-08-01T09:19:01.000Z',
        route: 'POST /w/{world_id}/model-calls/failures',
        authenticated_actor: 'proc:orchestrator',
        claimed_actor: null,
        outcome: 'served',
        http_status: 200,
        operation_evidence: {
          ...failedCallEvidence,
          failure_reason: 'authorization-invalidated',
          provider_disclosure: 'possible',
        },
      }).success,
    ).toBe(false);
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_call_failed',
        at: '2026-08-01T09:19:01.000Z',
        route: 'POST /w/{world_id}/model-calls/failures',
        authenticated_actor: 'proc:orchestrator',
        claimed_actor: null,
        outcome: 'served',
        http_status: 200,
        operation_evidence: failedCallEvidence,
      }).success,
    ).toBe(true);
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_call_raw_error',
        at: '2026-08-01T09:19:01.000Z',
        route: 'POST /w/{world_id}/model-calls/failures',
        authenticated_actor: 'proc:orchestrator',
        claimed_actor: null,
        outcome: 'served',
        http_status: 200,
        operation_evidence: { ...failedCallEvidence, error: 'must not enter the access chain' },
      }).success,
    ).toBe(false);
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_output_raw_text',
        at: '2026-08-01T09:20:00.000Z',
        route: 'POST /w/{world_id}/model-outputs/admit',
        authenticated_actor: 'proc:orchestrator',
        claimed_actor: null,
        outcome: 'served',
        http_status: 200,
        operation_evidence: {
          ...callAdmissionEvidence,
          decision: { ...outputEvidence, content: 'must not enter the access chain' },
        },
      }).success,
    ).toBe(false);
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_suppression_1',
        at: '2026-08-01T09:20:01.000Z',
        route: 'AUTHZ unauthenticated ingress',
        authenticated_actor: null,
        claimed_actor: null,
        outcome: 'rate-limited',
        http_status: 429,
        suppressed_count: 42,
        suppression_window_ms: 1_000,
        suppression_final: true,
      }).success,
    ).toBe(true);
  });

  it('the policy set, the model card, and the card revocation', () => {
    const policy = policySet.safeParse({
      policy_version: '2026-08-01.3',
      ordering: 'deny-escalate-allow-then-priority',
      default_escalation_contract: validContract(),
      aggregate_ceiling_contract: validContract(),
      recovery_escalation_contract: validContract(),
      escalation_pattern: {
        window_ms: 3_600_000,
        escalation_count: 3,
        timeout_count: 2,
        override_count: 2,
        consequence: 'narrow-pending-reauthorization',
      },
      rules: [
        {
          id: 'rule_filing_within_ceiling',
          priority: 10,
          gate: 'commit',
          matcher: { kind: 'always' },
          verdict: 'allow',
          ux_class: 'silent',
          reason_template: 'Within the mandate ceiling.',
        },
        {
          id: 'rule_default_escalate',
          priority: 5,
          gate: 'submit',
          matcher: { kind: 'always' },
          verdict: 'escalate',
          ux_class: 'stop',
          reason_template: 'No rule matched; failing closed.',
          intervention_contract: validContract(),
        },
      ],
    });
    expect(policy.success, JSON.stringify(policy.error?.issues)).toBe(true);

    const card = modelCard.safeParse(validCard());
    expect(card.success, JSON.stringify(card.error?.issues)).toBe(true);

    const revocation = cardRevocation.safeParse({
      card_id: 'openai-gpt-5.5',
      revokes_versions: 'all',
      reason_class: 'security',
      effective_at: '2026-08-14T10:00:00.000Z',
      issued_by: 'maintainer',
      signature: { alg: 'ed25519', key_id: 'card-2026-08-01', signature: SIGNATURE },
    });
    expect(revocation.success, JSON.stringify(revocation.error?.issues)).toBe(true);
  });

  it('the WAL transaction with its closed op vocabulary', () => {
    const parsed = walTransaction.safeParse({
      kind: 'transaction',
      world_id: 'w-demo',
      ts: '2026-08-01T09:14:22.418Z',
      txn: 'commit_verify',
      run_id: 'run-2026-08-01-02',
      actor: { credential: 'proc:services_host', claimed_role: null },
      ops: [
        {
          op: 'policy.reload',
          policy: {
            world_id: 'w-demo',
            policy_version: '2026-08-01.3',
            policy_content_digest: DIGEST,
            evaluator_build_id: 'gate-core@0.0.1+9f3c1a2b7d4e5f60',
            activated_at: '2026-08-01T09:14:22.418Z',
          },
        },
      ],
    });
    expect(parsed.success, JSON.stringify(parsed.error?.issues)).toBe(true);
  });

  it('every accepted contract is inside the canonicalization subset', () => {
    for (const value of [validMandate(), validProposal(), validRuling(), validCard(), validContract()]) {
      expect(() => canonicalize(value)).not.toThrow();
    }
  });
});

describe('schemas — reject what fails closed', () => {
  it('a float amount', () => {
    expect(mandate.safeParse(validMandate({ limits: { ...(validMandate()['limits'] as object), amount_minor_units: 25.5 } })).success).toBe(
      false,
    );
    expect(
      frozenProposal.safeParse(
        validProposal({ cost_obligation: { amount_minor_units: 25_000.5, description: 'x' } }),
      ).success,
    ).toBe(false);
    expect(
      gateRuling.safeParse(validRuling({ counter_reservations: [{ id: 'rsv_1', counter: 'amount', delta: 1.5 }] }))
        .success,
    ).toBe(false);
  });

  it('an unknown or malformed restriction tag', () => {
    expect(restrictionTag.safeParse('conf:secret').success).toBe(false);
    expect(restrictionTag.safeParse('conf:public ').success).toBe(false);
    expect(restrictionTag.safeParse('recipient:provider:').success).toBe(false);
    expect(restrictionTag.safeParse('recipient:provider:OpenAI-GPT').success).toBe(false);
    expect(restrictionTag.safeParse('recipient:provider:openai-gpt-5.5').success).toBe(true);
    expect(storeItem.safeParse(saidItem({ tags: ['conf:secret'] })).success).toBe(false);
  });

  it('origin_actor on an inferred item', () => {
    const parsed = storeItem.safeParse(inferredItem({ origin_actor: 'officer' }));
    expect(parsed.success).toBe(false);
    expect(parsed.error?.issues[0]?.path).toEqual(['origin_actor']);
  });

  it('a said item with no origin_actor', () => {
    const item = saidItem();
    delete item['origin_actor'];
    const parsed = storeItem.safeParse(item);
    expect(parsed.success).toBe(false);
    expect(parsed.error?.issues[0]?.path).toEqual(['origin_actor']);
    // ...and the same for the other two attributed stores.
    for (const store of ['confirmed', 'permitted']) {
      const other = saidItem({ store });
      delete other['origin_actor'];
      expect(storeItem.safeParse(other).success).toBe(false);
    }
  });

  it('a malformed timestamp', () => {
    for (const bad of [
      '2026-08-01T09:00:00Z',
      '2026-08-01T09:00:00.000+02:00',
      '2026-08-01 09:00:00.000Z',
      '2026-08-01',
      '',
    ]) {
      expect(mandate.safeParse(validMandate({ issued_at: bad })).success, bad).toBe(false);
    }
    // The card's date fields are calendar dates, not timestamps (ADR-006 §2).
    expect(modelCard.safeParse(validCard({ valid_from: '2026-08-01T00:00:00.000Z' })).success).toBe(false);
  });

  it('unsorted or duplicated item tags', () => {
    expect(storeItem.safeParse(saidItem({ tags: ['purpose:grant-assessment', 'conf:case'] })).success).toBe(false);
    expect(storeItem.safeParse(saidItem({ tags: ['conf:case', 'conf:case'] })).success).toBe(false);
  });

  it('an approved role with no clearances, or clearances for an unapproved role', () => {
    expect(
      mandate.safeParse(
        validMandate({
          approved_models: [
            approvedModelEntry({ data_classes: { acting: ['conf:public', 'purpose:grant-assessment'] } }),
          ],
        }),
      ).success,
    ).toBe(false);
    expect(
      mandate.safeParse(
        validMandate({
          approved_models: [
            approvedModelEntry({
              roles: ['acting'],
              data_classes: {
                acting: ['conf:public', 'purpose:grant-assessment'],
                screening: ['conf:public'],
              },
            }),
          ],
        }),
      ).success,
    ).toBe(false);
  });

  it('a world id that is a Windows reserved device name', () => {
    expect(mandate.safeParse(validMandate({ world_id: 'con' })).success).toBe(false);
    expect(mandate.safeParse(validMandate({ world_id: 'w-demo' })).success).toBe(true);
  });

  it('an escalating policy rule without its six contract fields', () => {
    const parsed = policySet.safeParse({
      policy_version: '2026-08-01.3',
      ordering: 'deny-escalate-allow-then-priority',
      default_escalation_contract: validContract(),
      recovery_escalation_contract: validContract(),
      escalation_pattern: {
        window_ms: 3_600_000,
        escalation_count: 3,
        timeout_count: 2,
        override_count: 2,
        consequence: 'narrow-pending-reauthorization',
      },
      rules: [
        {
          id: 'rule_default_escalate',
          priority: 1,
          gate: 'submit',
          matcher: { kind: 'always' },
          verdict: 'escalate',
          ux_class: 'stop',
          reason_template: 'No rule matched.',
        },
      ],
    });
    expect(parsed.success).toBe(false);
  });

  it('a contract missing any of the six fields', () => {
    for (const field of [
      'trigger_and_state',
      'decision_and_route',
      'decision_basis_shown',
      'response_bound_and_default',
      'permitted_dispositions',
      'record_and_feedback',
    ]) {
      const contract = validContract();
      delete contract[field];
      expect(interventionContract.safeParse(contract).success, field).toBe(false);
    }
  });

  it('an unsafe timeout fallback or a mixed disposition family', () => {
    const unsafe = validContract();
    unsafe['response_bound_and_default'] = {
      response_bound_ms: 900_000,
      safe_default: {
        kind: 'stop-remains',
        disposition: 'allow-within-scope',
        authority_basis: { kind: 'no-new-authority' },
        reversible: true,
      },
    };
    expect(interventionContract.safeParse(unsafe).success).toBe(false);
    expect(
      interventionContract.safeParse({
        ...validContract(),
        permitted_dispositions: ['confirm', 'deny', 'abstain'],
      }).success,
    ).toBe(false);
  });

  it('a suppression entry without its bounded-window count', () => {
    expect(
      accessEntry.safeParse({
        world_id: 'w-demo',
        entry_id: 'acc_suppression_invalid',
        at: '2026-08-01T09:20:01.000Z',
        route: 'AUTHZ unauthenticated ingress',
        authenticated_actor: null,
        claimed_actor: null,
        outcome: 'rate-limited',
        http_status: 429,
      }).success,
    ).toBe(false);
  });

  it('a card whose pinning mode contradicts its lane resolution policy', () => {
    const card = validCard();
    const model = { ...(card['model'] as Record<string, unknown>), pinning_mode: 'exact' };
    expect(modelCard.safeParse({ ...card, model }).success).toBe(false);
  });

  it('an op outside the closed WAL vocabulary', () => {
    const parsed = walTransaction.safeParse({
      kind: 'transaction',
      world_id: 'w-demo',
      ts: '2026-08-01T09:14:22.418Z',
      txn: 'commit_verify',
      run_id: 'run-2026-08-01-02',
      actor: { credential: 'proc:services_host', claimed_role: null },
      ops: [{ op: 'counter.set', id: 'ctr_1', value: 0 }],
    });
    expect(parsed.success).toBe(false);
  });

  it('a confidence outside 0-100 and a non-integer confidence', () => {
    for (const value of [101, -1, 72.5]) {
      const ruling = validRuling();
      const signal = {
        kind: 'screening_signal',
        signal: 'unconfirmed_inference_as_fact',
        confidence_pct: value,
        rationale: 'Inference inf_7 is used as a decision basis without confirmation.',
        model_id: 'gpt-5.5',
        model_version_reported: 'gpt-5.5-2026-04-23',
      };
      expect(
        gateRuling.safeParse({ ...ruling, verdict: 'escalate', ux_class: 'stop', evidence_refs: [signal] }).success,
        String(value),
      ).toBe(false);
    }
  });
});
