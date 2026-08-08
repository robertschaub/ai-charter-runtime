// SPDX-License-Identifier: MIT
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  acceptsHandoffTransfer,
  parseBrowserConversation,
  parseBrowserCurrentSelection,
  parseBrowserMessagePreparation,
  parseBrowserModelTurnPreparation,
  parseBrowserModelTurnStatus,
  parseBrowserProposalPreparation,
  parseBrowserProposalRunStatus,
  parseBrowserSelectionPreparation,
  parseBrowserSelectionResult,
  parseCreatedSession,
  parseRuntimeConsoleConfig,
  shouldPollCaseState,
} from './caseHandoffConsole.js';

const target = {
  card_id: 'publicai-apertus-v1.5-70b',
  card_version: 1,
  requested_id: 'swiss-ai/apertus-v1.5-70b',
};

const transition = {
  selection_id: 'sel_one',
  kind: 'initial',
  predecessor_selection_id: null,
  mandate_id: 'mdt_demo_grant',
  mandate_version: 1,
  target,
  selected_at: '2026-08-05T10:00:01.000Z',
  authority_effect: 'none',
};

describe('orchestrator-origin exact-window handoff client', () => {
  it('accepts only an exact two-origin runtime configuration', () => {
    expect(
      parseRuntimeConsoleConfig({
        authorization_origin: 'http://127.0.0.1:7801',
        orchestrator_origin: 'http://127.0.0.1:7802',
      }),
    ).toEqual({
      authorization_origin: 'http://127.0.0.1:7801',
      orchestrator_origin: 'http://127.0.0.1:7802',
    });
    expect(
      parseRuntimeConsoleConfig({
        authorization_origin: 'http://127.0.0.1:7801/path',
        orchestrator_origin: 'http://127.0.0.1:7802',
      }),
    ).toBeNull();
    expect(
      parseRuntimeConsoleConfig({
        authorization_origin: 'http://127.0.0.1:7801',
        orchestrator_origin: 'http://127.0.0.1:7802',
        caller_target: 'http://attacker.invalid',
      }),
    ).toBeNull();
  });

  it('requires reciprocal origin, source, target, and strict message bindings', () => {
    const opener = {} as WindowProxy;
    const other = {} as WindowProxy;
    const data = {
      type: 'runtime.case-handoff.transfer',
      handoff_id: 'handoff_one',
      handoff_code: 'a'.repeat(64),
      role: 'case_officer',
      world_id: 'w-demo',
      case_id: 'case_demo',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_one',
    };
    const event = { origin: 'http://127.0.0.1:7801', source: opener, data };
    expect(acceptsHandoffTransfer(event, event.origin, opener, data.target_origin)).toBe(true);
    expect(acceptsHandoffTransfer({ ...event, origin: 'null' }, event.origin, opener, data.target_origin)).toBe(false);
    expect(acceptsHandoffTransfer({ ...event, source: other }, event.origin, opener, data.target_origin)).toBe(false);
    expect(
      acceptsHandoffTransfer(
        { ...event, data: { ...data, target_origin: 'http://127.0.0.1:9999' } },
        event.origin,
        opener,
        data.target_origin,
      ),
    ).toBe(false);
    expect(
      acceptsHandoffTransfer({ ...event, data: { ...data, extra: true } }, event.origin, opener, data.target_origin),
    ).toBe(false);
  });

  it('keeps the fixed handoff shell free of inline and third-party executable content', () => {
    const shell = readFileSync(resolve('packages/consoles/assets/case-console/handoff.html'), 'utf8');
    expect(shell).toContain('<script type="module" src="/console/handoff.js"></script>');
    expect(shell).toContain('<link rel="stylesheet" href="/console/case-styles.css">');
    expect(shell).not.toMatch(/<script(?![^>]*\bsrc=)/i);
    expect(shell).not.toMatch(/<style\b/i);
    expect(shell).not.toMatch(/\son[a-z]+=/i);
    expect(shell).not.toMatch(/https?:\/\//i);
    expect(shell).toContain('Find → check → select');
    expect(shell).toContain('Prepare model run');
    expect(shell).toContain('Run selected model');
    expect(shell).toContain('<textarea id="case-message"');
    expect(shell).toContain('Prepare message');
    expect(shell).toContain('Send governed turn');
    expect(shell).toContain('Prepare a governed proposal');
    expect(shell).toContain('Prepare proposal');
    expect(shell).toContain('Generate and check proposal');
    expect(shell).toContain('pre-commit evidence');
    expect(shell).toContain('No commitment, service call, or effect can occur here.');
    expect(shell).not.toMatch(/<input\b/i);
  });

  it('accepts only exact message preparations and field-bounded conversation projections', () => {
    const preparation = {
      preparation_id: 'msgp_one',
      message_id: 'msg_one',
      turn_id: 'turn_message_one',
      issued_at: '2026-08-07T09:00:00.000Z',
      expires_at: '2026-08-07T09:02:00.000Z',
    };
    expect(parseBrowserMessagePreparation(preparation)).toEqual({
      preparationId: 'msgp_one',
      messageId: 'msg_one',
      turnId: 'turn_message_one',
    });
    expect(parseBrowserMessagePreparation({ ...preparation, text: 'forbidden' })).toBeNull();
    const conversation = {
      case_id: 'case_demo',
      conversation_version: 3,
      events: [
        {
          speaker: 'case_officer',
          message_id: 'msg_one',
          turn_id: 'turn_message_one',
          text: 'Synthetic question',
          recorded_at: '2026-08-07T09:00:00.000Z',
        },
        {
          speaker: 'model',
          message_id: 'msg_one',
          turn_id: 'turn_message_one',
          text: 'Synthetic inference',
          recorded_at: '2026-08-07T09:00:01.000Z',
          requested_id: target.requested_id,
          served_id: target.requested_id,
          classification: 'inferred-unconfirmed',
        },
      ],
    };
    expect(parseBrowserConversation(conversation)).toEqual(conversation);
    expect(parseBrowserConversation({ ...conversation, authorization_boot_id: 'forbidden' })).toBeNull();
    expect(parseBrowserConversation({
      ...conversation,
      events: [{ ...conversation.events[0], session_id: 'forbidden' }],
    })).toBeNull();
  });

  it('accepts only exact content-free model-turn preparation and status projections', () => {
    const preparation = {
      preparation_id: 'mtp_one',
      turn_id: 'turn_one',
      selection_id: 'sel_one',
      target,
      issued_at: '2026-08-07T09:00:00.000Z',
      expires_at: '2026-08-07T09:02:00.000Z',
    };
    expect(parseBrowserModelTurnPreparation(preparation)).toEqual({
      preparationId: 'mtp_one',
      turnId: 'turn_one',
      selectionId: 'sel_one',
      target,
    });
    expect(parseBrowserModelTurnPreparation({ ...preparation, message: 'forbidden' })).toBeNull();
    const status = {
      turn_id: 'turn_one',
      selection_id: 'sel_one',
      target,
      state: 'quarantined',
      provider_disclosure: 'confirmed',
      requested_id: target.requested_id,
      served_id: target.requested_id,
      terminal_reason: null,
      quarantine: {
        release_state: 'sealed-no-release-path',
        call_id: 'mcl_one',
        projection_digest: 'a'.repeat(64),
        output_digest: 'b'.repeat(64),
        derived_tags: ['conf:case'],
      },
    };
    expect(parseBrowserModelTurnStatus(status)).toEqual(status);
    expect(parseBrowserModelTurnStatus({ ...status, content: 'forbidden output' })).toBeNull();
    expect(parseBrowserModelTurnStatus({ ...status, provider_disclosure: 'none' })).toBeNull();
    expect(parseBrowserModelTurnStatus({ ...status, quarantine: null })).toBeNull();
    expect(parseBrowserModelTurnStatus({
      ...status,
      state: 'failed',
      provider_disclosure: 'possible',
      served_id: null,
      terminal_reason: 'provider-failure',
      quarantine: null,
    })).toMatchObject({ state: 'failed', provider_disclosure: 'possible' });
  });

  it('accepts only exact proposal preparation and redacted pre-commit evidence', () => {
    const preparation = {
      preparation_id: 'pprep_one',
      proposal_run_id: 'prun_one',
      target,
      issued_at: '2026-08-08T09:00:00.000Z',
      expires_at: '2026-08-08T09:02:00.000Z',
    };
    expect(parseBrowserProposalPreparation(preparation)).toEqual({
      preparationId: 'pprep_one',
      proposalRunId: 'prun_one',
      target,
    });
    for (const forbidden of [
      { proposal_intake_id: 'pint_hidden' },
      { conversation_version: 1 },
      { prompt: 'forbidden' },
      { retry: true },
    ]) expect(parseBrowserProposalPreparation({ ...preparation, ...forbidden })).toBeNull();

    const proposal = {
      proposal_id: 'prp_one',
      action_id: 'act_one',
      revision: 1,
      declared_objective: 'Synthetic objective',
      proposed_action: 'Synthetic action',
      target: { recipient: 'Synthetic recipient', resource: 'Synthetic resource' },
      exact_parameters: { count: 1, modes: ['safe'] },
      data_to_be_disclosed: ['Synthetic public field'],
      cost_obligation: { amount_minor_units: 0, description: 'No monetary cost' },
      material_consequences: ['Synthetic consequence'],
      reversibility_class: 'reversible',
      commercial_influence: { applicable: false, note: 'None' },
      requested_id: target.requested_id,
      served_id: target.requested_id,
      basis: [
        { standing: 'said', text: 'Synthetic stated basis' },
        { standing: 'inferred-unconfirmed', text: 'Synthetic inferred basis' },
      ],
    };
    const gate = {
      gate: 'authorize',
      ruling_id: 'rul_one',
      verdict: 'allow',
      ux_class: 'silent',
      reason: 'Synthetic pre-commit gate evidence.',
      status: 'issued',
      validity_window: {
        not_before: '2026-08-08T09:00:00.000Z',
        not_after: '2026-08-08T09:02:00.000Z',
      },
    };
    const status = {
      proposal_run_id: 'prun_one',
      state: 'frozen',
      proposal,
      gates: [gate],
    };
    expect(parseBrowserProposalRunStatus(status)).toEqual(status);
    for (const forbidden of [
      { proposal_intake_id: 'pint_hidden' },
      { call_id: 'mcl_hidden' },
      { output_digest: 'a'.repeat(64) },
      { commit_token: 'forbidden' },
    ]) expect(parseBrowserProposalRunStatus({ ...status, ...forbidden })).toBeNull();
    expect(parseBrowserProposalRunStatus({ ...status, proposal: { ...proposal, item_id: 'said_hidden' } })).toBeNull();
    expect(parseBrowserProposalRunStatus({ ...status, gates: [{ ...gate, service: 'filing' }] })).toBeNull();
    expect(parseBrowserProposalRunStatus({ ...status, state: 'prepared', proposal: undefined, gates: [] })).toMatchObject({ state: 'prepared' });
    expect(parseBrowserProposalRunStatus({ ...status, state: 'verified', proposal: undefined })).toBeNull();
  });

  it('accepts only redacted browser model-selection projections', () => {
    const evidence = {
      approval: {
        ...target,
        roles: ['acting'],
        data_classes: { acting: ['conf:case'] },
      },
      effective_data_classes: { acting: ['conf:case'] },
      card_status: 'current',
      signature_status: 'valid',
      integrity_alarm: false,
      current_card: null,
    };
    const preparation = {
      preparation: {
        preparation_id: 'msp_one',
        target,
        issued_at: '2026-08-05T10:00:00.000Z',
        expires_at: '2026-08-05T10:02:00.000Z',
      },
      evidence,
    };
    expect(parseBrowserSelectionPreparation(preparation)).toEqual({
      preparation_id: 'msp_one',
      target,
      evidence,
    });
    expect(parseBrowserSelectionPreparation({
      ...preparation,
      evidence: { ...evidence, check_id: 'msc_hidden' },
    })).toBeNull();
    expect(parseBrowserSelectionPreparation({
      ...preparation,
      evidence: { ...evidence, approval: { ...evidence.approval, card_digest: 'a'.repeat(64) } },
    })).toBeNull();
    expect(parseBrowserCurrentSelection({
      state: 'selected',
      case_id: 'case_demo',
      selection: transition,
      latest_observation: null,
    })).toEqual({ state: 'selected', target });
    expect(parseBrowserCurrentSelection({
      state: 'selected',
      authorization_boot_id: 'authz_boot_hidden',
      case_id: 'case_demo',
      selection: transition,
      latest_observation: null,
    })).toBeNull();
    expect(parseBrowserCurrentSelection({
      state: 'selected',
      case_id: 'case_demo',
      selection: { ...transition, system_use_decision: {} },
      latest_observation: null,
    })).toBeNull();
    expect(parseBrowserSelectionResult({
      selection: transition,
      invalidated_ruling_count: 0,
      terminalized_open_call_count: 0,
    })).toEqual({ selection_id: 'sel_one', target });
  });

  it('does not persist a model target or preparation in browser storage', () => {
    const source = readFileSync(resolve('packages/consoles/src/caseHandoffConsole.ts'), 'utf8');
    expect(source).not.toContain('runtime-case-model-choice');
    expect(source).not.toMatch(/(?:local|session)Storage\.setItem\([^\n]*(?:model|preparation)/i);
  });

  it('binds created sessions to one case and polls only an open dialogue mirror', () => {
    expect(
      parseCreatedSession({
        session_token: 'a'.repeat(64),
        session_id: 'session_one',
        role: 'case_officer',
        world_id: 'w-demo',
        case_id: 'case_demo',
        expires_at: '2026-08-03T10:15:00.000Z',
      }),
    ).toEqual({ session_token: 'a'.repeat(64), world_id: 'w-demo', case_id: 'case_demo' });
    expect(
      parseCreatedSession({
        session_token: 'a'.repeat(64),
        session_id: 'session_one',
        role: 'case_officer',
        world_id: 'w-demo',
        expires_at: '2026-08-03T10:15:00.000Z',
      }),
    ).toBeNull();
    expect(shouldPollCaseState({ dialogue: { status: 'open' } })).toBe(true);
    expect(shouldPollCaseState({ dialogue: { status: 'terminal' } })).toBe(false);
    expect(shouldPollCaseState({ dialogue: null })).toBe(false);
  });
});
