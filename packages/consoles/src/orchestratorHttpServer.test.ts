// SPDX-License-Identifier: MIT
import { digestFor, digestModelOutput } from 'gate-core';
import { ModelAdapterError } from 'model-adapters';
import { describe, expect, it, vi } from 'vitest';

import { CaseConsoleStateStore } from './caseConsoleState.js';
import { CaseConversationStore } from './caseConversation.js';
import { CaseModelSelectionPreparationStore } from './caseModelSelection.js';
import { CaseModelTurnStore } from './caseModelTurn.js';
import { CaseProposalStore } from './caseProposal.js';
import { CaseSessionStore } from './caseSessionStore.js';
import {
  ModelOutputQuarantine,
  ModelTurnCoordinator,
  type ModelTurnAuthorizationClient,
} from './modelTurnCoordinator.js';
import { OrchestratorHttpServer } from './orchestratorHttpServer.js';
import type { OrchestratorAuthorizationHttpClient, OrchestratorServicesHttpClient } from './runtimeHttpClients.js';

describe('orchestrator case-console routes', () => {
  it('confines proposal and response-bound revision routes to exact dynamic sessions and fixed browser projections', async () => {
    const digest = 'a'.repeat(64);
    const target = {
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
    };
    const dynamicTokens = ['c'.repeat(64), 'd'.repeat(64), 'e'.repeat(64)];
    const sessionIds = ['session_proposal_one', 'session_proposal_two', 'session_prior_boot'];
    const sessions = new CaseSessionStore({
      now: () => '2026-08-08T10:00:00.000Z',
      randomToken: () => dynamicTokens.shift()!,
      nextSessionId: () => sessionIds.shift()!,
    });
    const claim = {
      handoff_id: 'handoff_proposal_one',
      role: 'case_officer' as const,
      world_id: 'w-demo',
      case_id: 'case_demo',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_proposal',
      consumed_at: '2026-08-08T10:00:00.000Z',
    };
    const first = sessions.create(claim);
    const second = sessions.create({ ...claim, handoff_id: 'handoff_proposal_two' });
    const priorBoot = sessions.create({
      ...claim,
      handoff_id: 'handoff_prior_boot',
      authorization_boot_id: 'authz_boot_prior',
    });
    const current = {
      state: 'selected' as const,
      authorization_boot_id: 'authz_boot_proposal',
      case_id: 'case_demo',
      selection: {
        world_id: 'w-demo',
        selection_id: 'sel_proposal',
        case_id: 'case_demo',
        kind: 'initial' as const,
        predecessor_selection_id: null,
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        target: { ...target, card_digest: digest, verifying_key_id: 'card_key_one' },
        system_use_decision: {
          decision_id: 'sud_one',
          version: 1,
          record_digest: digest,
          status: 'approved' as const,
          conditions: [],
        },
        check_id: 'msc_proposal',
        selected_at: '2026-08-08T10:00:00.000Z',
        authority_effect: 'none' as const,
      },
      latest_observation: null,
    };
    const conversation = {
      case_id: 'case_demo',
      conversation_version: 2,
      events: [{
        speaker: 'case_officer' as const,
        message_id: 'msg_proposal',
        turn_id: 'turn_message_proposal',
        text: 'Synthetic current conversation.',
        recorded_at: '2026-08-08T10:00:00.000Z',
      }],
    };
    const processStatus = {
      kind: 'proposal_precommit_status' as const,
      proposal_id: 'prp_proposal',
      proposal_run_id: 'prun_proposal',
      proposal: {
        proposal_id: 'prp_proposal',
        action_id: 'act_proposal',
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
        requested_id: target.requested_id,
        served_id: target.requested_id,
        basis: [{ standing: 'said' as const, text: 'Synthetic basis' }],
      },
      state: 'verified' as const,
      gates: [{
        gate: 'verify' as const,
        ruling_id: 'rul_verify',
        verdict: 'allow' as const,
        ux_class: 'silent' as const,
        reason: 'Synthetic current policy allows the pre-commit stage.',
        status: 'issued' as const,
        validity_window: {
          not_before: '2026-08-08T10:00:00.000Z',
          not_after: '2026-08-08T10:02:00.000Z',
        },
      }],
      escalation_id: null,
      continuation: { state: 'available' as const, source_proposal_run_id: null },
      updated_at: '2026-08-08T10:00:01.000Z',
    };
    const runProposalPrecommit = vi.fn(async () => processStatus);
    const proposalRunStatus = vi.fn(async () => processStatus);
    const prepareProposalRevision = vi.fn(async () => ({
      kind: 'proposal_revision_preparation' as const,
      preparation_id: 'rprep_revision',
      proposal_run_id: 'prun_revision',
      source_proposal_run_id: 'prun_proposal',
      target,
      issued_at: '2026-08-08T10:00:00.000Z',
      expires_at: '2026-08-08T10:02:00.000Z',
    }));
    const authorization = {
      currentModelSelection: vi.fn(async () => current),
      conversation: vi.fn(async () => conversation),
      runProposalPrecommit,
      proposalRunStatus,
      prepareProposalRevision,
    } as unknown as OrchestratorAuthorizationHttpClient;
    const quarantine = new ModelOutputQuarantine();
    const runProposal = vi.fn(async () => ({
      disposition: 'proposal-frozen' as const,
      proposal: {
        kind: 'proposal_intake_consumption_result' as const,
        proposal_run_id: 'prun_proposal',
        state: 'consumed' as const,
        proposal_id: 'prp_proposal',
        recorded_at: '2026-08-08T10:00:01.000Z',
      },
    }));
    const coordinator = {
      quarantine,
      hasConfiguredLane: () => true,
      runProposal,
    } as unknown as ModelTurnCoordinator;
    const caseProposals = new CaseProposalStore({
      now: () => '2026-08-08T10:00:00.000Z',
      nextPreparationId: () => 'pprep_proposal',
      nextRunId: () => 'prun_proposal',
      nextTurnId: () => 'turn_proposal',
    });
    const server = new OrchestratorHttpServer({
      authorization,
      services: {} as OrchestratorServicesHttpClient,
      modelTurnCoordinator: coordinator,
      worldId: 'w-demo',
      demoCaseId: 'case_demo',
      demoMandateId: 'mdt_demo_grant',
      caseOfficerToken: 'b'.repeat(64),
      authorizationOrigin: 'http://127.0.0.1:7801',
      caseConsoleAssets: { shell: '', script: '', stylesheet: '' },
      caseSessions: sessions,
      caseProposals,
      host: '127.0.0.1',
      port: 0,
    });
    const address = await server.listen();
    const post = (path: string, body: unknown, token?: string, origin?: string) => fetch(`${address.origin}${path}`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
        ...(origin === undefined ? {} : { origin }),
      },
      body: JSON.stringify(body),
    });
    const get = (path: string, token?: string, origin?: string) => fetch(`${address.origin}${path}`, {
      headers: {
        ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
        ...(origin === undefined ? {} : { origin }),
      },
    });
    try {
      const preparePath = '/w/w-demo/cases/case_demo/proposal-preparations';
      expect((await post(preparePath, {}, first.session_token)).status).toBe(403);
      expect((await post(preparePath, {}, first.session_token, 'null')).status).toBe(403);
      expect((await post(preparePath, {}, first.session_token, 'http://foreign.invalid')).status).toBe(403);
      expect((await post(preparePath, {}, 'b'.repeat(64), address.origin)).status).toBe(401);
      expect((await post(preparePath, { proposal: {} }, first.session_token, address.origin)).status).toBe(422);
      expect((await post(preparePath, {}, priorBoot.session_token, address.origin)).status).toBe(401);
      expect(sessions.authenticate(priorBoot.session_token, 'w-demo', 'case_demo')).toBeNull();

      const prepared = await post(preparePath, {}, first.session_token, address.origin);
      expect(prepared.status).toBe(201);
      await expect(prepared.json()).resolves.toEqual({
        preparation_id: 'pprep_proposal',
        proposal_run_id: 'prun_proposal',
        target,
        issued_at: '2026-08-08T10:00:00.000Z',
        expires_at: '2026-08-08T10:02:00.000Z',
      });

      const usePath = '/w/w-demo/cases/case_demo/proposals';
      expect((await post(usePath, { preparation_id: 'pprep_proposal' }, first.session_token)).status).toBe(403);
      expect((await post(usePath, { preparation_id: 'pprep_proposal' }, first.session_token, 'null')).status).toBe(403);
      expect((await post(usePath, { preparation_id: 'pprep_proposal' }, 'b'.repeat(64), address.origin)).status).toBe(401);
      expect((await post(usePath, { preparation_id: 'pprep_proposal', gate: 'commit' }, first.session_token, address.origin)).status).toBe(422);
      expect((await post(usePath, { preparation_id: 'pprep_proposal' }, second.session_token, address.origin)).status).toBe(409);
      expect(runProposal).not.toHaveBeenCalled();
      const used = await post(usePath, { preparation_id: 'pprep_proposal' }, first.session_token, address.origin);
      expect(used.status).toBe(200);
      const usedBody = await used.json();
      expect(Object.keys(usedBody).sort()).toEqual(['continuation', 'gates', 'proposal', 'proposal_run_id', 'state']);
      expect(usedBody).toMatchObject({ proposal_run_id: 'prun_proposal', state: 'verified' });
      for (const hidden of ['proposal_intake_id', 'call_id', 'output_digest', 'selection_id', 'commit_token']) {
        expect(JSON.stringify(usedBody)).not.toContain(hidden);
      }
      expect(runProposal).toHaveBeenCalledOnce();
      expect(runProposalPrecommit).toHaveBeenCalledOnce();

      const statusPath = '/w/w-demo/cases/case_demo/proposal-runs/prun_proposal';
      expect((await get(statusPath, second.session_token, 'null')).status).toBe(403);
      expect((await get(statusPath, second.session_token, 'http://foreign.invalid')).status).toBe(403);
      expect((await get(statusPath, 'b'.repeat(64), address.origin)).status).toBe(401);
      const recovered = await get(statusPath, second.session_token);
      expect(recovered.status).toBe(200);
      await expect(recovered.json()).resolves.toEqual(usedBody);
      expect(proposalRunStatus).toHaveBeenCalledOnce();

      const revisionPath = `${statusPath}/revision-preparations`;
      expect((await post(revisionPath, {}, first.session_token)).status).toBe(403);
      expect((await post(revisionPath, {}, first.session_token, 'null')).status).toBe(403);
      expect((await post(revisionPath, {}, first.session_token, 'http://foreign.invalid')).status).toBe(403);
      expect((await post(revisionPath, {}, 'b'.repeat(64), address.origin)).status).toBe(401);
      expect((await post(revisionPath, { response: 'caller-asserted' }, first.session_token, address.origin)).status).toBe(422);
      expect(prepareProposalRevision).not.toHaveBeenCalled();
      const revisionPrepared = await post(revisionPath, {}, first.session_token, address.origin);
      expect(revisionPrepared.status).toBe(201);
      await expect(revisionPrepared.json()).resolves.toEqual({
        preparation_id: 'rprep_revision',
        proposal_run_id: 'prun_revision',
        target,
        issued_at: '2026-08-08T10:00:00.000Z',
        expires_at: '2026-08-08T10:02:00.000Z',
      });
      expect(prepareProposalRevision).toHaveBeenCalledWith(
        'w-demo',
        'case_demo',
        'prun_proposal',
        { role: 'case_officer', session_id: first.session_id },
      );
      const localRevision = await get('/w/w-demo/cases/case_demo/proposal-runs/prun_revision', first.session_token);
      expect(localRevision.status).toBe(200);
      await expect(localRevision.json()).resolves.toEqual({
        proposal_run_id: 'prun_revision',
        state: 'prepared',
        gates: [],
        continuation: { state: 'prepared', source_proposal_run_id: 'prun_proposal' },
      });
    } finally {
      await server.close();
    }
  });

  it('confines model evidence and the two-hop ruling mirror to the dynamic case session', async () => {
    const digest = 'c'.repeat(64);
    const modelTarget = {
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
    };
    const sessionToken = 'a'.repeat(64);
    const staticToken = 'b'.repeat(64);
    const sessions = new CaseSessionStore({
      randomToken: () => sessionToken,
      nextSessionId: () => 'session_test',
      now: () => '2026-08-03T10:00:00.000Z',
    });
    sessions.create({
      handoff_id: 'handoff_test',
      role: 'case_officer',
      world_id: 'w-demo',
      case_id: 'case_demo',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_test',
      consumed_at: '2026-08-03T10:00:00.000Z',
    });
    const caseState = new CaseConsoleStateStore();
    caseState.track('case_demo', {
      ruling: {
        ruling_id: 'rul_dialogue',
        verdict: 'escalate',
        ux_class: 'stop',
        reason: 'A third-party fact needs a routed response.',
        status: 'issued',
        successor_ruling_id: null,
        validity_window: {
          not_before: '2026-08-03T10:00:00.000Z',
          not_after: '2026-08-03T10:15:00.000Z',
        },
      },
      escalation_id: 'esc_dialogue',
    });
    const rulingStatus = vi.fn(async () => ({
      ruling_id: 'rul_dialogue',
      verdict: 'escalate' as const,
      ux_class: 'stop' as const,
      reason: 'A third-party fact needs a routed response.',
      status: 'invalidated' as const,
      successor_ruling_id: 'rul_successor',
      validity_window: {
        not_before: '2026-08-03T10:00:00.000Z',
        not_after: '2026-08-03T10:15:00.000Z',
      },
    }));
    const approvedModels = vi.fn(async () => ({
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      mandate_state: 'active' as const,
      default_acting_model: modelTarget,
      models: [],
    }));
    const currentModelSelection = vi.fn(async () => ({
      state: 'unselected' as const,
      authorization_boot_id: 'authz_boot_test',
      case_id: 'case_demo',
      selection: null,
      latest_observation: null,
    }));
    const checkModelSelection = vi.fn(async () => ({
      check: {
        kind: 'model_selection_check' as const,
        world_id: 'w-demo',
        check_id: 'msc_hidden',
        authorization_boot_id: 'authz_boot_test',
        case_id: 'case_demo',
        authenticated_actor: 'proc:orchestrator' as const,
        expected_current_selection_id: null,
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        target: { ...modelTarget, card_digest: digest, verifying_key_id: 'card_test' },
        system_use_decision: {
          decision_id: 'sud_demo',
          version: 1,
          record_digest: digest,
          status: 'approved' as const,
          conditions: [],
        },
        policy_version: 'policy-test',
        policy_content_digest: digest,
        evaluator_build_id: 'build-test',
        issued_at: '2026-08-03T10:00:00.000Z',
        expires_at: '2026-08-03T10:02:00.000Z',
        state: 'issued' as const,
        consumed_at: null,
      },
      evidence: {
        approval: {
          ...modelTarget,
          card_digest: digest,
          roles: ['acting' as const],
          data_classes: { acting: ['conf:case'] },
        },
        effective_data_classes: { acting: ['conf:case'] },
        card_status: 'current' as const,
        signature_status: 'valid' as const,
        integrity_alarm: false,
        current_card_digest: digest,
        verifying_key_id: 'card_test',
        current_card: null,
      },
    }));
    const selectionResult = {
      kind: 'model_selection_result' as const,
      selection: {
        world_id: 'w-demo',
        selection_id: 'sel_one',
        case_id: 'case_demo',
        kind: 'initial' as const,
        predecessor_selection_id: null,
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        target: { ...modelTarget, card_digest: digest, verifying_key_id: 'card_test' },
        system_use_decision: {
          decision_id: 'sud_demo',
          version: 1,
          record_digest: digest,
          status: 'approved' as const,
          conditions: [],
        },
        check_id: 'msc_hidden',
        selected_at: '2026-08-03T10:00:01.000Z',
        authority_effect: 'none' as const,
      },
      invalidated_ruling_count: 0,
      terminalized_open_call_count: 0,
    };
    const selectModel = vi.fn(async () => selectionResult);
    const authorization = {
      rulingStatus,
      approvedModels,
      currentModelSelection,
      checkModelSelection,
      selectModel,
      redeemCaseSessionHandoff: vi.fn(),
      closeCaseSession: vi.fn(async () => undefined),
      ruleCommit: vi.fn(),
    } as unknown as OrchestratorAuthorizationHttpClient;
    const preparationIds = ['msp_browser_one', 'msp_browser_two', 'msp_browser_three'];
    const server = new OrchestratorHttpServer({
      authorization,
      services: {} as OrchestratorServicesHttpClient,
      worldId: 'w-demo',
      demoCaseId: 'case_demo',
      demoMandateId: 'mdt_demo_grant',
      caseOfficerToken: staticToken,
      authorizationOrigin: 'http://127.0.0.1:7801',
      caseConsoleAssets: { shell: '', script: '', stylesheet: '' },
      caseSessions: sessions,
      modelSelectionPreparations: new CaseModelSelectionPreparationStore({
        now: () => '2026-08-03T10:00:00.000Z',
        nextPreparationId: () => preparationIds.shift() ?? 'msp_browser_exhausted',
      }),
      caseState,
      host: '127.0.0.1',
      port: 0,
    });
    const address = await server.listen();
    const get = (path: string, token?: string, origin?: string) =>
      fetch(`${address.origin}${path}`, {
        headers: {
          ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
          ...(origin === undefined ? {} : { origin }),
        },
      });
    try {
      expect((await get('/w/w-demo/models')).status).toBe(401);
      expect((await get('/w/w-demo/models', staticToken)).status).toBe(401);
      expect((await get('/w/w-demo/models', sessionToken, 'http://127.0.0.1:9999')).status).toBe(403);
      const models = await get('/w/w-demo/models', sessionToken, address.origin);
      expect(models.status).toBe(200);
      await expect(models.json()).resolves.toEqual({
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        mandate_state: 'active',
        default_acting_model: modelTarget,
        models: [],
      });

      const current = await get(
        '/w/w-demo/cases/case_demo/model-selection',
        sessionToken,
        address.origin,
      );
      expect(current.status).toBe(200);
      await expect(current.json()).resolves.toEqual({
        state: 'unselected',
        case_id: 'case_demo',
        selection: null,
        latest_observation: null,
      });

      const postSelection = (path: string, body: unknown, token?: string, origin?: string) =>
        fetch(`${address.origin}${path}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
            ...(origin === undefined ? {} : { origin }),
          },
          body: JSON.stringify(body),
        });
      const preparationPath = '/w/w-demo/cases/case_demo/model-selection-preparations';
      expect((await postSelection(preparationPath, { target: modelTarget }, sessionToken)).status).toBe(403);
      expect(
        (await postSelection(preparationPath, { target: modelTarget }, sessionToken, 'http://127.0.0.1:9999')).status,
      ).toBe(403);
      expect((await postSelection(preparationPath, { target: modelTarget }, staticToken, address.origin)).status).toBe(
        401,
      );
      expect(
        (await postSelection(preparationPath, { target: modelTarget, check_id: 'msc_caller' }, sessionToken, address.origin))
          .status,
      ).toBe(422);
      const prepared = await postSelection(preparationPath, { target: modelTarget }, sessionToken, address.origin);
      expect(prepared.status).toBe(201);
      const preparedBody = await prepared.json();
      expect(preparedBody).toMatchObject({
        preparation: { preparation_id: 'msp_browser_one', target: modelTarget },
        evidence: { approval: modelTarget },
      });
      for (const hidden of ['msc_hidden', digest, 'verifying_key_id', 'system_use_decision']) {
        expect(JSON.stringify(preparedBody)).not.toContain(hidden);
      }
      expect(checkModelSelection).toHaveBeenCalledWith(
        'w-demo',
        'case_demo',
        { expected_current_selection_id: null, target: modelTarget },
        { role: 'case_officer', session_id: 'session_test' },
      );

      const selectionPath = '/w/w-demo/cases/case_demo/model-selections';
      expect(
        (await postSelection(selectionPath, { preparation_id: 'msp_browser_one' }, sessionToken)).status,
      ).toBe(403);
      const selected = await postSelection(
        selectionPath,
        { preparation_id: 'msp_browser_one' },
        sessionToken,
        address.origin,
      );
      expect(selected.status).toBe(200);
      const selectedBody = await selected.json();
      expect(selectedBody).toMatchObject({
        selection: { selection_id: 'sel_one', target: modelTarget },
        invalidated_ruling_count: 0,
        terminalized_open_call_count: 0,
      });
      expect(JSON.stringify(selectedBody)).not.toContain('msc_hidden');
      expect(selectModel).toHaveBeenCalledWith(
        'w-demo',
        'case_demo',
        { check_id: 'msc_hidden', expected_current_selection_id: null },
        { role: 'case_officer', session_id: 'session_test' },
      );
      expect(
        (
          await postSelection(
            selectionPath,
            { preparation_id: 'msp_browser_one' },
            sessionToken,
            address.origin,
          )
        ).status,
      ).toBe(409);
      expect(selectModel).toHaveBeenCalledTimes(1);

      const ambiguousPreparation = await postSelection(
        preparationPath,
        { target: modelTarget },
        sessionToken,
        address.origin,
      );
      expect(ambiguousPreparation.status).toBe(201);
      selectModel.mockRejectedValueOnce(new Error('synthetic lost dependency response'));
      const ambiguous = await postSelection(
        selectionPath,
        { preparation_id: 'msp_browser_two' },
        sessionToken,
        address.origin,
      );
      expect(ambiguous.status).toBe(502);
      await expect(ambiguous.json()).resolves.toEqual({ error: 'dependency-failure' });
      expect(
        (
          await postSelection(
            selectionPath,
            { preparation_id: 'msp_browser_two' },
            sessionToken,
            address.origin,
          )
        ).status,
      ).toBe(409);
      expect(selectModel).toHaveBeenCalledTimes(2);

      const mismatchedPreparation = await postSelection(
        preparationPath,
        { target: modelTarget },
        sessionToken,
        address.origin,
      );
      expect(mismatchedPreparation.status).toBe(201);
      selectModel.mockResolvedValueOnce({
        ...selectionResult,
        selection: { ...selectionResult.selection, check_id: 'msc_wrong_dependency_binding' },
      });
      const mismatched = await postSelection(
        selectionPath,
        { preparation_id: 'msp_browser_three' },
        sessionToken,
        address.origin,
      );
      expect(mismatched.status).toBe(502);
      expect(
        (
          await postSelection(
            selectionPath,
            { preparation_id: 'msp_browser_three' },
            sessionToken,
            address.origin,
          )
        ).status,
      ).toBe(409);
      expect(selectModel).toHaveBeenCalledTimes(3);

      const state = await get('/w/w-demo/cases/case_demo/state', sessionToken, address.origin);
      expect(state.status).toBe(200);
      const body = await state.json();
      expect(body).toMatchObject({
        case_id: 'case_demo',
        model_interaction_available: false,
        ruling: {
          ruling_id: 'rul_dialogue',
          reason: 'A third-party fact needs a routed response.',
          status: 'invalidated',
          successor_ruling_id: 'rul_successor',
        },
        dialogue: {
          escalation_id: 'esc_dialogue',
          status: 'terminal',
          response_url: 'http://127.0.0.1:7801/console/dialogue/w-demo/esc_dialogue',
        },
      });
      expect(JSON.stringify(body)).not.toMatch(/question|contract|token/i);
      expect(rulingStatus).toHaveBeenCalledWith('w-demo', 'rul_dialogue');
      expect(approvedModels).toHaveBeenCalledWith('w-demo', 'mdt_demo_grant');

      const message = await fetch(`${address.origin}/w/w-demo/cases/case_demo/messages`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${sessionToken}`,
          origin: address.origin,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ message: 'Synthetic message.' }),
      });
      expect(message.status).toBe(422);
      await expect(message.json()).resolves.toEqual({ error: 'invalid-request' });
    } finally {
      await server.close();
    }
  });

  it('runs a selected lane only through a single-use, same-session, content-free two-step route', async () => {
    const digest = 'd'.repeat(64);
    const target = {
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
    };
    const transition = {
      world_id: 'w-demo',
      selection_id: 'sel_native_turn',
      case_id: 'case_demo',
      kind: 'initial' as const,
      predecessor_selection_id: null,
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      target: { ...target, card_digest: digest, verifying_key_id: 'card_test' },
      system_use_decision: {
        decision_id: 'sud_native_turn',
        version: 1,
        record_digest: digest,
        status: 'approved' as const,
        conditions: [],
      },
      check_id: 'msc_native_turn',
      selected_at: '2026-08-07T09:00:00.000Z',
      authority_effect: 'none' as const,
    };
    let current = {
      state: 'selected' as const,
      authorization_boot_id: 'authz_boot_native_turn',
      case_id: 'case_demo',
      selection: transition,
      latest_observation: null,
    };
    const projection = {
      world_id: 'w-demo',
      case_id: 'case_demo',
      provider: target.card_id,
      role: 'acting' as const,
      items: [],
      summary: { included: 0, dropped: 0, dropped_item_ids: [], unmet_tags: [] },
    };
    const projectionDigest = digestFor('conversation-projection', projection);
    const beginModelCall = vi.fn(async (
      input: { worldId: string; turnId: string; selectionId: string },
      _claim?: { role: 'case_officer'; session_id: string },
    ) => ({
      call: {
        kind: 'model_call_lifecycle' as const,
        world_id: 'w-demo',
        call_id: `mcl_${input.turnId}`,
        authorization_boot_id: 'authz_boot_native_turn',
        case_id: 'case_demo',
        turn_id: input.turnId,
        selection_id: input.selectionId,
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: target.card_id,
        card_version: target.card_version,
        requested_id: target.requested_id,
        projection_digest: projectionDigest,
        projection_item_count: 0,
        system_use_decision: transition.system_use_decision,
        opened_at: '2026-08-07T09:00:00.000Z',
        expires_at: '2026-08-07T09:02:00.000Z',
        state: 'open' as const,
        outcome: 'indeterminate' as const,
        provider_disclosure: 'possible' as const,
        completed_at: null,
        served_id: null,
        output_digest: null,
        failure_reason: null,
      },
      projection,
    }));
    const admitModelOutput = vi.fn(async (
      _world: string,
      callId: string,
      input: Parameters<ModelTurnAuthorizationClient['admitModelOutput']>[2],
      _claim?: { role: 'case_officer'; session_id: string },
    ) => ({
      kind: 'model_call_admission' as const,
      call_id: callId,
      decision: {
        kind: 'model_output_control' as const,
        case_id: 'case_demo',
        turn_id: input.turn_id,
        selection_id: input.selection_id,
        mandate_id: input.mandate_id,
        mandate_version: input.mandate_version,
        card_id: input.card_id,
        card_version: input.card_version,
        requested_id: input.requested_id,
        served_id: input.served_id,
        projection_digest: input.projection_digest,
        projection_item_count: 0,
        output_digest: digestModelOutput(input, 'case_demo'),
        model_resolution: 'exact' as const,
        flags: [],
        authority_effect: 'none' as const,
        disposition: 'admitted' as const,
        reasons: [],
        derived_tags: [],
      },
    }));
    const failModelCall = vi.fn(async (
      _world: string,
      _input: unknown,
      _claim?: { role: 'case_officer'; session_id: string },
    ) => ({} as never));
    const authorization = {
      currentModelSelection: vi.fn(async () => current),
      checkModelSelection: vi.fn(),
      selectModel: vi.fn(),
      beginModelCall,
      admitModelOutput,
      failModelCall,
      rulingStatus: vi.fn(),
      approvedModels: vi.fn(),
      redeemCaseSessionHandoff: vi.fn(),
      closeCaseSession: vi.fn(async () => undefined),
      ruleCommit: vi.fn(),
    };
    const provider = vi
      .fn()
      .mockResolvedValueOnce({
        lane: 'publicai',
        requestedId: target.requested_id,
        servedId: target.requested_id,
        content: 'Synthetic output confined to quarantine.',
        toolCalls: [],
      })
      .mockRejectedValueOnce(new ModelAdapterError('timeout', 'synthetic timeout'));
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: authorization as unknown as ModelTurnAuthorizationClient,
      lanes: [{
        lane: 'publicai',
        cardId: target.card_id,
        cardVersion: target.card_version,
        requestedId: target.requested_id,
        adapter: { lane: 'publicai', requestedId: target.requested_id, act: provider },
      }],
    });
    const sessions = new CaseSessionStore({
      randomToken: (() => {
        const values = ['c'.repeat(64), 'e'.repeat(64), 'f'.repeat(64)];
        return () => values.shift() ?? '9'.repeat(64);
      })(),
      nextSessionId: (() => {
        const values = ['session_native_one', 'session_native_two', 'session_native_three'];
        return () => values.shift() ?? 'session_native_exhausted';
      })(),
      now: () => '2026-08-07T09:00:00.000Z',
    });
    const firstCreated = sessions.create({
      handoff_id: 'handoff_native_one',
      role: 'case_officer',
      world_id: 'w-demo',
      case_id: 'case_demo',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_native_turn',
      consumed_at: '2026-08-07T09:00:00.000Z',
    });
    const modelTurns = new CaseModelTurnStore({ now: () => '2026-08-07T09:00:00.000Z' });
    const server = new OrchestratorHttpServer({
      authorization: authorization as unknown as OrchestratorAuthorizationHttpClient,
      services: {} as OrchestratorServicesHttpClient,
      modelTurnCoordinator: coordinator,
      modelTurns,
      worldId: 'w-demo',
      demoCaseId: 'case_demo',
      demoMandateId: 'mdt_demo_grant',
      caseOfficerToken: 'b'.repeat(64),
      authorizationOrigin: 'http://127.0.0.1:7801',
      caseConsoleAssets: { shell: '', script: '', stylesheet: '' },
      caseSessions: sessions,
      host: '127.0.0.1',
      port: 0,
    });
    const address = await server.listen();
    const post = (path: string, body: unknown, token = firstCreated.session_token, origin = address.origin) =>
      fetch(`${address.origin}${path}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/json',
          origin,
        },
        body: JSON.stringify(body),
      });
    const preparationPath = '/w/w-demo/cases/case_demo/model-turn-preparations';
    const usePath = '/w/w-demo/cases/case_demo/model-turns';
    try {
      expect((await fetch(`${address.origin}${preparationPath}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: '{}',
      })).status).toBe(403);
      expect((await post(preparationPath, {}, firstCreated.session_token, 'null')).status).toBe(403);
      expect((await post(preparationPath, {}, 'b'.repeat(64))).status).toBe(401);
      expect((await post(preparationPath, { message: 'forbidden' })).status).toBe(422);
      expect(beginModelCall).not.toHaveBeenCalled();
      expect(provider).not.toHaveBeenCalled();

      const preparedResponse = await post(preparationPath, {});
      expect(preparedResponse.status).toBe(201);
      const prepared = (await preparedResponse.json()) as {
        preparation_id: string;
        turn_id: string;
        selection_id: string;
      };
      expect(Object.keys(prepared).sort()).toEqual([
        'expires_at',
        'issued_at',
        'preparation_id',
        'selection_id',
        'target',
        'turn_id',
      ]);
      expect((await post(usePath, { preparation_id: prepared.preparation_id }, firstCreated.session_token, 'null')).status)
        .toBe(403);
      expect((await fetch(`${address.origin}${usePath}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${firstCreated.session_token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ preparation_id: prepared.preparation_id }),
      })).status).toBe(403);
      expect((await post(usePath, { preparation_id: prepared.preparation_id }, 'b'.repeat(64))).status).toBe(401);
      expect(provider).not.toHaveBeenCalled();
      const runResponse = await post(usePath, { preparation_id: prepared.preparation_id });
      expect(runResponse.status).toBe(200);
      const run = await runResponse.json();
      expect(run).toMatchObject({
        turn_id: prepared.turn_id,
        state: 'quarantined',
        provider_disclosure: 'confirmed',
        quarantine: { release_state: 'sealed-no-release-path' },
      });
      expect(JSON.stringify(run)).not.toContain('Synthetic output confined');
      expect(provider).toHaveBeenCalledTimes(1);
      expect(provider.mock.calls[0]?.[0]).toMatchObject({ maxOutputTokens: 512 });
      expect(beginModelCall.mock.calls[0]?.[1]).toEqual({
        role: 'case_officer',
        session_id: firstCreated.session_id,
      });
      expect(admitModelOutput.mock.calls[0]?.[3]).toEqual({
        role: 'case_officer',
        session_id: firstCreated.session_id,
      });
      expect((await post(usePath, { preparation_id: prepared.preparation_id })).status).toBe(409);
      expect(provider).toHaveBeenCalledTimes(1);
      expect((await fetch(`${address.origin}${usePath}/${prepared.turn_id}`, {
        headers: {
          authorization: `Bearer ${firstCreated.session_token}`,
          origin: 'null',
        },
      })).status).toBe(403);
      expect((await fetch(`${address.origin}${usePath}/${prepared.turn_id}`, {
        headers: { authorization: `Bearer ${'b'.repeat(64)}` },
      })).status).toBe(401);
      const statusRead = await fetch(`${address.origin}${usePath}/${prepared.turn_id}`, {
        headers: { authorization: `Bearer ${firstCreated.session_token}` },
      });
      expect(statusRead.status).toBe(200);
      expect(await statusRead.json()).toEqual(run);

      const firstSession = sessions.authenticate(firstCreated.session_token, 'w-demo', 'case_demo');
      if (firstSession === null) throw new Error('synthetic session disappeared');
      expect((await post('/w/w-demo/case-sessions/close', {})).status).toBe(200);
      expect(authorization.closeCaseSession).toHaveBeenCalledWith(
        'w-demo',
        firstSession.session_id,
        { role: 'case_officer', session_id: firstSession.session_id },
      );
      expect(coordinator.quarantine.size).toBe(0);
      expect(modelTurns.status(prepared.turn_id, firstSession)).toMatchObject({
        state: 'discarded',
        terminal_reason: 'session-ended',
        quarantine: null,
      });

      const second = sessions.create({
        handoff_id: 'handoff_native_two',
        role: 'case_officer',
        world_id: 'w-demo',
        case_id: 'case_demo',
        target_origin: address.origin,
        authorization_boot_id: 'authz_boot_native_turn',
        consumed_at: '2026-08-07T09:00:00.000Z',
      });
      const secondPreparedResponse = await post(preparationPath, {}, second.session_token);
      const secondPrepared = (await secondPreparedResponse.json()) as { preparation_id: string; turn_id: string };
      const failedResponse = await post(usePath, { preparation_id: secondPrepared.preparation_id }, second.session_token);
      expect(await failedResponse.json()).toMatchObject({
        turn_id: secondPrepared.turn_id,
        state: 'failed',
        provider_disclosure: 'possible',
        terminal_reason: 'provider-failure',
        quarantine: null,
      });
      expect(failModelCall.mock.calls[0]?.[2]).toEqual({
        role: 'case_officer',
        session_id: second.session_id,
      });
      expect((await post('/w/w-demo/cases/case_demo/messages', { message: 'still closed' }, second.session_token)).status)
        .toBe(422);
      expect(provider).toHaveBeenCalledTimes(2);

      const third = sessions.create({
        handoff_id: 'handoff_native_three',
        role: 'case_officer',
        world_id: 'w-demo',
        case_id: 'case_demo',
        target_origin: address.origin,
        authorization_boot_id: 'authz_boot_native_turn',
        consumed_at: '2026-08-07T09:00:00.000Z',
      });
      current = { ...current, authorization_boot_id: 'authz_boot_restarted' };
      expect((await post(preparationPath, {}, third.session_token)).status).toBe(401);
      expect((await post(preparationPath, {}, third.session_token)).status).toBe(401);
      expect(provider).toHaveBeenCalledTimes(2);
    } finally {
      await server.close();
    }
  });

  it('prepares, consumes, and reads a governed message turn only through its bound browser session', async () => {
    const digest = 'e'.repeat(64);
    const target = {
      card_id: 'publicai-apertus-v1.5-70b',
      card_version: 1,
      requested_id: 'swiss-ai/apertus-v1.5-70b',
    };
    const current = {
      state: 'selected' as const,
      authorization_boot_id: 'authz_boot_message_listener',
      case_id: 'case_demo',
      selection: {
        world_id: 'w-demo',
        selection_id: 'sel_message_listener',
        case_id: 'case_demo',
        kind: 'initial' as const,
        predecessor_selection_id: null,
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        target: { ...target, card_digest: digest, verifying_key_id: 'card_test' },
        system_use_decision: {
          decision_id: 'sud_message_listener',
          version: 1,
          record_digest: digest,
          status: 'approved' as const,
          conditions: [],
        },
        check_id: 'msc_message_listener',
        selected_at: '2026-08-07T09:00:00.000Z',
        authority_effect: 'none' as const,
      },
      latest_observation: null,
    };
    const sessionToken = '7'.repeat(64);
    const sessions = new CaseSessionStore({
      randomToken: () => sessionToken,
      nextSessionId: () => 'session_message_listener',
      now: () => '2026-08-07T09:00:00.000Z',
    });
    const created = sessions.create({
      handoff_id: 'handoff_message_listener',
      role: 'case_officer',
      world_id: 'w-demo',
      case_id: 'case_demo',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_message_listener',
      consumed_at: '2026-08-07T09:00:00.000Z',
    });
    const conversation = vi.fn(async () => ({
      case_id: 'case_demo',
      conversation_version: 3,
      events: [
        {
          speaker: 'case_officer' as const,
          message_id: 'msg_listener',
          turn_id: 'turn_listener',
          text: 'Synthetic governed question.',
          recorded_at: '2026-08-07T09:00:00.000Z',
        },
        {
          speaker: 'model' as const,
          message_id: 'msg_listener',
          turn_id: 'turn_listener',
          text: 'Synthetic unconfirmed inference.',
          recorded_at: '2026-08-07T09:00:01.000Z',
          requested_id: target.requested_id,
          served_id: target.requested_id,
          classification: 'inferred-unconfirmed' as const,
        },
      ],
    }));
    const authorization = {
      currentModelSelection: vi.fn(async () => current),
      conversation,
      rulingStatus: vi.fn(),
      approvedModels: vi.fn(),
      redeemCaseSessionHandoff: vi.fn(),
      closeCaseSession: vi.fn(async () => undefined),
      ruleCommit: vi.fn(),
    } as unknown as OrchestratorAuthorizationHttpClient;
    const runMessage = vi.fn(async (input: { turnId: string }) => ({
      disposition: 'released' as const,
      admission: {
        kind: 'model_output_control' as const,
        disposition: 'admitted' as const,
        authority_effect: 'none' as const,
        case_id: 'case_demo',
        turn_id: input.turnId,
        selection_id: 'sel_message_listener',
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: target.card_id,
        card_version: target.card_version,
        requested_id: target.requested_id,
        served_id: target.requested_id,
        model_resolution: 'exact' as const,
        projection_digest: digest,
        projection_item_count: 1,
        output_digest: digest,
        flags: [],
        derived_tags: [],
        reasons: [],
      },
      ingestion: {
        kind: 'output_release_consumption_result' as const,
        release_id: 'rel_listener',
        state: 'consumed' as const,
        event_id: 'event_listener_output',
        item_id: 'item_listener_output',
        conversation_version: 3,
        recorded_at: '2026-08-07T09:00:01.000Z',
      },
    }));
    const coordinator = {
      quarantine: new ModelOutputQuarantine(),
      hasConfiguredLane: () => true,
      runMessage,
    } as unknown as ModelTurnCoordinator;
    const caseConversations = new CaseConversationStore({
      now: () => '2026-08-07T09:00:00.000Z',
      nextPreparationId: () => 'msgp_listener',
      nextMessageId: () => 'msg_listener',
      nextTurnId: () => 'turn_listener',
    });
    const server = new OrchestratorHttpServer({
      authorization,
      services: {} as OrchestratorServicesHttpClient,
      modelTurnCoordinator: coordinator,
      caseConversations,
      worldId: 'w-demo',
      demoCaseId: 'case_demo',
      demoMandateId: 'mdt_demo_grant',
      caseOfficerToken: '8'.repeat(64),
      authorizationOrigin: 'http://127.0.0.1:7801',
      caseConsoleAssets: { shell: '', script: '', stylesheet: '' },
      caseSessions: sessions,
      host: '127.0.0.1',
      port: 0,
    });
    const address = await server.listen();
    const post = (path: string, body: unknown, token = created.session_token, origin = address.origin) =>
      fetch(`${address.origin}${path}`, {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json', origin },
        body: JSON.stringify(body),
      });
    const preparationPath = '/w/w-demo/cases/case_demo/message-preparations';
    const messagePath = '/w/w-demo/cases/case_demo/messages';
    try {
      expect((await post(preparationPath, { message: 'Synthetic governed question.' }, created.session_token, 'null')).status)
        .toBe(403);
      expect((await post(preparationPath, { message: 'Synthetic governed question.' }, '8'.repeat(64))).status)
        .toBe(401);
      const preparedResponse = await post(preparationPath, { message: 'Synthetic governed question.' });
      expect(preparedResponse.status).toBe(201);
      const prepared = (await preparedResponse.json()) as { preparation_id: string; turn_id: string };
      expect(Object.keys(prepared).sort()).toEqual([
        'expires_at',
        'issued_at',
        'message_id',
        'preparation_id',
        'turn_id',
      ]);
      expect(JSON.stringify(prepared)).not.toContain('Synthetic governed question.');
      expect((await post(messagePath, { message: 'bypass' })).status).toBe(422);
      expect(runMessage).not.toHaveBeenCalled();
      const usedResponse = await post(messagePath, { preparation_id: prepared.preparation_id });
      expect(usedResponse.status).toBe(200);
      const used = await usedResponse.json();
      expect(used).toMatchObject({
        turn_id: prepared.turn_id,
        state: 'released',
        provider_disclosure: 'confirmed',
        quarantine: null,
      });
      expect(JSON.stringify(used)).not.toContain('Synthetic unconfirmed inference.');
      expect(runMessage).toHaveBeenCalledWith(
        expect.objectContaining({
          messageId: 'msg_listener',
          text: 'Synthetic governed question.',
          turnId: 'turn_listener',
          selectionId: 'sel_message_listener',
        }),
        { onBehalfOf: { role: 'case_officer', session_id: created.session_id } },
      );
      expect((await post(messagePath, { preparation_id: prepared.preparation_id })).status).toBe(409);
      const foreignRead = await fetch(`${address.origin}/w/w-demo/cases/case_demo/conversation`, {
        headers: { authorization: `Bearer ${created.session_token}`, origin: 'null' },
      });
      expect(foreignRead.status).toBe(403);
      const read = await fetch(`${address.origin}/w/w-demo/cases/case_demo/conversation`, {
        headers: { authorization: `Bearer ${created.session_token}` },
      });
      expect(read.status).toBe(200);
      expect(await read.json()).toEqual(await conversation.mock.results[0]?.value);
      expect(conversation).toHaveBeenCalledWith('w-demo', 'case_demo', {
        role: 'case_officer',
        session_id: created.session_id,
      });
    } finally {
      await server.close();
    }
  });
});
