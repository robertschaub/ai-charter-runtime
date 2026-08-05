// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from 'vitest';

import { CaseConsoleStateStore } from './caseConsoleState.js';
import { CaseModelSelectionPreparationStore } from './caseModelSelection.js';
import { CaseSessionStore } from './caseSessionStore.js';
import { OrchestratorHttpServer } from './orchestratorHttpServer.js';
import type { OrchestratorAuthorizationHttpClient, OrchestratorServicesHttpClient } from './runtimeHttpClients.js';

describe('orchestrator case-console routes', () => {
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
      expect(message.status).toBe(501);
      await expect(message.json()).resolves.toEqual({ error: 'model-interaction-not-active' });
    } finally {
      await server.close();
    }
  });
});
