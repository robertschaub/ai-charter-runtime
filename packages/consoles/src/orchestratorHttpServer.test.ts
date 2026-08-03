// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from 'vitest';

import { CaseConsoleStateStore } from './caseConsoleState.js';
import { CaseSessionStore } from './caseSessionStore.js';
import { OrchestratorHttpServer } from './orchestratorHttpServer.js';
import type { OrchestratorAuthorizationHttpClient, OrchestratorServicesHttpClient } from './runtimeHttpClients.js';

describe('orchestrator case-console routes', () => {
  it('confines model evidence and the two-hop ruling mirror to the dynamic case session', async () => {
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
      models: [],
    }));
    const authorization = {
      rulingStatus,
      approvedModels,
      redeemCaseSessionHandoff: vi.fn(),
      ruleCommit: vi.fn(),
    } as unknown as OrchestratorAuthorizationHttpClient;
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
        models: [],
      });

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
