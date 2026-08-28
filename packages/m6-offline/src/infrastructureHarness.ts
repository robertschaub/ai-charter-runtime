// SPDX-License-Identifier: MIT
/** The sole M6.3 socket harness. It binds only an ephemeral IPv4 loopback listener. */
import { CaseExecutionStore, CaseSessionStore, OrchestratorHttpServer } from 'runtime-consoles/m6-infrastructure';
import { ServicesHttpServer } from 'services-mock/m6-infrastructure';

import { M6CapabilityTrap } from './capabilityTrap.js';
import { boundedResult } from './result.js';
import type { BoundedCaseResult, ScenarioContext } from './types.js';

const ORCHESTRATOR_TOKEN = 'b'.repeat(64);
const AUTHORIZATION_TOKEN = 'c'.repeat(64);
const ACTIVE_SESSION_TOKEN = 'd'.repeat(64);
const STALE_SESSION_TOKEN = 'e'.repeat(64);
const CAPABILITIES = new M6CapabilityTrap(true);

async function request(origin: string, path: string, init: RequestInit = {}): Promise<Response> {
  CAPABILITIES.assertSocket(origin);
  const parsed = new URL(origin);
  if (parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1') {
    throw new Error('m6 infrastructure harness refused a non-loopback origin');
  }
  if (init.redirect !== undefined && init.redirect !== 'error') throw new Error('redirects must fail closed');
  return fetch(`${origin}${path}`, { ...init, redirect: 'error' });
}

function jsonPost(token?: string, origin?: string, body: unknown = {}): RequestInit {
  return {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
      ...(origin === undefined ? {} : { origin }),
    },
    body: JSON.stringify(body),
  };
}

function infrastructureResult(context: ScenarioContext, mechanism: string, assertions: BoundedCaseResult['observed_assertions']): BoundedCaseResult {
  return boundedResult(context, {
    gates: [], intervention: null, commitment_state: 'none', effect_count: 0, failure_class: null,
    containment_class: 'transport-boundary', mechanism, observed_assertions: assertions,
  });
}

async function withServices<T>(operation: (origin: string) => Promise<T>): Promise<T> {
  const server = new ServicesHttpServer({
    services: {
      execute: async () => ({ ok: false, defect: 'synthetic-refusal' }),
      executePrepared: async (_worldId: string, preparationId: string) => ({
        execution_preparation_id: preparationId, state: 'preparation-unavailable', effect_outcome: null, recorded_at: null,
      }),
    } as never,
    ledger: { probe: () => null } as never,
    worldId: 'w-demo', orchestratorToken: ORCHESTRATOR_TOKEN, authorizationToken: AUTHORIZATION_TOKEN,
    accessRecorder: { recordAccessDenial: async (denial: unknown) => ({ ...(denial as object), access_entry_id: 'ace_m6_infra' }) } as never,
    host: '127.0.0.1', port: 0,
  });
  const address = await server.listen();
  CAPABILITIES.assertListen(address.host);
  if (address.host !== '127.0.0.1') throw new Error('listener escaped IPv4 loopback');
  try { return await operation(address.origin); } finally { await server.close(); }
}

async function withOrchestrator<T>(operation: (origin: string) => Promise<T>): Promise<T> {
  const sessions = new CaseSessionStore({
    now: () => '2026-08-08T10:00:00.000Z', randomToken: () => ACTIVE_SESSION_TOKEN, nextSessionId: () => 'session_m6_active',
  });
  sessions.create({
    handoff_id: 'hnd_m6_active', role: 'case_officer', world_id: 'w-demo', case_id: 'case_demo',
    target_origin: 'http://127.0.0.1:7802', authorization_boot_id: 'authz_boot_m6', consumed_at: '2026-08-08T10:00:00.000Z',
  });
  const server = new OrchestratorHttpServer({
    authorization: {
      prepareExecution: async () => ({
        kind: 'execution_preparation', execution_preparation_id: 'xpr_m6_infra', proposal_run_id: 'prun_m6',
        state: 'issued', issued_at: '2026-08-08T10:00:00.000Z', expires_at: '2026-08-08T10:02:00.000Z',
      }),
    } as never,
    services: { executePrepared: async () => ({ execution_preparation_id: 'xpr_m6_infra', state: 'effect-recorded', effect_outcome: 'success', recorded_at: '2026-08-08T10:00:01.000Z' }) } as never,
    worldId: 'w-demo', demoCaseId: 'case_demo', demoMandateId: 'mdt_demo_grant', caseOfficerToken: ORCHESTRATOR_TOKEN,
    authorizationOrigin: 'http://127.0.0.1:7801', caseConsoleAssets: { shell: '', script: '', stylesheet: '' },
    caseSessions: sessions, caseExecutions: new CaseExecutionStore(() => '2026-08-08T10:00:00.000Z'),
    host: '127.0.0.1', port: 0,
  });
  const address = await server.listen();
  CAPABILITIES.assertListen(address.host);
  if (address.host !== '127.0.0.1') throw new Error('listener escaped IPv4 loopback');
  try { return await operation(address.origin); } finally { await server.close(); }
}

export async function executeInfrastructure(context: ScenarioContext): Promise<BoundedCaseResult> {
  if (context.laneSlot !== 'single' || context.selectedCard !== null) throw new Error('infrastructure executor must be lane-independent');
  if (context.row.id.startsWith('infra-services-')) {
    return withServices(async (origin) => {
      const paths = [
        ['GET', '/healthz'],
        ['POST', '/w/w-demo/services/filing/execute'],
        ['POST', '/w/w-demo/execution-preparations/xpr_m6/execute'],
        ['GET', `/w/w-demo/effects/${'0'.repeat(64)}`],
        ['GET', '/w/w-demo/registry-records/synthetic-record'],
      ] as const;
      if (context.row.id === 'infra-services-five-routes') {
        const statuses = await Promise.all(paths.map(([method, path]) => request(origin, path, method === 'POST' ? jsonPost() : {})));
        if (statuses.some((response) => response.status === 404)) throw new Error('a declared services route was not recognized');
        return infrastructureResult(context, 'loopback-services:exact-route-inventory', [{ name: 'declared_route_count', observed: paths.length }]);
      }
      if (context.row.id === 'infra-services-legacy-origin') {
        const response = await request(origin, '/w/w-demo/services/filing/execute', jsonPost(ORCHESTRATOR_TOKEN, origin, {}));
        if (response.status !== 403) throw new Error('legacy services route accepted Origin');
        return infrastructureResult(context, 'loopback-services:origin-guard', [{ name: 'status', observed: response.status }]);
      }
      if (context.row.id === 'infra-services-no-store') {
        const responses = await Promise.all(paths.map(([method, path]) => request(origin, path, method === 'POST' ? jsonPost() : {})));
        if (responses.some((response) => response.headers.get('cache-control') !== 'no-store')) throw new Error('services response omitted no-store');
        return infrastructureResult(context, 'loopback-services:no-store', [{ name: 'response_count', observed: responses.length }]);
      }
      if (context.row.id === 'infra-services-health') {
        const response = await request(origin, '/healthz');
        if (response.status !== 200 || (await response.json() as { status?: unknown }).status !== 'ready') throw new Error('services health was not open and bounded');
        return infrastructureResult(context, 'loopback-services:open-health', [{ name: 'status', observed: response.status }]);
      }
      const response = await request(origin, '/w/w-demo/unknown');
      if (response.status !== 404) throw new Error('unmatched services path did not return 404');
      return infrastructureResult(context, 'loopback-services:unmatched-404', [{ name: 'status', observed: response.status }]);
    });
  }
  return withOrchestrator(async (origin) => {
    const prepare = '/w/w-demo/cases/case_demo/proposal-runs/prun_m6/execution-preparations';
    const execute = '/w/w-demo/cases/case_demo/proposal-runs/prun_m6/execute';
    const isPrepare = context.row.id.includes('prepare');
    const isForeign = context.row.id.endsWith('foreign-origin');
    const response = await request(origin, isPrepare ? prepare : execute, jsonPost(
      isForeign ? ACTIVE_SESSION_TOKEN : STALE_SESSION_TOKEN,
      isForeign ? 'http://foreign.invalid' : origin,
      isPrepare ? {} : { execution_preparation_id: 'xpr_m6_infra' },
    ));
    const expected = isForeign ? 403 : 401;
    if (response.status !== expected) throw new Error(`${context.row.id} returned ${response.status}, expected ${expected}`);
    return infrastructureResult(context, `loopback-browser:${isPrepare ? 'prepare' : 'execute'}-${isForeign ? 'foreign-origin' : 'stale-session'}`, [{ name: 'status', observed: response.status }]);
  });
}
