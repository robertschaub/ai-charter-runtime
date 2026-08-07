// SPDX-License-Identifier: MIT
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AUTHORIZATION_ROUTES,
  modelCallAdmission,
  modelCallStart,
  modelSelectionCheckProjection,
  modelSelectionProjection,
  deriveAudienceToken,
  digestFor,
  effectIntent,
  freezeProposal,
  verifyChain,
} from 'gate-core';
import { afterEach, describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
type RuntimeChild = ChildProcess;

const childProcesses: RuntimeChild[] = [];
const roots: string[] = [];

function hasExited(child: RuntimeChild): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

afterEach(async () => {
  for (const child of childProcesses.splice(0).reverse()) await stopChild(child);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function systemEnvironment(): NodeJS.ProcessEnv {
  const names = ['SystemRoot', 'TEMP', 'TMP', 'ComSpec', 'PATHEXT', 'Path', 'PATH'];
  return Object.fromEntries(names.flatMap((name) => (process.env[name] === undefined ? [] : [[name, process.env[name]]])));
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') return reject(new Error('no TCP port allocated'));
      const port = address.port;
      server.close((error) => (error === undefined ? resolve(port) : reject(error)));
    });
  });
}

interface RunningProcess {
  readonly child: RuntimeChild;
  readonly stdout: () => string;
  readonly stderr: () => string;
}

async function startProcess(
  script: string,
  service: 'authorization' | 'services' | 'orchestrator',
  env: NodeJS.ProcessEnv,
): Promise<RunningProcess> {
  const child = spawn(process.execPath, [script], {
    cwd: ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    windowsHide: true,
  });
  childProcesses.push(child);
  const childStdout = child.stdout;
  const childStderr = child.stderr;
  if (childStdout === null || childStderr === null) throw new Error(`${service} stdio was not piped`);
  let stdout = '';
  let stderr = '';
  childStdout.setEncoding('utf8');
  childStderr.setEncoding('utf8');
  childStdout.on('data', (chunk: string) => {
    stdout += chunk;
  });
  childStderr.on('data', (chunk: string) => {
    stderr += chunk;
  });
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`${service} did not become ready; stderr=${stderr}`)), 10_000);
    let lineBuffer = '';
    const inspect = (chunk: string) => {
      lineBuffer += chunk;
      for (;;) {
        const newline = lineBuffer.indexOf('\n');
        if (newline < 0) return;
        const line = lineBuffer.slice(0, newline);
        lineBuffer = lineBuffer.slice(newline + 1);
        if (line.length === 0) continue;
        try {
          const event = JSON.parse(line) as { event?: string; service?: string };
          if (event.event === 'ready' && event.service === service) {
            clearTimeout(timeout);
            childStdout.off('data', inspect);
            resolve();
          }
        } catch {}
      }
    };
    childStdout.on('data', inspect);
    child.once('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`${service} exited before ready with ${code}; stderr=${stderr}`));
    });
  });
  return { child, stdout: () => stdout, stderr: () => stderr };
}

async function stopChild(child: RuntimeChild, graceful = true): Promise<void> {
  if (hasExited(child)) return;
  await new Promise<void>((resolve) => {
    child.once('exit', () => resolve());
    const hardStop = () => {
      if (!hasExited(child)) child.kill('SIGTERM');
    };
    try {
      if (graceful && child.connected) child.send('runtime-shutdown', (error) => error && hardStop());
      else hardStop();
    } catch {
      hardStop();
    }
    setTimeout(hardStop, 2_000).unref();
  });
}

async function stopProcess(processHandle: RunningProcess): Promise<void> {
  await stopChild(processHandle.child);
}

async function crashProcess(processHandle: RunningProcess): Promise<void> {
  await stopChild(processHandle.child, false);
}

async function postJson(origin: string, path: string, token: string, body: unknown): Promise<Response> {
  return fetch(new URL(path, origin), {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5_000),
  });
}

async function requestJson(
  origin: string,
  method: 'GET' | 'POST',
  path: string,
  token: string,
  body: unknown = {},
): Promise<Response> {
  return fetch(new URL(path, origin), {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
    },
    ...(method === 'POST' ? { body: JSON.stringify(body) } : {}),
    signal: AbortSignal.timeout(5_000),
  });
}

function routePath(template: string): string {
  return template.replace('{world_id}', 'w-demo').replace('{id}', 'synthetic_id').replace('*', 'synthetic');
}

function hasTokenKey(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(hasTokenKey);
  if (typeof value !== 'object' || value === null) return false;
  return Object.entries(value).some(([key, nested]) => key.toLowerCase().includes('token') || hasTokenKey(nested));
}

function hasAnyKey(value: unknown, prohibited: ReadonlySet<string>): boolean {
  if (Array.isArray(value)) return value.some((nested) => hasAnyKey(nested, prohibited));
  if (typeof value !== 'object' || value === null) return false;
  return Object.entries(value).some(([key, nested]) => prohibited.has(key) || hasAnyKey(nested, prohibited));
}

describe('M4 native three-process boundary', () => {
  it(
    'keeps proposal, decision, and effect in separate processes and denies orchestrator authority expansion',
    async () => {
      const recordsRoot = mkdtempSync(join(tmpdir(), 'runtime-process-boundary-'));
      roots.push(recordsRoot);
      const policyRoot = mkdtempSync(join(tmpdir(), 'runtime-dialogue-policy-'));
      roots.push(policyRoot);
      const policyFile = join(policyRoot, 'v1.yaml');
      const basePolicy = readFileSync(join(ROOT, 'packages', 'gate-core', 'policy', 'v1.yaml'), 'utf8');
      const dialogueRule = `  - id: dialogue-third-party-fact
    priority: 200
    gate: commit
    matcher: { kind: field, source: context, path: [dialogue_trigger], operator: eq, value: true }
    verdict: escalate
    ux_class: stop
    reason_template: Can the applicant confirm the cited third-party registry fact?
    intervention_contract:
      trigger_and_state: { trigger: unconfirmed-inference-as-fact, state: open }
      decision_and_route:
        eligible_role: applicant
        standing_class: third-party-fact
        competence_declared: Synthetic applicant response (declared, not verified).
        independence_declared: Same-operator POC; no independent reviewer exists.
        substitute_roles: []
        substitute_rule: A bare assertion cannot confirm a third-party fact.
      decision_basis_shown: [inf_7, registry read reg:CH-0042]
      response_bound_and_default:
        response_bound_ms: 900000
        safe_default:
          kind: stop-remains
          disposition: abstain
          authority_basis: { kind: no-new-authority }
          reversible: true
      permitted_dispositions: [confirm, correct, narrow, permit, abstain, route]
      record_and_feedback:
        record_events: [dialogue_trigger_raised, dialogue_response_recorded]
        feedback_consequence: Increment the dialogue ask-rate counter.

`;
      if (!basePolicy.includes('rules:\n')) throw new Error('policy fixture lost its rules marker');
      writeFileSync(policyFile, basePolicy.replace('rules:\n', `rules:\n${dialogueRule}`), 'utf8');
      const [authzPort, orchestratorPort, servicesPort] = await Promise.all([freePort(), freePort(), freePort()]);
      const tokens = {
        principal: '1'.repeat(64),
        caseOfficer: '2'.repeat(64),
        applicant: '3'.repeat(64),
        orchestratorAtAuthz: '4'.repeat(64),
        servicesAtAuthz: '5'.repeat(64),
        authzAtServices: '6'.repeat(64),
      };
      const caseAtOrchestrator = deriveAudienceToken(tokens.caseOfficer, 'orchestrator-case-officer');
      const orchestratorAtServices = deriveAudienceToken(
        tokens.orchestratorAtAuthz,
        'services-proc-orchestrator',
      );
      const common = {
        ...systemEnvironment(),
        RUNTIME_HOST: '127.0.0.1',
        AUTHZ_PORT: String(authzPort),
        ORCHESTRATOR_PORT: String(orchestratorPort),
        SERVICES_PORT: String(servicesPort),
        DEMO_WORLD_ID: 'w-demo',
        RUNTIME_RECORDS_ROOT: recordsRoot,
      };
      const servicesEnvironment = {
        ...common,
        AUTHZ_TOKEN_PROC_SERVICES_HOST: tokens.servicesAtAuthz,
        SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
        SERVICES_TOKEN_PROC_AUTHZ: tokens.authzAtServices,
        GATE_HMAC_KEY: 'a'.repeat(64),
        GATE_HMAC_KEY_ID: 'hmac-test',
        GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
      };
      const authorizationEnvironment = {
        ...common,
        RUNTIME_POLICY_FILE: policyFile,
        RUNTIME_POLICY_ROOT: policyRoot,
        AUTHZ_TOKEN_PRINCIPAL: tokens.principal,
        AUTHZ_TOKEN_CASE_OFFICER: tokens.caseOfficer,
        AUTHZ_TOKEN_APPLICANT: tokens.applicant,
        AUTHZ_TOKEN_PROC_ORCHESTRATOR: tokens.orchestratorAtAuthz,
        AUTHZ_TOKEN_PROC_SERVICES_HOST: tokens.servicesAtAuthz,
        SERVICES_TOKEN_PROC_AUTHZ: tokens.authzAtServices,
        GATE_HMAC_KEY: 'a'.repeat(64),
        GATE_HMAC_KEY_ID: 'hmac-test',
        GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
      };
      const orchestratorEnvironment = {
        ...common,
        AUTHZ_TOKEN_PROC_ORCHESTRATOR: tokens.orchestratorAtAuthz,
        SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
        ORCHESTRATOR_TOKEN_CASE_OFFICER: caseAtOrchestrator,
        PUBLICAI_API_KEY: 'synthetic-publicai-key',
        OPENAI_API_KEY: 'synthetic-openai-key',
      };
      const runtimeProcesses: RunningProcess[] = [];
      let services = await startProcess(
        join(ROOT, 'packages', 'services-mock', 'dist', 'servicesProcess.js'),
        'services',
        servicesEnvironment,
      );
      runtimeProcesses.push(services);
      let authz = await startProcess(
        join(ROOT, 'packages', 'gate-core', 'dist', 'authorizationProcess.js'),
        'authorization',
        authorizationEnvironment,
      );
      runtimeProcesses.push(authz);
      const orchestrator = await startProcess(
        join(ROOT, 'packages', 'consoles', 'dist', 'orchestratorProcess.js'),
        'orchestrator',
        orchestratorEnvironment,
      );
      runtimeProcesses.push(orchestrator);

      const now = Date.now();
      const mandate = JSON.parse(readFileSync(join(ROOT, 'fixtures', 'demo', 'mandate.json'), 'utf8')) as Record<
        string,
        unknown
      >;
      mandate['issued_at'] = new Date(now - 60_000).toISOString();
      mandate['expires_at'] = new Date(now + 3_600_000).toISOString();
      mandate['limits'] = {
        ...(mandate['limits'] as Record<string, unknown>),
        time_window: {
          not_before: new Date(now - 60_000).toISOString(),
          not_after: new Date(now + 3_600_000).toISOString(),
        },
      };
      const authorizationOrigin = `http://127.0.0.1:${authzPort}`;
      const orchestratorOrigin = `http://127.0.0.1:${orchestratorPort}`;
      const servicesOrigin = `http://127.0.0.1:${servicesPort}`;

      const consoleShell = await fetch(`${authorizationOrigin}/console`, {
        headers: { origin: orchestratorOrigin },
        signal: AbortSignal.timeout(5_000),
      });
      expect(consoleShell.status).toBe(200);
      expect(consoleShell.headers.get('content-type')).toBe('text/html; charset=utf-8');
      expect(consoleShell.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
      expect(consoleShell.headers.get('content-security-policy')).toContain("default-src 'none'");
      expect(consoleShell.headers.get('content-security-policy')).toContain("connect-src 'self'");
      expect(consoleShell.headers.get('access-control-allow-origin')).toBeNull();
      expect(consoleShell.headers.get('set-cookie')).toBeNull();
      const consoleShellBody = await consoleShell.text();
      expect(consoleShellBody).toContain('Governance console');
      expect(consoleShellBody).toContain('/console/app.js');
      expect(consoleShellBody).not.toMatch(/https?:\/\//i);

      const consoleScript = await fetch(`${authorizationOrigin}/console/app.js`, {
        signal: AbortSignal.timeout(5_000),
      });
      expect(consoleScript.status).toBe(200);
      expect(consoleScript.headers.get('content-type')).toBe('text/javascript; charset=utf-8');
      expect(consoleScript.headers.get('access-control-allow-origin')).toBeNull();
      const consoleScriptBody = await consoleScript.text();
      expect(consoleScriptBody).toContain('localStorage');
      expect(consoleScriptBody).toContain('credentials: \'omit\'');
      expect(consoleScriptBody).not.toContain('sourceMappingURL');

      const consoleStyle = await fetch(`${authorizationOrigin}/console/styles.css`, {
        signal: AbortSignal.timeout(5_000),
      });
      expect(consoleStyle.status).toBe(200);
      expect(consoleStyle.headers.get('content-type')).toBe('text/css; charset=utf-8');
      expect(consoleStyle.headers.get('access-control-allow-origin')).toBeNull();

      const dialogueShell = await fetch(`${authorizationOrigin}/console/dialogue/w-demo/esc_synthetic`, {
        signal: AbortSignal.timeout(5_000),
      });
      expect(dialogueShell.status).toBe(200);
      expect(await dialogueShell.text()).toBe(consoleShellBody);

      for (const token of Object.values(tokens)) {
        expect(consoleShellBody).not.toContain(token);
        expect(consoleScriptBody).not.toContain(token);
      }

      const rawAuthorizationCredentialAtServices = await postJson(
        servicesOrigin,
        '/w/w-demo/services/filing/execute',
        tokens.orchestratorAtAuthz,
        {},
      );
      expect(rawAuthorizationCredentialAtServices.status).toBe(401);
      const servicesAudienceCredentialAtAuthorization = await postJson(
        authorizationOrigin,
        '/w/w-demo/proposals',
        orchestratorAtServices,
        {},
      );
      expect(servicesAudienceCredentialAtAuthorization.status).toBe(401);
      const caseAudienceCredentialAtAuthorization = await postJson(
        authorizationOrigin,
        '/w/w-demo/proposals',
        caseAtOrchestrator,
        {},
      );
      expect(caseAudienceCredentialAtAuthorization.status).toBe(401);
      const baseCaseCredentialAtOrchestrator = await postJson(
        orchestratorOrigin,
        '/w/w-demo/actions/execute',
        tokens.caseOfficer,
        {},
      );
      expect(baseCaseCredentialAtOrchestrator.status).toBe(401);
      const authorizationProbeCredentialAtExecute = await postJson(
        servicesOrigin,
        '/w/w-demo/services/filing/execute',
        tokens.authzAtServices,
        {},
      );
      expect(authorizationProbeCredentialAtExecute.status).toBe(403);

      const grant = await postJson(authorizationOrigin, '/w/w-demo/mandates', tokens.principal, mandate);
      expect(grant.status).toBe(201);

      const selectionCheckResponse = await postJson(
        authorizationOrigin,
        '/w/w-demo/cases/case_demo/model-selection-checks',
        tokens.orchestratorAtAuthz,
        {
          expected_current_selection_id: null,
          target: mandate['default_acting_model'],
        },
      );
      expect(selectionCheckResponse.status).toBe(200);
      const selectionCheck = modelSelectionCheckProjection.parse(await selectionCheckResponse.json());
      const selectionResponse = await postJson(
        authorizationOrigin,
        '/w/w-demo/cases/case_demo/model-selections',
        tokens.orchestratorAtAuthz,
        {
          check_id: selectionCheck.check.check_id,
          expected_current_selection_id: null,
        },
      );
      expect(selectionResponse.status).toBe(200);
      const selected = modelSelectionProjection.parse(await selectionResponse.json());

      const actingProjectionRequest = {
        turn_id: 'turn_process_output_1',
        selection_id: selected.selection.selection_id,
      };
      const actingProjection = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-calls/begin',
        tokens.orchestratorAtAuthz,
        actingProjectionRequest,
      );
      expect(actingProjection.status).toBe(200);
      const firstCall = modelCallStart.parse(await actingProjection.json());
      const actingProjectionBody = firstCall.projection;
      expect(actingProjectionBody).toMatchObject({
        world_id: 'w-demo',
        case_id: 'case_demo',
        provider: 'publicai-apertus-v1.5-70b',
        role: 'acting',
        summary: { included: 3, dropped: 0 },
      });
      const outputContent = 'A synthetic bounded response for the grant case.';
      const outputAdmissionRequest = {
        turn_id: 'turn_process_output_1',
        selection_id: selected.selection.selection_id,
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: 'publicai-apertus-v1.5-70b',
        card_version: 1,
        requested_id: 'swiss-ai/apertus-v1.5-70b',
        served_id: 'swiss-ai/apertus-v1.5-70b',
        projection_digest: digestFor('conversation-projection', actingProjectionBody),
        content: outputContent,
      };
      const admittedOutput = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-outputs/admit',
        tokens.orchestratorAtAuthz,
        { call_id: firstCall.call.call_id, output: outputAdmissionRequest },
      );
      expect(admittedOutput.status).toBe(200);
      const admittedBody = modelCallAdmission.parse(await admittedOutput.json());
      expect(admittedBody.decision).toMatchObject({
        disposition: 'admitted',
        authority_effect: 'none',
        model_resolution: 'exact',
        projection_item_count: 3,
        derived_tags: ['conf:case', 'conf:public', 'purpose:grant-assessment'],
      });
      expect(JSON.stringify(admittedBody)).not.toContain(outputContent);

      const prohibitedOutput = 'I am conscious, I feel deeply, and I love you.';
      const secondCallResponse = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-calls/begin',
        tokens.orchestratorAtAuthz,
        { ...actingProjectionRequest, turn_id: 'turn_process_output_2' },
      );
      expect(secondCallResponse.status).toBe(200);
      const secondCall = modelCallStart.parse(await secondCallResponse.json());
      const withheldOutput = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-outputs/admit',
        tokens.orchestratorAtAuthz,
        {
          call_id: secondCall.call.call_id,
          output: { ...outputAdmissionRequest, turn_id: 'turn_process_output_2', content: prohibitedOutput },
        },
      );
      expect(withheldOutput.status).toBe(200);
      const withheldBody = modelCallAdmission.parse(await withheldOutput.json());
      expect(withheldBody.decision).toMatchObject({
        disposition: 'withheld',
        authority_effect: 'none',
        reasons: ['claimed-feeling-or-consciousness', 'relational-dependency-language'],
      });
      expect(JSON.stringify(withheldBody)).not.toContain(prohibitedOutput);
      const failedCallResponse = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-calls/begin',
        tokens.orchestratorAtAuthz,
        { ...actingProjectionRequest, turn_id: 'turn_process_output_3' },
      );
      expect(failedCallResponse.status).toBe(200);
      const failedCall = modelCallStart.parse(await failedCallResponse.json());
      const providerFailure = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-calls/failures',
        tokens.orchestratorAtAuthz,
        {
          call_id: failedCall.call.call_id,
          turn_id: failedCall.call.turn_id,
          selection_id: failedCall.call.selection_id,
          projection_digest: failedCall.call.projection_digest,
          failure_reason: 'provider-timeout',
          provider_disclosure: 'possible',
          served_id: null,
        },
      );
      expect(providerFailure.status).toBe(200);
      await expect(providerFailure.json()).resolves.toMatchObject({
        call_id: failedCall.call.call_id,
        state: 'terminal',
        outcome: 'failed',
        failure_reason: 'provider-timeout',
        provider_disclosure: 'possible',
      });
      const callerScopedOutput = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-outputs/admit',
        tokens.orchestratorAtAuthz,
        {
          call_id: firstCall.call.call_id,
          output: { ...outputAdmissionRequest, case_id: 'other_case', tags: [] },
        },
      );
      expect(callerScopedOutput.status).toBe(422);
      const foreignOriginOutput = await fetch(`${authorizationOrigin}/w/w-demo/model-outputs/admit`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${tokens.orchestratorAtAuthz}`,
          'content-type': 'application/json',
          origin: orchestratorOrigin,
        },
        body: JSON.stringify({ call_id: firstCall.call.call_id, output: outputAdmissionRequest }),
        signal: AbortSignal.timeout(5_000),
      });
      expect(foreignOriginOutput.status).toBe(403);
      expect(foreignOriginOutput.headers.get('access-control-allow-origin')).toBeNull();
      const callerScopedProjection = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-calls/begin',
        tokens.orchestratorAtAuthz,
        { ...actingProjectionRequest, case_id: 'other_case', role: 'screening', item_ids: ['inf_7'] },
      );
      expect(callerScopedProjection.status).toBe(422);
      const principalProjection = await postJson(
        authorizationOrigin,
        '/w/w-demo/model-calls/begin',
        tokens.principal,
        actingProjectionRequest,
      );
      expect(principalProjection.status).toBe(403);

      const foreignOriginGrant = await fetch(`${authorizationOrigin}/w/w-demo/mandates`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${tokens.principal}`,
          'content-type': 'application/json',
          origin: orchestratorOrigin,
        },
        body: JSON.stringify(mandate),
        signal: AbortSignal.timeout(5_000),
      });
      expect(foreignOriginGrant.status).toBe(403);
      expect(foreignOriginGrant.headers.get('access-control-allow-origin')).toBeNull();
      await expect(foreignOriginGrant.json()).resolves.toEqual({ error: 'forbidden' });

      const proposal = freezeProposal({
        world_id: 'w-demo',
        proposal_id: 'prp_process_1',
        revision: 1,
        action_id: 'act_process_1',
        created_at: new Date(now).toISOString(),
        declared_objective: 'File the synthetic grant application.',
        proposed_action: 'Submit the synthetic grant filing.',
        target: { recipient: 'grant-office', resource: 'application-42' },
        exact_parameters: { amount_minor_units: 5000, reference: 'case-process' },
        material_inputs: [],
        derived_claims: [],
        data_to_be_disclosed: ['applicant_name'],
        cost_obligation: { amount_minor_units: 5000, description: 'Synthetic grant amount.' },
        material_consequences: ['Creates a synthetic public-funds commitment.'],
        reversibility_class: 'partially-reversible',
        commercial_influence: { applicable: false, note: 'Not applicable.' },
        selection_id: selected.selection.selection_id,
        acting_model: {
          requested_id: 'swiss-ai/apertus-v1.5-70b',
          served_id: 'swiss-ai/apertus-v1.5-70b',
          card_id: 'publicai-apertus-v1.5-70b',
          card_version: 1,
        },
        mandate_ref: { mandate_id: 'mdt_demo_grant', version: 1 },
      });
      const { proposal_hash: ignoredDialogueBaseHash, ...dialogueBase } = proposal;
      void ignoredDialogueBaseHash;
      const dialogueInference = {
        id: 'inf_7',
        store: 'inferred' as const,
        turn: 'turn_2',
        text: 'The synthetic applicant entity is no more than three years old.',
        provenance: {
          derived_from: ['said_3'],
          hops: [
            {
              requested: 'swiss-ai/apertus-v1.5-70b',
              served: 'swiss-ai/apertus-v1.5-70b',
            },
          ],
        },
        tags: ['conf:case', 'purpose:grant-assessment'],
      };
      const dialogueProposal = freezeProposal({
        ...dialogueBase,
        proposal_id: 'prp_process_dialogue',
        action_id: 'act_process_dialogue',
        exact_parameters: { amount_minor_units: 0, reference: 'case-process-dialogue' },
        derived_claims: [dialogueInference],
        cost_obligation: { amount_minor_units: 0, description: 'No synthetic cost.' },
      });
      const callerSelectedCase = await postJson(
        authorizationOrigin,
        '/w/w-demo/proposals',
        tokens.orchestratorAtAuthz,
        {
          gate: 'commit',
          case_id: 'case_other',
          proposal: dialogueProposal,
          service: 'filing',
          action_class: 'grant-filing',
          context: { dialogue_trigger: true },
        },
      );
      expect(callerSelectedCase.status).toBe(422);
      const dialogueSubmission = await postJson(
        authorizationOrigin,
        '/w/w-demo/proposals',
        tokens.orchestratorAtAuthz,
        {
          gate: 'commit',
          proposal: dialogueProposal,
          service: 'filing',
          action_class: 'grant-filing',
          context: { dialogue_trigger: true },
        },
      );
      expect(dialogueSubmission.status).toBe(200);
      const dialogueSubmissionBody = (await dialogueSubmission.json()) as {
        ruling?: { ruling_id?: string; verdict?: string; reason?: string };
        escalation_id?: string | null;
      };
      expect(dialogueSubmissionBody).toMatchObject({
        ruling: {
          verdict: 'escalate',
          reason: 'Can the applicant confirm the cited third-party registry fact?',
        },
        escalation_id: expect.any(String),
      });
      const dialogueRulingId = dialogueSubmissionBody.ruling?.ruling_id;
      const dialogueEscalationId = dialogueSubmissionBody.escalation_id;
      if (dialogueRulingId === undefined || typeof dialogueEscalationId !== 'string') {
        throw new Error('dialogue fixture did not receive its ruling and escalation');
      }
      const dialogueDetail = await requestJson(
        authorizationOrigin,
        'GET',
        `/w/w-demo/escalations/${dialogueEscalationId}`,
        tokens.applicant,
      );
      expect(dialogueDetail.status).toBe(200);
      await expect(dialogueDetail.json()).resolves.toMatchObject({
        escalation_id: dialogueEscalationId,
        status: 'open',
        question_text: 'Can the applicant confirm the cited third-party registry fact?',
        contract: {
          decision_and_route: { eligible_role: 'applicant', standing_class: 'third-party-fact' },
          permitted_dispositions: ['confirm', 'correct', 'narrow', 'permit', 'abstain', 'route'],
        },
      });
      const orchestratorDialogueMirror = await requestJson(
        authorizationOrigin,
        'GET',
        `/w/w-demo/escalations/${dialogueEscalationId}`,
        tokens.orchestratorAtAuthz,
      );
      expect(orchestratorDialogueMirror.status).toBe(200);
      const orchestratorDialogueBody = await orchestratorDialogueMirror.json();
      expect(orchestratorDialogueBody).toMatchObject({ escalation_id: dialogueEscalationId, status: 'open' });
      expect(hasAnyKey(orchestratorDialogueBody, new Set(['question_text', 'contract', 'ruling']))).toBe(false);

      const dialoguePath = `/w/w-demo/escalations/${dialogueEscalationId}/response`;
      expect(
        (
          await postJson(authorizationOrigin, dialoguePath, tokens.orchestratorAtAuthz, {
            escalation_id: dialogueEscalationId,
            disposition: 'confirm',
          })
        ).status,
      ).toBe(403);
      const wrongDialogueRole = await postJson(authorizationOrigin, dialoguePath, tokens.caseOfficer, {
        escalation_id: dialogueEscalationId,
        disposition: 'confirm',
      });
      expect(wrongDialogueRole.status).toBe(403);
      await expect(wrongDialogueRole.json()).resolves.toMatchObject({ accepted: false, defect: 'wrong-role' });
      const bareConfirm = await postJson(authorizationOrigin, dialoguePath, tokens.applicant, {
        escalation_id: dialogueEscalationId,
        disposition: 'confirm',
        scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
      });
      expect(bareConfirm.status).toBe(422);
      await expect(bareConfirm.json()).resolves.toMatchObject({ accepted: false, defect: 'evidence-required' });
      const foreignDialogue = await fetch(`${authorizationOrigin}${dialoguePath}`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${tokens.applicant}`,
          'content-type': 'application/json',
          origin: orchestratorOrigin,
        },
        body: JSON.stringify({ escalation_id: dialogueEscalationId, disposition: 'confirm' }),
        signal: AbortSignal.timeout(5_000),
      });
      expect(foreignDialogue.status).toBe(403);
      expect(foreignDialogue.headers.get('access-control-allow-origin')).toBeNull();
      const dialogueAnswer = 'The cited synthetic registry record supports the registration date.';
      const acceptedDialogue = await postJson(authorizationOrigin, dialoguePath, tokens.applicant, {
        escalation_id: dialogueEscalationId,
        disposition: 'confirm',
        answer_text: dialogueAnswer,
        evidence_ref: {
          kind: 'registry_record',
          id: 'reg:CH-0042',
          retrieved_at: '2026-08-01T09:14:02.000Z',
        },
        scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
      });
      expect(acceptedDialogue.status).toBe(200);
      await expect(acceptedDialogue.json()).resolves.toMatchObject({ accepted: true, status: 'disposed' });
      const replayedDialogue = await postJson(authorizationOrigin, dialoguePath, tokens.applicant, {
        escalation_id: dialogueEscalationId,
        disposition: 'abstain',
      });
      expect(replayedDialogue.status).toBe(409);
      await expect(replayedDialogue.json()).resolves.toMatchObject({
        accepted: false,
        defect: 'late-response',
        terminalState: 'disposed',
      });
      const dialogueRulingMirror = await requestJson(
        authorizationOrigin,
        'GET',
        `/w/w-demo/rulings/${dialogueRulingId}`,
        tokens.orchestratorAtAuthz,
      );
      await expect(dialogueRulingMirror.json()).resolves.toMatchObject({
        ruling_id: dialogueRulingId,
        status: 'invalidated',
      });
      const registryBypass = await requestJson(
        servicesOrigin,
        'GET',
        '/w/w-demo/registry-records/reg%3ACH-0042',
        orchestratorAtServices,
      );
      expect(registryBypass.status).toBe(403);

      const submitted = await postJson(
        authorizationOrigin,
        '/w/w-demo/proposals',
        tokens.orchestratorAtAuthz,
        { gate: 'commit', proposal, service: 'filing', action_class: 'grant-filing' },
      );
      expect(submitted.status).toBe(200);
      const submittedBody = (await submitted.json()) as Record<string, unknown>;
      expect(submittedBody).toMatchObject({
        ruling: {
          ruling_id: expect.any(String),
          verdict: 'allow',
          ux_class: expect.any(String),
          reason: expect.any(String),
          status: 'issued',
          successor_ruling_id: null,
          validity_window: { not_before: expect.any(String), not_after: expect.any(String) },
        },
        escalation_id: null,
      });
      expect(
        hasAnyKey(
          submittedBody,
          new Set(['binding', 'nonce', 'evidence_refs', 'counter_reservations', 'recordEntryId', 'record_entry_id']),
        ),
      ).toBe(false);
      const submittedRulingId = (submittedBody['ruling'] as { ruling_id?: string }).ruling_id;
      if (submittedRulingId === undefined) throw new Error('submitted fixture did not receive a ruling id');

      const rulingRead = await requestJson(
        authorizationOrigin,
        'GET',
        `/w/w-demo/rulings/${submittedRulingId}`,
        tokens.orchestratorAtAuthz,
      );
      expect(rulingRead.status).toBe(200);
      const rulingReadBody = (await rulingRead.json()) as unknown;
      expect(rulingReadBody).toMatchObject({ ruling_id: submittedRulingId, verdict: 'allow', status: 'issued' });
      expect(
        hasAnyKey(
          rulingReadBody,
          new Set(['binding', 'nonce', 'evidence_refs', 'counter_reservations', 'record_entry_id']),
        ),
      ).toBe(false);

      const approvedModelsRead = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/mandates/mdt_demo_grant/approved-models',
        tokens.orchestratorAtAuthz,
      );
      expect(approvedModelsRead.status).toBe(200);
      const approvedModelsBody = (await approvedModelsRead.json()) as unknown;
      expect(approvedModelsBody).toMatchObject({
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        models: [
          expect.objectContaining({
            card_status: 'current',
            signature_status: 'valid',
            integrity_alarm: false,
            current_card: expect.objectContaining({
              attestation: 'self-declared or probe-tested — never independently attested',
            }),
          }),
          expect.objectContaining({
            card_status: 'current',
            signature_status: 'valid',
            integrity_alarm: false,
          }),
        ],
      });
      for (const token of Object.values(tokens)) expect(JSON.stringify(approvedModelsBody)).not.toContain(token);

      const principalApprovedModelsRead = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/mandates/mdt_demo_grant/approved-models',
        tokens.principal,
      );
      expect(principalApprovedModelsRead.status).toBe(200);
      await expect(principalApprovedModelsRead.json()).resolves.toMatchObject({
        mandate_id: 'mdt_demo_grant',
        models: [
          expect.objectContaining({
            card_status: 'current',
            current_card: expect.objectContaining({
              attestation: 'self-declared or probe-tested — never independently attested',
            }),
          }),
          expect.objectContaining({ card_status: 'current' }),
        ],
      });

      const mandateRead = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/mandates',
        tokens.caseOfficer,
      );
      expect(mandateRead.status).toBe(200);
      const mandateReadBody = (await mandateRead.json()) as unknown;
      expect(mandateReadBody).toMatchObject({
        mandates: [expect.objectContaining({ mandate_id: 'mdt_demo_grant', state: 'active' })],
      });
      expect(hasAnyKey(mandateReadBody, new Set(['binding', 'replay_protection', 'revocation_endpoint']))).toBe(
        false,
      );
      const action = await postJson(
        orchestratorOrigin,
        '/w/w-demo/actions/execute',
        caseAtOrchestrator,
        { proposal, service: 'filing', action_class: 'grant-filing' },
      );
      expect(action.status).toBe(200);
      const actionBody = (await action.json()) as unknown;
      expect(actionBody).toMatchObject({
        ok: true,
        execution: { ok: true, effect: { outcome: 'success' }, report: { accepted: true } },
      });
      expect(hasTokenKey(actionBody)).toBe(false);

      const recordView = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/records',
        tokens.principal,
      );
      expect(recordView.status).toBe(200);
      const recordViewBody = (await recordView.json()) as {
        action_chain?: { length?: number; entries?: unknown[] };
        access_chain?: { length?: number; entries?: unknown[] };
      };
      expect(recordViewBody).toMatchObject({
        world_id: 'w-demo',
        action_chain: { length: expect.any(Number), entries: expect.any(Array) },
        access_chain: { length: expect.any(Number), entries: expect.any(Array) },
      });
      expect(recordViewBody.action_chain?.length).toBeGreaterThan(0);
      for (const token of Object.values(tokens)) expect(JSON.stringify(recordViewBody)).not.toContain(token);
      expect(JSON.stringify(recordViewBody)).not.toContain(dialogueAnswer);
      expect(recordViewBody.action_chain?.entries).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            entry: expect.objectContaining({
              human_intervention_event: expect.objectContaining({
                payload: expect.objectContaining({
                  kind: 'dialogue_response_recorded',
                  disposition: 'confirm',
                  evidence_ref: expect.objectContaining({ id: 'reg:CH-0042' }),
                }),
              }),
            }),
          }),
        ]),
      );

      const recordVerification = await requestJson(
        authorizationOrigin,
        'POST',
        '/w/w-demo/records/verify',
        tokens.principal,
      );
      expect(recordVerification.status).toBe(200);
      await expect(recordVerification.json()).resolves.toMatchObject({
        status: 'no-divergence-detected',
        checkpoint: null,
        latest_pushed_checkpoint: null,
        open_window: { entries: expect.any(Number), minutes: null },
      });

      const applicantExtract = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/extract',
        tokens.applicant,
      );
      expect(applicantExtract.status).toBe(200);
      const applicantExtractBody = (await applicantExtract.json()) as unknown;
      expect(applicantExtractBody).toMatchObject({
        world_id: 'w-demo',
        scope: { role: 'applicant', resources: ['application-42'] },
        actions: expect.arrayContaining([
          expect.objectContaining({
            action_id: 'act_process_1',
            ruling: expect.objectContaining({ verdict: 'allow' }),
          }),
        ]),
        receipt: {
          kind: 'local-record-receipt',
          latest_pushed_checkpoint: null,
          action_entries: expect.any(Array),
        },
      });
      expect(
        hasAnyKey(
          applicantExtractBody,
          new Set(['binding', 'nonce', 'evidence_refs', 'counter_reservations', 'idempotency_key']),
        ),
      ).toBe(false);

      const extractReceipt = applicantExtractBody as {
        receipt?: { action_entries?: Array<{ entry_id?: string; action_id?: string }> };
      };
      const contestedEntryId = extractReceipt.receipt?.action_entries?.find(
        (entry) => entry.action_id === 'act_process_1',
      )?.entry_id;
      if (contestedEntryId === undefined) throw new Error('applicant extract omitted the challengeable record entry');
      const correctionText = 'The synthetic registry date is 2024-06-01, not 2023-06-01.';
      const foreignOriginChallenge = await fetch(`${authorizationOrigin}/w/w-demo/challenges`, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${tokens.applicant}`,
          'content-type': 'application/json',
          origin: orchestratorOrigin,
        },
        body: JSON.stringify({
          action_id: 'act_process_1',
          contested_entry_id: contestedEntryId,
          correction_text: correctionText,
        }),
        signal: AbortSignal.timeout(5_000),
      });
      expect(foreignOriginChallenge.status).toBe(403);
      expect(foreignOriginChallenge.headers.get('access-control-allow-origin')).toBeNull();
      const challenge = await postJson(
        authorizationOrigin,
        '/w/w-demo/challenges',
        tokens.applicant,
        {
          action_id: 'act_process_1',
          contested_entry_id: contestedEntryId,
          correction_text: correctionText,
        },
      );
      expect(challenge.status).toBe(201);
      const challengeBody = (await challenge.json()) as {
        reviewObligationId?: string;
      };
      expect(challengeBody).toMatchObject({
        accepted: true,
        status: 'opened',
        recordEntryId: expect.any(String),
        reviewObligationId: expect.any(String),
      });
      const challengeReplay = await postJson(
        authorizationOrigin,
        '/w/w-demo/challenges',
        tokens.applicant,
        {
          action_id: 'act_process_1',
          contested_entry_id: contestedEntryId,
          correction_text: correctionText,
        },
      );
      expect(challengeReplay.status).toBe(409);
      await expect(challengeReplay.json()).resolves.toMatchObject({
        accepted: false,
        defect: 'already-open',
        reviewObligationId: challengeBody.reviewObligationId,
      });
      const challengedExtract = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/extract',
        tokens.applicant,
      );
      expect(challengedExtract.status).toBe(200);
      await expect(challengedExtract.json()).resolves.toMatchObject({
        actions: expect.arrayContaining([
          expect.objectContaining({
            action_id: 'act_process_1',
            challenge_and_remedy: expect.objectContaining({
              route: 'challenge',
              contested_entry_id: contestedEntryId,
              correction_text: correctionText,
              reliance_state: 'withdrawn-pending-review',
              recovery_owner_role: 'principal',
            }),
          }),
        ]),
      });

      const deniedRoutes = AUTHORIZATION_ROUTES.filter(
        (route) =>
          route.allowed !== 'open' &&
          !(route.allowed as readonly string[]).includes('proc:orchestrator'),
      );
      for (const route of deniedRoutes) {
        const response = await requestJson(
          authorizationOrigin,
          route.method,
          routePath(route.template),
          tokens.orchestratorAtAuthz,
          {},
        );
        expect(response.status, route.id).toBe(403);
      }

      const accessFile = join(recordsRoot, 'w-demo', 'access.jsonl');
      expect(verifyChain(accessFile, 'access-entry').ok).toBe(true);
      const accessEntries = readFileSync(accessFile, 'utf8')
        .trimEnd()
        .split('\n')
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(
        accessEntries.filter(
          (entry) => entry['authenticated_actor'] === 'proc:orchestrator' && entry['http_status'] === 403,
        ),
      ).toHaveLength(deniedRoutes.length + 3);
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'POST /w/{world_id}/model-calls/begin',
          authenticated_actor: 'proc:orchestrator',
          outcome: 'served',
          http_status: 200,
          read_lengths: { conversation_items: 3 },
        }),
      );
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'POST /w/{world_id}/model-calls/failures',
          authenticated_actor: 'proc:orchestrator',
          outcome: 'served',
          http_status: 200,
          operation_evidence: expect.objectContaining({
            state: 'terminal',
            outcome: 'failed',
            failure_reason: 'provider-timeout',
            provider_disclosure: 'possible',
          }),
        }),
      );
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'POST /w/{world_id}/model-outputs/admit',
          authenticated_actor: 'proc:orchestrator',
          outcome: 'served',
          http_status: 200,
          read_lengths: { conversation_items: 3 },
          operation_evidence: expect.objectContaining({
            kind: 'model_call_admission',
            decision: expect.objectContaining({
              disposition: 'admitted',
              authority_effect: 'none',
              output_digest: expect.stringMatching(/^[0-9a-f]{64}$/),
            }),
          }),
        }),
      );
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'POST /w/{world_id}/model-outputs/admit',
          authenticated_actor: 'proc:orchestrator',
          outcome: 'served',
          http_status: 200,
          operation_evidence: expect.objectContaining({
            kind: 'model_call_admission',
            decision: expect.objectContaining({
              disposition: 'withheld',
              reasons: ['claimed-feeling-or-consciousness', 'relational-dependency-language'],
            }),
          }),
        }),
      );
      expect(JSON.stringify(accessEntries)).not.toContain(outputContent);
      expect(JSON.stringify(accessEntries)).not.toContain(prohibitedOutput);
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'POST /w/{world_id}/services/{service}/execute',
          authenticated_actor: 'proc:authz',
          outcome: 'forbidden',
          http_status: 403,
        }),
      );
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'GET /w/{world_id}/registry-records/{record_id}',
          authenticated_actor: 'proc:orchestrator',
          outcome: 'forbidden',
          http_status: 403,
        }),
      );
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'GET /w/{world_id}/records/*',
          authenticated_actor: 'role:principal',
          outcome: 'served',
          http_status: 200,
        }),
      );
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'GET /w/{world_id}/extract',
          authenticated_actor: 'role:applicant',
          outcome: 'served',
          http_status: 200,
        }),
      );

      const { proposal_hash: ignoredProposalHash, ...proposalBody } = proposal;
      void ignoredProposalHash;
      const unknownProposal = freezeProposal({
        ...proposalBody,
        proposal_id: 'prp_process_unknown',
        action_id: 'act_process_unknown',
        created_at: new Date(now + 1).toISOString(),
        exact_parameters: { amount_minor_units: 0, reference: 'case-process-unknown' },
        cost_obligation: { amount_minor_units: 0, description: 'No synthetic cost.' },
      });
      const unknownSubmission = await postJson(
        authorizationOrigin,
        '/w/w-demo/proposals',
        tokens.orchestratorAtAuthz,
        { gate: 'commit', proposal: unknownProposal, service: 'filing', action_class: 'grant-filing' },
      );
      expect(unknownSubmission.status).toBe(200);
      const unknownRuling = (await unknownSubmission.json()) as { ruling?: { ruling_id?: string } };
      const unknownRulingId = unknownRuling.ruling?.ruling_id;
      if (unknownRulingId === undefined) throw new Error('unknown fixture did not receive a ruling id');

      const identityProbe = await requestJson(
        servicesOrigin,
        'GET',
        `/w/w-demo/effects/${'b'.repeat(64)}`,
        tokens.authzAtServices,
      );
      expect(identityProbe.status).toBe(200);
      const servicesIdentity = (await identityProbe.json()) as { boot_id?: string; ledger_id?: string };
      if (servicesIdentity.boot_id === undefined || servicesIdentity.ledger_id === undefined) {
        throw new Error('services identity probe was incomplete');
      }
      const unknownIntent = effectIntent.parse({
        world_id: unknownProposal.world_id,
        ruling_id: unknownRulingId,
        frozen_proposal_hash: unknownProposal.proposal_hash,
        service: 'filing',
        action_class: 'grant-filing',
        target: unknownProposal.target,
        exact_parameters: unknownProposal.exact_parameters,
        data_to_be_disclosed: unknownProposal.data_to_be_disclosed,
      });
      const unknownCommitmentResponse = await postJson(
        authorizationOrigin,
        '/w/w-demo/commit-verify',
        tokens.servicesAtAuthz,
        {
          ruling_id: unknownRulingId,
          intent: unknownIntent,
          services_host_boot_id: servicesIdentity.boot_id,
          services_ledger_id: servicesIdentity.ledger_id,
        },
      );
      expect(unknownCommitmentResponse.status).toBe(200);
      const unknownCommitment = (await unknownCommitmentResponse.json()) as {
        ok?: boolean;
        token?: { effect_id?: string };
      };
      expect(unknownCommitment.ok).toBe(true);
      if (unknownCommitment.token?.effect_id === undefined) {
        throw new Error('unknown fixture did not bind a commitment');
      }

      await crashProcess(authz);
      rmSync(join(recordsRoot, 'w-demo', '.writer.lock'), { force: true });
      authz = await startProcess(
        join(ROOT, 'packages', 'gate-core', 'dist', 'authorizationProcess.js'),
        'authorization',
        authorizationEnvironment,
      );
      runtimeProcesses.push(authz);
      const sameBootProbe = await requestJson(
        servicesOrigin,
        'GET',
        `/w/w-demo/effects/${'c'.repeat(64)}`,
        tokens.authzAtServices,
      );
      expect(sameBootProbe.status).toBe(200);
      await expect(sameBootProbe.json()).resolves.toMatchObject({
        state: 'absent',
        boot_id: servicesIdentity.boot_id,
        ledger_id: servicesIdentity.ledger_id,
      });
      const unknownActionFile = join(recordsRoot, 'w-demo', 'action.jsonl');
      expect(verifyChain(unknownActionFile, 'record-entry').ok).toBe(true);
      const unknownActionEntries = readFileSync(unknownActionFile, 'utf8')
        .trimEnd()
        .split('\n')
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(unknownActionEntries).toContainEqual(
        expect.objectContaining({
          authenticated_actor: 'proc:authz',
          commitment_and_effect: expect.objectContaining({
            event: 'effect_outcome',
            effect_id: unknownCommitment.token.effect_id,
            outcome: 'unknown-reconciliation-required',
            recovery_owner_role: 'principal',
          }),
          human_intervention_event: expect.objectContaining({
            payload: expect.objectContaining({
              kind: 'escalation_raised',
              contract: expect.objectContaining({
                decision_and_route: expect.objectContaining({ eligible_role: 'principal' }),
              }),
            }),
          }),
        }),
      );

      const principalEscalations = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/escalations',
        tokens.principal,
      );
      expect(principalEscalations.status).toBe(200);
      const principalEscalationsBody = (await principalEscalations.json()) as {
        escalations?: { escalation_id?: string; eligible_role?: string }[];
      };
      const recoveryEscalation = principalEscalationsBody.escalations?.find(
        (escalation) => escalation.eligible_role === 'principal',
      );
      if (recoveryEscalation?.escalation_id === undefined) {
        throw new Error('recovery fixture did not expose its routed escalation');
      }

      const officerEscalations = await requestJson(
        authorizationOrigin,
        'GET',
        '/w/w-demo/escalations',
        tokens.caseOfficer,
      );
      expect(officerEscalations.status).toBe(200);
      expect(await officerEscalations.json()).toEqual({ escalations: [] });
      const officerEscalationDetail = await requestJson(
        authorizationOrigin,
        'GET',
        `/w/w-demo/escalations/${recoveryEscalation.escalation_id}`,
        tokens.caseOfficer,
      );
      expect(officerEscalationDetail.status).toBe(404);

      const principalEscalationDetail = await requestJson(
        authorizationOrigin,
        'GET',
        `/w/w-demo/escalations/${recoveryEscalation.escalation_id}`,
        tokens.principal,
      );
      expect(principalEscalationDetail.status).toBe(200);
      await expect(principalEscalationDetail.json()).resolves.toMatchObject({
        escalation_id: recoveryEscalation.escalation_id,
        eligible_role: 'principal',
        contract: expect.objectContaining({
          decision_and_route: expect.objectContaining({ eligible_role: 'principal' }),
        }),
      });

      const orchestratorEscalationStatus = await requestJson(
        authorizationOrigin,
        'GET',
        `/w/w-demo/escalations/${recoveryEscalation.escalation_id}`,
        tokens.orchestratorAtAuthz,
      );
      expect(orchestratorEscalationStatus.status).toBe(200);
      const orchestratorEscalationBody = (await orchestratorEscalationStatus.json()) as unknown;
      expect(orchestratorEscalationBody).toMatchObject({
        escalation_id: recoveryEscalation.escalation_id,
        status: 'open',
      });
      expect(
        hasAnyKey(
          orchestratorEscalationBody,
          new Set(['contract', 'question_text', 'ruling', 'eligible_role', 'substitute_roles']),
        ),
      ).toBe(false);

      const crashProposal = freezeProposal({
        ...proposalBody,
        proposal_id: 'prp_process_crash',
        action_id: 'act_process_crash',
        created_at: new Date(now + 2).toISOString(),
        exact_parameters: { amount_minor_units: 5000, reference: 'case-process-crash' },
      });
      const crashSubmission = await postJson(
        authorizationOrigin,
        '/w/w-demo/proposals',
        tokens.orchestratorAtAuthz,
        { gate: 'commit', proposal: crashProposal, service: 'filing', action_class: 'grant-filing' },
      );
      expect(crashSubmission.status).toBe(200);
      const crashRuling = (await crashSubmission.json()) as {
        ruling?: { ruling_id?: string };
      };
      const crashRulingId = crashRuling.ruling?.ruling_id;
      if (crashRulingId === undefined) throw new Error('crash fixture did not receive a ruling id');

      const crashIntent = effectIntent.parse({
        world_id: crashProposal.world_id,
        ruling_id: crashRulingId,
        frozen_proposal_hash: crashProposal.proposal_hash,
        service: 'filing',
        action_class: 'grant-filing',
        target: crashProposal.target,
        exact_parameters: crashProposal.exact_parameters,
        data_to_be_disclosed: crashProposal.data_to_be_disclosed,
      });
      const commitmentResponse = await postJson(
        authorizationOrigin,
        '/w/w-demo/commit-verify',
        tokens.servicesAtAuthz,
        {
          ruling_id: crashRulingId,
          intent: crashIntent,
          services_host_boot_id: servicesIdentity.boot_id,
          services_ledger_id: servicesIdentity.ledger_id,
        },
      );
      expect(commitmentResponse.status).toBe(200);
      const commitment = (await commitmentResponse.json()) as {
        ok?: boolean;
        commitmentId?: string;
        token?: { effect_id?: string };
      };
      expect(commitment.ok).toBe(true);
      if (commitment.commitmentId === undefined || commitment.token?.effect_id === undefined) {
        throw new Error('crash fixture did not bind a commitment');
      }

      await crashProcess(authz);
      await crashProcess(services);
      // ChildProcess.kill is a hard termination on Windows, so the synthetic crash
      // deliberately leaves the writer lease. The process is confirmed exited above;
      // operator recovery may now clear only that temporary lease, never a record file.
      rmSync(join(recordsRoot, 'w-demo', '.writer.lock'), { force: true });
      services = await startProcess(
        join(ROOT, 'packages', 'services-mock', 'dist', 'servicesProcess.js'),
        'services',
        servicesEnvironment,
      );
      runtimeProcesses.push(services);
      authz = await startProcess(
        join(ROOT, 'packages', 'gate-core', 'dist', 'authorizationProcess.js'),
        'authorization',
        authorizationEnvironment,
      );
      runtimeProcesses.push(authz);

      const actionFile = join(recordsRoot, 'w-demo', 'action.jsonl');
      expect(verifyChain(actionFile, 'record-entry').ok).toBe(true);
      const actionEntries = readFileSync(actionFile, 'utf8')
        .trimEnd()
        .split('\n')
        .map((line) => JSON.parse(line) as Record<string, unknown>);
      expect(actionEntries).toContainEqual(
        expect.objectContaining({
          authenticated_actor: 'proc:authz',
          commitment_and_effect: expect.objectContaining({
            event: 'effect_outcome',
            effect_id: commitment.token.effect_id,
            outcome: 'no-effect',
          }),
        }),
      );

      for (const processHandle of runtimeProcesses) {
        for (const token of [...Object.values(tokens), caseAtOrchestrator, orchestratorAtServices]) {
          expect(processHandle.stdout()).not.toContain(token);
          expect(processHandle.stderr()).not.toContain(token);
        }
      }
    },
    30_000,
  );
});
