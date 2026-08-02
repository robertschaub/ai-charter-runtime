// SPDX-License-Identifier: MIT
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AUTHORIZATION_ROUTES,
  deriveAudienceToken,
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
        acting_model: {
          requested_id: 'swiss-ai/apertus-v1.5-70b',
          served_id: 'swiss-ai/apertus-v1.5-70b',
          card_id: 'publicai-apertus-v1.5-70b',
          card_version: 1,
        },
        mandate_ref: { mandate_id: 'mdt_demo_grant', version: 1 },
      });
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
      ).toHaveLength(deniedRoutes.length);
      expect(accessEntries).toContainEqual(
        expect.objectContaining({
          route: 'POST /w/{world_id}/services/{service}/execute',
          authenticated_actor: 'proc:authz',
          outcome: 'forbidden',
          http_status: 403,
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
