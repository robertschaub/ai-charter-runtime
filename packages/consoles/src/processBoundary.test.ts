// SPDX-License-Identifier: MIT
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { createServer } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { Readable } from 'node:stream';

import {
  AUTHORIZATION_ROUTES,
  deriveAudienceToken,
  freezeProposal,
  verifyChain,
} from 'gate-core';
import { afterEach, describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
type RuntimeChild = ChildProcessByStdio<null, Readable, Readable>;

const childProcesses: RuntimeChild[] = [];
const roots: string[] = [];

afterEach(async () => {
  for (const child of childProcesses.splice(0).reverse()) {
    if (child.exitCode === null) child.kill('SIGTERM');
    await new Promise<void>((resolve) => {
      if (child.exitCode !== null) return resolve();
      child.once('exit', () => resolve());
      setTimeout(resolve, 2_000).unref();
    });
  }
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
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  childProcesses.push(child);
  let stdout = '';
  let stderr = '';
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  child.stdout.on('data', (chunk: string) => {
    stdout += chunk;
  });
  child.stderr.on('data', (chunk: string) => {
    stderr += chunk;
  });
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`${service} did not become ready; stderr=${stderr}`)), 10_000);
    const inspect = (chunk: string) => {
      for (const line of chunk.split('\n')) {
        if (line.length === 0) continue;
        try {
          const event = JSON.parse(line) as { event?: string; service?: string };
          if (event.event === 'ready' && event.service === service) {
            clearTimeout(timeout);
            child.stdout.off('data', inspect);
            resolve();
          }
        } catch {}
      }
    };
    child.stdout.on('data', inspect);
    child.once('exit', (code) => {
      clearTimeout(timeout);
      reject(new Error(`${service} exited before ready with ${code}; stderr=${stderr}`));
    });
  });
  return { child, stdout: () => stdout, stderr: () => stderr };
}

async function postJson(origin: string, path: string, token: string, body: unknown): Promise<Response> {
  return fetch(new URL(path, origin), {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
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
      const authz = await startProcess(
        join(ROOT, 'packages', 'gate-core', 'dist', 'authorizationProcess.js'),
        'authorization',
        {
          ...common,
          AUTHZ_TOKEN_PRINCIPAL: tokens.principal,
          AUTHZ_TOKEN_CASE_OFFICER: tokens.caseOfficer,
          AUTHZ_TOKEN_APPLICANT: tokens.applicant,
          AUTHZ_TOKEN_PROC_ORCHESTRATOR: tokens.orchestratorAtAuthz,
          AUTHZ_TOKEN_PROC_SERVICES_HOST: tokens.servicesAtAuthz,
          GATE_HMAC_KEY: 'a'.repeat(64),
          GATE_HMAC_KEY_ID: 'hmac-test',
          GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
        },
      );
      const services = await startProcess(
        join(ROOT, 'packages', 'services-mock', 'dist', 'servicesProcess.js'),
        'services',
        {
          ...common,
          AUTHZ_TOKEN_PROC_SERVICES_HOST: tokens.servicesAtAuthz,
          SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
          SERVICES_TOKEN_PROC_AUTHZ: tokens.authzAtServices,
          GATE_HMAC_KEY: 'a'.repeat(64),
          GATE_HMAC_KEY_ID: 'hmac-test',
          GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
        },
      );
      const orchestrator = await startProcess(
        join(ROOT, 'packages', 'consoles', 'dist', 'orchestratorProcess.js'),
        'orchestrator',
        {
          ...common,
          AUTHZ_TOKEN_PROC_ORCHESTRATOR: tokens.orchestratorAtAuthz,
          SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
          ORCHESTRATOR_TOKEN_CASE_OFFICER: caseAtOrchestrator,
        },
      );

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
      const action = await postJson(
        `http://127.0.0.1:${orchestratorPort}`,
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
          route.authorityChanging &&
          !(route.allowed as readonly string[]).includes('proc:orchestrator'),
      );
      for (const route of deniedRoutes) {
        const response = await postJson(
          authorizationOrigin,
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

      for (const processHandle of [authz, services, orchestrator]) {
        for (const token of [...Object.values(tokens), caseAtOrchestrator, orchestratorAtServices]) {
          expect(processHandle.stdout()).not.toContain(token);
          expect(processHandle.stderr()).not.toContain(token);
        }
      }
    },
    30_000,
  );
});
