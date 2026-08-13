// SPDX-License-Identifier: AGPL-3.0-only
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { freezeProposal } from './authorizationCore.js';
import { startAuthorizationProcess } from './authorizationProcess.js';
import { writeCheckpoint } from './checkpoint.js';
import { frozenProposal } from './schemas/index.js';
import { WalStore } from './walStore.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const children: ChildProcess[] = [];
const roots: string[] = [];
const servers: Server[] = [];
const CREDENTIALS = {
  AUTHZ_TOKEN_PRINCIPAL: '1'.repeat(64),
  AUTHZ_TOKEN_CASE_OFFICER: '2'.repeat(64),
  AUTHZ_TOKEN_APPLICANT: '3'.repeat(64),
  AUTHZ_TOKEN_PROC_ORCHESTRATOR: '4'.repeat(64),
  AUTHZ_TOKEN_PROC_SERVICES_HOST: '5'.repeat(64),
  SERVICES_TOKEN_PROC_AUTHZ: '6'.repeat(64),
  GATE_HMAC_KEY: 'a'.repeat(64),
} as const;

function hasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

async function waitForExit(child: ChildProcess, timeoutMs = 10_000): Promise<void> {
  if (hasExited(child)) return;
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('authorization process did not exit')), timeoutMs);
    child.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

async function closeServer(server: Server): Promise<void> {
  if (!server.listening) return;
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

afterEach(async () => {
  for (const child of children.splice(0).reverse()) {
    if (!hasExited(child)) child.kill('SIGKILL');
    await waitForExit(child).catch(() => undefined);
  }
  for (const server of servers.splice(0).reverse()) await closeServer(server).catch(() => undefined);
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function systemEnvironment(): NodeJS.ProcessEnv {
  const names = ['SystemRoot', 'TEMP', 'TMP', 'ComSpec', 'PATHEXT', 'Path', 'PATH'];
  return Object.fromEntries(names.flatMap((name) => (process.env[name] === undefined ? [] : [[name, process.env[name]]])));
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const server = createNetServer();
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') return reject(new Error('no TCP port allocated'));
      server.close((error) => (error === undefined ? resolve(address.port) : reject(error)));
    });
  });
}

async function waitForPortRelease(port: number): Promise<void> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const released = await new Promise<boolean>((resolve) => {
      const server = createNetServer();
      server.once('error', () => resolve(false));
      server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
    });
    if (released) return;
    if (Date.now() >= deadline) throw new Error(`authorization port ${port} remained occupied`);
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
}

async function startHealthyServices(): Promise<number> {
  const server = createServer((request, response) => {
    if (request.method !== 'GET' || request.url !== '/healthz') {
      response.writeHead(404).end();
      return;
    }
    const body = JSON.stringify({ status: 'ready', service: 'services' });
    response.writeHead(200, {
      'content-type': 'application/json',
      'content-length': Buffer.byteLength(body),
    });
    response.end(body);
  });
  servers.push(server);
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') return reject(new Error('services listener has no port'));
      resolve(address.port);
    });
  });
}

describe('authorization process fail-stop lifecycle', () => {
  it('fixes live screening at startup without reading or falling back to the fixture source', async () => {
    const recordsRoot = mkdtempSync(join(tmpdir(), 'authorization-live-screening-mode-'));
    roots.push(recordsRoot);
    const servicesPort = await startHealthyServices();
    const authorizationPort = await freePort();
    const handle = await startAuthorizationProcess({
      ...systemEnvironment(),
      ...CREDENTIALS,
      GATE_HMAC_KEY_ID: 'hmac-test',
      GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
      RUNTIME_HOST: '127.0.0.1',
      AUTHZ_PORT: String(authorizationPort),
      ORCHESTRATOR_PORT: String(await freePort()),
      SERVICES_PORT: String(servicesPort),
      DEMO_WORLD_ID: 'w-demo',
      RUNTIME_RECORDS_ROOT: recordsRoot,
      RUNTIME_CHECKPOINTS_ROOT: join(recordsRoot, 'checkpoints'),
      CHECKPOINT_VERIFY_LOCAL: '1',
      RUNTIME_SCREENING_MODE: 'live',
      RUNTIME_SCREENING_FIXTURE: join(recordsRoot, 'must-not-be-read.json'),
    });
    try {
      expect(handle.address.host).toBe('127.0.0.1');
      expect(existsSync(join(recordsRoot, 'must-not-be-read.json'))).toBe(false);
    } finally {
      await handle.close();
    }
  });

  it('binds native proposals to the selected lane and fails stale fixture hashes closed', async () => {
    const recordsRoot = mkdtempSync(join(tmpdir(), 'authorization-screening-fixture-'));
    roots.push(recordsRoot);
    const checkpointsRoot = join(recordsRoot, 'checkpoints');
    const servicesPort = await startHealthyServices();
    const authorizationPort = await freePort();
    const orchestratorPort = await freePort();
    const handle = await startAuthorizationProcess({
      ...systemEnvironment(),
      ...CREDENTIALS,
      GATE_HMAC_KEY_ID: 'hmac-test',
      GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
      RUNTIME_HOST: '127.0.0.1',
      AUTHZ_PORT: String(authorizationPort),
      ORCHESTRATOR_PORT: String(orchestratorPort),
      SERVICES_PORT: String(servicesPort),
      DEMO_WORLD_ID: 'w-demo',
      RUNTIME_RECORDS_ROOT: recordsRoot,
      RUNTIME_CHECKPOINTS_ROOT: checkpointsRoot,
      CHECKPOINT_VERIFY_LOCAL: '1',
    });
    const post = (path: string, token: string, value: unknown) =>
      fetch(new URL(path, handle.address.origin), {
        method: 'POST',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        body: JSON.stringify(value),
        signal: AbortSignal.timeout(5_000),
      });
    try {
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
      const grant = await post('/w/w-demo/mandates', CREDENTIALS.AUTHZ_TOKEN_PRINCIPAL, mandate);
      expect(grant.status).toBe(201);

      const selectionCheckResponse = await post(
        '/w/w-demo/cases/case_demo/model-selection-checks',
        CREDENTIALS.AUTHZ_TOKEN_PROC_ORCHESTRATOR,
        {
          expected_current_selection_id: null,
          target: mandate['default_acting_model'],
        },
      );
      expect(selectionCheckResponse.status).toBe(200);
      const selectionCheck = (await selectionCheckResponse.json()) as {
        check: { check_id: string };
      };
      const selectionResponse = await post(
        '/w/w-demo/cases/case_demo/model-selections',
        CREDENTIALS.AUTHZ_TOKEN_PROC_ORCHESTRATOR,
        {
          check_id: selectionCheck.check.check_id,
          expected_current_selection_id: null,
        },
      );
      expect(selectionResponse.status).toBe(200);
      const selected = (await selectionResponse.json()) as {
        selection: { selection_id: string };
      };

      const fixtureProposal = frozenProposal.parse(
        JSON.parse(readFileSync(join(ROOT, 'fixtures', 'demo', 'screening-proposal.json'), 'utf8')),
      );
      const { proposal_hash: ignoredFixtureHash, ...fixtureBody } = fixtureProposal;
      void ignoredFixtureHash;
      const proposal = freezeProposal({
        ...fixtureBody,
        selection_id: selected.selection.selection_id,
      });
      const exact = await post('/w/w-demo/proposals', CREDENTIALS.AUTHZ_TOKEN_PROC_ORCHESTRATOR, {
        gate: 'submit',
        proposal,
        service: 'filing',
        action_class: 'grant-filing',
      });
      expect(exact.status).toBe(200);
      await expect(exact.json()).resolves.toMatchObject({
        ruling: { verdict: 'escalate', reason: 'A required screening check is unavailable.' },
        escalation_id: expect.any(String),
      });

      const { proposal_hash: ignoredHash, ...proposalBody } = proposal;
      void ignoredHash;
      const changed = freezeProposal({
        ...proposalBody,
        proposal_id: 'prp_screening_unpinned',
        action_id: 'act_screening_unpinned',
      });
      const missing = await post('/w/w-demo/proposals', CREDENTIALS.AUTHZ_TOKEN_PROC_ORCHESTRATOR, {
        gate: 'submit',
        proposal: changed,
        service: 'filing',
        action_class: 'grant-filing',
      });
      expect(missing.status).toBe(200);
      await expect(missing.json()).resolves.toMatchObject({
        ruling: { verdict: 'escalate', reason: 'A required screening check is unavailable.' },
        escalation_id: expect.any(String),
      });

      const wal = readFileSync(join(recordsRoot, 'w-demo', 'wal.jsonl'), 'utf8');
      expect(wal).not.toContain('"kind":"submit_projection"');
      expect(wal).not.toContain('"kind":"screening_signal"');
      expect(wal).toContain('"kind":"screening_skipped"');
      expect(wal).toContain('"reason":"fixture-unavailable"');
    } finally {
      await handle.close();
    }
  });

  it(
    'fails stop on periodic maintenance failure without leaking credentials or its writer lease',
    async () => {
      const recordsRoot = mkdtempSync(join(tmpdir(), 'authorization-maintenance-failure-'));
      roots.push(recordsRoot);
      const servicesPort = await startHealthyServices();
      const authorizationPort = await freePort();
      const script = `
        import { runAuthorizationProcess } from './packages/gate-core/dist/authorizationProcess.js';
        import { runRuntimeMaintenance } from './packages/gate-core/dist/runtimeMaintenance.js';
        let maintenancePasses = 0;
        await runAuthorizationProcess(process.env, {
          runMaintenance: async (options) => {
            maintenancePasses += 1;
            if (maintenancePasses > 1) throw new Error('synthetic maintenance/store failure');
            return runRuntimeMaintenance(options);
          },
        });
      `;
      const child = spawn(process.execPath, ['--input-type=module', '--eval', script], {
        cwd: ROOT,
        env: {
          ...systemEnvironment(),
          ...CREDENTIALS,
          GATE_HMAC_KEY_ID: 'hmac-test',
          RUNTIME_HOST: '127.0.0.1',
          AUTHZ_PORT: String(authorizationPort),
          SERVICES_PORT: String(servicesPort),
          DEMO_WORLD_ID: 'w-demo',
          RUNTIME_RECORDS_ROOT: recordsRoot,
          GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
          SWEEP_INTERVAL_MS: '25',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      children.push(child);
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      child.stdout?.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
      child.stderr?.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

      await waitForExit(child, 20_000);
      const stdout = Buffer.concat(stdoutChunks).toString('utf8');
      const stderr = Buffer.concat(stderrChunks).toString('utf8');

      expect(child.exitCode).toBe(1);
      expect(child.signalCode).toBeNull();
      expect(JSON.parse(stdout.trim())).toMatchObject({ event: 'ready', service: 'authorization' });
      expect(stderr).toBe('authorization maintenance failed: synthetic maintenance/store failure\n');
      for (const credential of Object.values(CREDENTIALS)) {
        expect(stdout).not.toContain(credential);
        expect(stderr).not.toContain(credential);
      }
      await waitForPortRelease(authorizationPort);
      expect(existsSync(join(recordsRoot, 'w-demo', '.writer.lock'))).toBe(false);
    },
    30_000,
  );

  it(
    'halts before listening when run-start verification finds a valid-prefix rollback',
    async () => {
      const root = mkdtempSync(join(tmpdir(), 'authorization-checkpoint-rollback-'));
      roots.push(root);
      const recordsRoot = join(root, 'records');
      const checkpointsRoot = join(root, 'checkpoints');
      const store = WalStore.open({
        recordsRoot,
        worldId: 'w-demo',
        runId: 'run_before_rollback',
        bootId: 'authz_boot_before_rollback',
        policyVersion: 'policy-test',
        policyContentDigest: 'a'.repeat(64),
        evaluatorBuildDigest: 'b'.repeat(64),
        now: () => '2026-08-02T00:00:00.000Z',
      });
      store.close();
      await writeCheckpoint({
        recordsRoot,
        checkpointsRoot,
        reason: 'run-end',
        runId: 'run_before_rollback',
        policyContentDigest: 'a'.repeat(64),
        evaluatorBuildId: 'gate-core@test',
        now: () => '2026-08-02T00:01:00.000Z',
        mode: 'write-only',
      });
      const walFile = join(recordsRoot, 'w-demo', 'wal.jsonl');
      const genesis = readFileSync(walFile, 'utf8').split('\n')[0];
      writeFileSync(walFile, `${genesis}\n`, 'utf8');

      const servicesPort = await startHealthyServices();
      const authorizationPort = await freePort();
      const child = spawn(
        process.execPath,
        [join(ROOT, 'packages', 'gate-core', 'dist', 'authorizationProcess.js')],
        {
          cwd: ROOT,
          env: {
            ...systemEnvironment(),
            ...CREDENTIALS,
            GATE_HMAC_KEY_ID: 'hmac-test',
            RUNTIME_HOST: '127.0.0.1',
            AUTHZ_PORT: String(authorizationPort),
            SERVICES_PORT: String(servicesPort),
            DEMO_WORLD_ID: 'w-demo',
            RUNTIME_RECORDS_ROOT: recordsRoot,
            RUNTIME_CHECKPOINTS_ROOT: checkpointsRoot,
            CHECKPOINT_VERIFY_LOCAL: '1',
            GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
          },
          stdio: ['ignore', 'pipe', 'pipe'],
          windowsHide: true,
        },
      );
      children.push(child);
      const stdoutChunks: Buffer[] = [];
      const stderrChunks: Buffer[] = [];
      child.stdout?.on('data', (chunk: Buffer) => stdoutChunks.push(chunk));
      child.stderr?.on('data', (chunk: Buffer) => stderrChunks.push(chunk));

      await waitForExit(child, 20_000);
      const stdout = Buffer.concat(stdoutChunks).toString('utf8');
      const stderr = Buffer.concat(stderrChunks).toString('utf8');

      expect(child.exitCode).toBe(1);
      expect(stdout).toBe('');
      expect(stderr).toContain('authorization startup failed: rollback alarm for w-demo/wal');
      expect(stderr).toContain('local length 1 is below anchored length 2');
      for (const credential of Object.values(CREDENTIALS)) {
        expect(stdout).not.toContain(credential);
        expect(stderr).not.toContain(credential);
      }
      await waitForPortRelease(authorizationPort);
      expect(existsSync(join(recordsRoot, 'w-demo', '.writer.lock'))).toBe(false);
      expect(readFileSync(walFile, 'utf8').split('\n').filter((line) => line.length > 0)).toHaveLength(1);
    },
    30_000,
  );
});
