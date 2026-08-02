// SPDX-License-Identifier: AGPL-3.0-only
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, rmSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const children: ChildProcess[] = [];
const roots: string[] = [];
const servers: Server[] = [];

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

describe('authorization process maintenance lifecycle', () => {
  it(
    'fails stop on periodic maintenance failure without leaking credentials or its writer lease',
    async () => {
      const recordsRoot = mkdtempSync(join(tmpdir(), 'authorization-maintenance-failure-'));
      roots.push(recordsRoot);
      const servicesPort = await startHealthyServices();
      const authorizationPort = await freePort();
      const credentials = {
        AUTHZ_TOKEN_PRINCIPAL: '1'.repeat(64),
        AUTHZ_TOKEN_CASE_OFFICER: '2'.repeat(64),
        AUTHZ_TOKEN_APPLICANT: '3'.repeat(64),
        AUTHZ_TOKEN_PROC_ORCHESTRATOR: '4'.repeat(64),
        AUTHZ_TOKEN_PROC_SERVICES_HOST: '5'.repeat(64),
        SERVICES_TOKEN_PROC_AUTHZ: '6'.repeat(64),
        GATE_HMAC_KEY: 'a'.repeat(64),
      } as const;
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
          ...credentials,
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
      for (const credential of Object.values(credentials)) {
        expect(stdout).not.toContain(credential);
        expect(stderr).not.toContain(credential);
      }
      await waitForPortRelease(authorizationPort);
      expect(existsSync(join(recordsRoot, 'w-demo', '.writer.lock'))).toBe(false);
    },
    30_000,
  );
});
