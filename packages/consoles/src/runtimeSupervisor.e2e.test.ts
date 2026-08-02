// SPDX-License-Identifier: MIT
import { spawn, type ChildProcess } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const supervisors: ChildProcess[] = [];
const roots: string[] = [];

function hasExited(child: ChildProcess): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

async function waitForExit(child: ChildProcess, timeoutMs = 10_000): Promise<void> {
  if (hasExited(child)) return;
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error('runtime supervisor did not exit')), timeoutMs);
    child.once('exit', () => {
      clearTimeout(timeout);
      resolve();
    });
  });
}

afterEach(async () => {
  for (const supervisor of supervisors.splice(0).reverse()) {
    if (!hasExited(supervisor)) supervisor.kill('SIGKILL');
    await waitForExit(supervisor).catch(() => undefined);
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

async function waitForPortRelease(port: number): Promise<void> {
  const deadline = Date.now() + 10_000;
  for (;;) {
    const released = await new Promise<boolean>((resolve) => {
      const server = createServer();
      server.once('error', () => resolve(false));
      server.listen(port, '127.0.0.1', () => server.close(() => resolve(true)));
    });
    if (released) return;
    if (Date.now() >= deadline) throw new Error(`runtime port ${port} remained occupied`);
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
}

async function waitForFileRemoval(path: string): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (existsSync(path)) {
    if (Date.now() >= deadline) throw new Error(`runtime file ${path} was not removed`);
    await new Promise<void>((resolve) => setTimeout(resolve, 50));
  }
}

function leaseOwnerIsAlive(path: string): boolean {
  const parsed = JSON.parse(readFileSync(path, 'utf8')) as { pid?: unknown };
  if (!Number.isSafeInteger(parsed.pid)) throw new Error('writer lease did not identify a process');
  try {
    process.kill(parsed.pid as number, 0);
    return true;
  } catch {
    return false;
  }
}

async function startSupervisor(
  env: NodeJS.ProcessEnv,
  waitUntilReady = true,
): Promise<{ child: ChildProcess; stderr: () => string }> {
  const child = spawn(process.execPath, [join(ROOT, 'packages', 'consoles', 'dist', 'runtimeSupervisor.js')], {
    cwd: ROOT,
    env,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    windowsHide: true,
  });
  supervisors.push(child);
  const stdout = child.stdout;
  const stderrStream = child.stderr;
  if (stdout === null || stderrStream === null) throw new Error('runtime supervisor stdio was not piped');
  stdout.setEncoding('utf8');
  stderrStream.setEncoding('utf8');
  let stderr = '';
  stderrStream.on('data', (chunk: string) => {
    stderr += chunk;
  });
  if (!waitUntilReady) return { child, stderr: () => stderr };
  await new Promise<void>((resolve, reject) => {
    let lineBuffer = '';
    const cleanup = () => {
      clearTimeout(timeout);
      stdout.off('data', inspect);
      child.off('exit', onExit);
    };
    const inspect = (chunk: string) => {
      lineBuffer += chunk;
      for (;;) {
        const newline = lineBuffer.indexOf('\n');
        if (newline < 0) return;
        const line = lineBuffer.slice(0, newline);
        lineBuffer = lineBuffer.slice(newline + 1);
        if (line.length === 0) continue;
        try {
          const event = JSON.parse(line) as { event?: string; services?: unknown };
          if (event.event === 'ready' && Array.isArray(event.services)) {
            cleanup();
            resolve();
            return;
          }
        } catch {}
      }
    };
    const onExit = (code: number | null) => {
      cleanup();
      reject(new Error(`runtime supervisor exited before ready with ${code}; stderr=${stderr}`));
    };
    const timeout = setTimeout(() => {
      cleanup();
      reject(new Error(`runtime supervisor was not ready; stderr=${stderr}`));
    }, 20_000);
    stdout.on('data', inspect);
    child.once('exit', onExit);
  });
  return { child, stderr: () => stderr };
}

function runtimeEnvironment(
  recordsRoot: string,
  ports: readonly [authz: number, orchestrator: number, services: number],
): NodeJS.ProcessEnv {
  return {
    ...systemEnvironment(),
    RUNTIME_HOST: '127.0.0.1',
    AUTHZ_PORT: String(ports[0]),
    ORCHESTRATOR_PORT: String(ports[1]),
    SERVICES_PORT: String(ports[2]),
    DEMO_WORLD_ID: 'w-demo',
    RUNTIME_RECORDS_ROOT: recordsRoot,
    GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
    AUTHZ_TOKEN_PRINCIPAL: '1'.repeat(64),
    AUTHZ_TOKEN_CASE_OFFICER: '2'.repeat(64),
    AUTHZ_TOKEN_APPLICANT: '3'.repeat(64),
    AUTHZ_TOKEN_PROC_ORCHESTRATOR: '4'.repeat(64),
    AUTHZ_TOKEN_PROC_SERVICES_HOST: '5'.repeat(64),
    SERVICES_TOKEN_PROC_AUTHZ: '6'.repeat(64),
    GATE_HMAC_KEY: 'a'.repeat(64),
    GATE_HMAC_KEY_ID: 'hmac-test',
  };
}

describe('runtime supervisor lifecycle', () => {
  it(
    'honors a shutdown request during the startup window without leaving a child',
    async () => {
      const recordsRoot = mkdtempSync(join(tmpdir(), 'runtime-supervisor-startup-stop-'));
      roots.push(recordsRoot);
      const ports = (await Promise.all([freePort(), freePort(), freePort()])) as [number, number, number];
      const supervisor = await startSupervisor(runtimeEnvironment(recordsRoot, ports), false);

      supervisor.child.send('runtime-shutdown');
      await waitForExit(supervisor.child, 20_000);

      await Promise.all(ports.map(waitForPortRelease));
      await waitForFileRemoval(join(recordsRoot, 'w-demo', '.writer.lock'));
      expect(supervisor.child.exitCode).toBe(0);
      expect(supervisor.stderr()).toBe('');
    },
    30_000,
  );

  it.each(['graceful', 'parent-disconnect', 'parent-death'] as const)(
    'leaves no live child listeners after %s shutdown',
    async (mode) => {
      const recordsRoot = mkdtempSync(join(tmpdir(), `runtime-supervisor-${mode}-`));
      roots.push(recordsRoot);
      const [authzPort, orchestratorPort, servicesPort] = await Promise.all([freePort(), freePort(), freePort()]);
      const env = runtimeEnvironment(recordsRoot, [authzPort, orchestratorPort, servicesPort]);
      const supervisor = await startSupervisor(env);
      const writerLease = join(recordsRoot, 'w-demo', '.writer.lock');
      expect(existsSync(writerLease)).toBe(true);

      if (mode === 'graceful') supervisor.child.send('runtime-shutdown');
      else if (mode === 'parent-disconnect') supervisor.child.disconnect();
      else supervisor.child.kill('SIGKILL');
      await waitForExit(supervisor.child);

      await Promise.all([authzPort, orchestratorPort, servicesPort].map(waitForPortRelease));
      if (mode === 'parent-death' && existsSync(writerLease)) {
        expect(leaseOwnerIsAlive(writerLease)).toBe(false);
        // A hard process-tree death is crash-visible on Windows. The harness has
        // confirmed the synthetic lease owner is gone, so it may clear only this lease.
        rmSync(writerLease, { force: true });
      } else {
        await waitForFileRemoval(writerLease);
      }
      expect(supervisor.stderr()).toBe('');
      if (mode !== 'parent-death') expect(supervisor.child.exitCode).toBe(0);
    },
    30_000,
  );
});
