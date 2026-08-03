// SPDX-License-Identifier: MIT
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveAudienceToken, verifyChain } from 'gate-core';
import { afterEach, describe, expect, it } from 'vitest';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const children: ChildProcess[] = [];
const roots: string[] = [];

afterEach(async () => {
  for (const child of children.splice(0).reverse()) await stop(child);
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
      server.close((error) => (error === undefined ? resolve(address.port) : reject(error)));
    });
  });
}

interface RunningProcess {
  readonly child: ChildProcess;
  readonly stdout: () => string;
  readonly stderr: () => string;
}

async function start(
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
  children.push(child);
  const childStdout = child.stdout;
  const childStderr = child.stderr;
  if (childStdout === null || childStderr === null) throw new Error('child stdio was not piped');
  childStdout.setEncoding('utf8');
  childStderr.setEncoding('utf8');
  let stdout = '';
  let stderr = '';
  childStdout.on('data', (chunk: string) => (stdout += chunk));
  childStderr.on('data', (chunk: string) => (stderr += chunk));
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error(`${service} did not become ready; stderr=${stderr}`)), 10_000);
    let buffer = '';
    const inspect = (chunk: string) => {
      buffer += chunk;
      for (;;) {
        const newline = buffer.indexOf('\n');
        if (newline < 0) return;
        const line = buffer.slice(0, newline);
        buffer = buffer.slice(newline + 1);
        try {
          const event = JSON.parse(line) as { event?: unknown; service?: unknown };
          if (event.event === 'ready' && event.service === service) {
            clearTimeout(timeout);
            childStdout.off('data', inspect);
            resolve();
            return;
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

async function stop(child: ChildProcess): Promise<void> {
  if (child.exitCode !== null || child.signalCode !== null) return;
  await new Promise<void>((resolve) => {
    child.once('exit', () => resolve());
    const terminate = () => {
      if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    };
    try {
      if (child.connected) child.send('runtime-shutdown', (error) => error && terminate());
      else terminate();
    } catch {
      terminate();
    }
    setTimeout(terminate, 2_000).unref();
  });
}

async function postJson(
  origin: string,
  path: string,
  body: unknown,
  options: { readonly token?: string; readonly requestOrigin?: string } = {},
): Promise<Response> {
  return fetch(new URL(path, origin), {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(options.token === undefined ? {} : { authorization: `Bearer ${options.token}` }),
      ...(options.requestOrigin === undefined ? {} : { origin: options.requestOrigin }),
    },
    body: JSON.stringify(body),
    signal: AbortSignal.timeout(5_000),
  });
}

describe('ADR-002 real-listener case-session boundary', () => {
  it(
    'mints, transfers, redeems, closes, expires on restart, and confines every credential class',
    async () => {
      const recordsRoot = mkdtempSync(join(tmpdir(), 'case-session-boundary-'));
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
      const orchestratorAtServices = deriveAudienceToken(tokens.orchestratorAtAuthz, 'services-proc-orchestrator');
      const common = {
        ...systemEnvironment(),
        RUNTIME_HOST: '127.0.0.1',
        AUTHZ_PORT: String(authzPort),
        ORCHESTRATOR_PORT: String(orchestratorPort),
        SERVICES_PORT: String(servicesPort),
        DEMO_WORLD_ID: 'w-demo',
        DEMO_CASE_ID: 'case_demo',
        RUNTIME_RECORDS_ROOT: recordsRoot,
      };
      const servicesEnv = {
        ...common,
        AUTHZ_TOKEN_PROC_SERVICES_HOST: tokens.servicesAtAuthz,
        SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
        SERVICES_TOKEN_PROC_AUTHZ: tokens.authzAtServices,
        GATE_HMAC_KEY: 'a'.repeat(64),
        GATE_HMAC_KEY_ID: 'hmac-test',
        GATE_KEYRING_PATH: join(recordsRoot, 'absent-keyring.json'),
      };
      const authzEnv = {
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
      const orchestratorEnv = {
        ...common,
        AUTHZ_TOKEN_PROC_ORCHESTRATOR: tokens.orchestratorAtAuthz,
        SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
        ORCHESTRATOR_TOKEN_CASE_OFFICER: caseAtOrchestrator,
      };
      const services = await start(
        join(ROOT, 'packages', 'services-mock', 'dist', 'servicesProcess.js'),
        'services',
        servicesEnv,
      );
      const processHandles: RunningProcess[] = [services];
      let authz = await start(
        join(ROOT, 'packages', 'gate-core', 'dist', 'authorizationProcess.js'),
        'authorization',
        authzEnv,
      );
      processHandles.push(authz);
      let orchestrator = await start(
        join(ROOT, 'packages', 'consoles', 'dist', 'orchestratorProcess.js'),
        'orchestrator',
        orchestratorEnv,
      );
      processHandles.push(orchestrator);
      const authorizationOrigin = `http://127.0.0.1:${authzPort}`;
      const orchestratorOrigin = `http://127.0.0.1:${orchestratorPort}`;

      const authzConfig = await fetch(`${authorizationOrigin}/console/runtime-config.json`);
      await expect(authzConfig.json()).resolves.toEqual({
        authorization_origin: authorizationOrigin,
        orchestrator_origin: orchestratorOrigin,
      });
      expect(authzConfig.headers.get('access-control-allow-origin')).toBeNull();
      const orchestratorConfig = await fetch(`${orchestratorOrigin}/console/runtime-config.json`);
      await expect(orchestratorConfig.json()).resolves.toEqual({
        authorization_origin: authorizationOrigin,
        orchestrator_origin: orchestratorOrigin,
      });
      const handoffShell = await fetch(`${orchestratorOrigin}/console/handoff`);
      expect(handoffShell.status).toBe(200);
      expect(handoffShell.headers.get('content-security-policy')).toContain("frame-ancestors 'none'");
      expect(handoffShell.headers.get('access-control-allow-origin')).toBeNull();
      expect(handoffShell.headers.get('set-cookie')).toBeNull();

      const wrongMintActor = await postJson(
        authorizationOrigin,
        '/w/w-demo/case-session-handoffs',
        { case_id: 'case_demo' },
        { token: tokens.orchestratorAtAuthz, requestOrigin: authorizationOrigin },
      );
      expect(wrongMintActor.status).toBe(403);
      const mint = await postJson(
        authorizationOrigin,
        '/w/w-demo/case-session-handoffs',
        { case_id: 'case_demo' },
        { token: tokens.caseOfficer, requestOrigin: authorizationOrigin },
      );
      expect(mint.status).toBe(201);
      expect(mint.headers.get('cache-control')).toBe('no-store');
      const minted = (await mint.json()) as {
        handoff_id: string;
        handoff_code: string;
        role: 'case_officer';
        world_id: string;
        case_id: string;
        target_origin: string;
        authorization_boot_id: string;
        expires_at: string;
      };
      const { expires_at: ignoredExpiry, ...handoff } = minted;
      void ignoredExpiry;

      const missingProcessAuth = await postJson(
        authorizationOrigin,
        `/w/w-demo/case-session-handoffs/${handoff.handoff_id}/redeem`,
        handoff,
      );
      expect(missingProcessAuth.status).toBe(401);
      const opaqueOrigin = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        handoff,
        { requestOrigin: 'null' },
      );
      expect(opaqueOrigin.status).toBe(403);
      await expect(opaqueOrigin.json()).resolves.toEqual({ error: 'handoff-refused' });
      const staticCredentialAtRedeem = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        handoff,
        { token: caseAtOrchestrator, requestOrigin: orchestratorOrigin },
      );
      expect(staticCredentialAtRedeem.status).toBe(403);

      const redeem = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        handoff,
        { requestOrigin: orchestratorOrigin },
      );
      expect(redeem.status).toBe(201);
      const created = (await redeem.json()) as { session_token: string; session_id: string };
      expect(created.session_token).toMatch(/^[0-9a-f]{64}$/);
      expect(
        (
          await postJson(
            authorizationOrigin,
            '/w/w-demo/mandates',
            {},
            { token: created.session_token, requestOrigin: authorizationOrigin },
          )
        ).status,
      ).toBe(401);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            '/w/w-demo/actions/execute',
            {},
            { token: minted.handoff_code },
          )
        ).status,
      ).toBe(401);
      const replay = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        handoff,
        { requestOrigin: orchestratorOrigin },
      );
      expect(replay.status).toBe(403);
      await expect(replay.json()).resolves.toEqual({ error: 'handoff-refused' });

      expect(
        (
          await postJson(
            orchestratorOrigin,
            '/w/w-demo/actions/execute',
            {},
            { token: created.session_token },
          )
        ).status,
      ).toBe(401);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            '/w/w-demo/case-sessions/close',
            {},
            { token: caseAtOrchestrator, requestOrigin: orchestratorOrigin },
          )
        ).status,
      ).toBe(401);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            '/w/w-demo/case-sessions/close',
            {},
            { token: created.session_token, requestOrigin: 'http://127.0.0.1:9999' },
          )
        ).status,
      ).toBe(403);
      const close = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/close',
        {},
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(close.status).toBe(200);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            '/w/w-demo/case-sessions/close',
            {},
            { token: created.session_token, requestOrigin: orchestratorOrigin },
          )
        ).status,
      ).toBe(401);

      const restartMint = await postJson(
        authorizationOrigin,
        '/w/w-demo/case-session-handoffs',
        { case_id: 'case_demo' },
        { token: tokens.caseOfficer, requestOrigin: authorizationOrigin },
      );
      const restartMinted = (await restartMint.json()) as typeof minted;
      const { expires_at: ignoredRestartExpiry, ...restartHandoff } = restartMinted;
      void ignoredRestartExpiry;
      const restartRedeem = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        restartHandoff,
        { requestOrigin: orchestratorOrigin },
      );
      const restartSession = (await restartRedeem.json()) as { session_token: string };
      await stop(orchestrator.child);
      orchestrator = await start(
        join(ROOT, 'packages', 'consoles', 'dist', 'orchestratorProcess.js'),
        'orchestrator',
        orchestratorEnv,
      );
      processHandles.push(orchestrator);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            '/w/w-demo/case-sessions/close',
            {},
            { token: restartSession.session_token, requestOrigin: orchestratorOrigin },
          )
        ).status,
      ).toBe(401);

      const bootMint = await postJson(
        authorizationOrigin,
        '/w/w-demo/case-session-handoffs',
        { case_id: 'case_demo' },
        { token: tokens.caseOfficer, requestOrigin: authorizationOrigin },
      );
      const bootMinted = (await bootMint.json()) as typeof minted;
      const { expires_at: ignoredBootExpiry, ...bootHandoff } = bootMinted;
      void ignoredBootExpiry;
      await stop(authz.child);
      authz = await start(
        join(ROOT, 'packages', 'gate-core', 'dist', 'authorizationProcess.js'),
        'authorization',
        authzEnv,
      );
      processHandles.push(authz);
      const afterAuthzRestart = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        bootHandoff,
        { requestOrigin: orchestratorOrigin },
      );
      expect(afterAuthzRestart.status).toBe(403);

      const worldDir = join(recordsRoot, 'w-demo');
      for (const name of ['wal.jsonl', 'action.jsonl', 'access.jsonl']) {
        const file = join(worldDir, name);
        if (!existsSync(file)) continue;
        const content = readFileSync(file, 'utf8');
        expect(content).not.toContain(minted.handoff_code);
        expect(content).not.toContain(restartMinted.handoff_code);
        expect(content).not.toContain(bootMinted.handoff_code);
        expect(content).not.toContain(created.session_token);
        expect(content).not.toContain(restartSession.session_token);
      }
      expect(verifyChain(join(worldDir, 'wal.jsonl'), 'wal-entry').ok).toBe(true);
      expect(verifyChain(join(worldDir, 'access.jsonl'), 'access-entry').ok).toBe(true);
      const access = readFileSync(join(worldDir, 'access.jsonl'), 'utf8');
      expect(access).toContain('case-session-handoffs');
      const wal = readFileSync(join(worldDir, 'wal.jsonl'), 'utf8');
      expect(wal).toContain('case_session_handoff.expire');
      expect(wal).toContain(bootHandoff.handoff_id);

      for (const processHandle of processHandles) {
        for (const secret of [
          minted.handoff_code,
          restartMinted.handoff_code,
          bootMinted.handoff_code,
          created.session_token,
          restartSession.session_token,
        ]) {
          expect(processHandle.stdout()).not.toContain(secret);
          expect(processHandle.stderr()).not.toContain(secret);
        }
      }
    },
    30_000,
  );
});
