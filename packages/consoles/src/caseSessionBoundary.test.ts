// SPDX-License-Identifier: MIT
import { spawn, type ChildProcess } from 'node:child_process';
import { createServer } from 'node:net';
import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { deriveAudienceToken, verifyChain } from 'gate-core';
import { afterEach, describe, expect, it } from 'vitest';

import { parseBrowserSelectionPreparation } from './caseHandoffConsole.js';

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

function occurrences(text: string, needle: string): number {
  return text.split(needle).length - 1;
}

describe('ADR-002 and ADR-010 real-listener browser boundary', () => {
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
      const grant = await postJson(
        authorizationOrigin,
        '/w/w-demo/mandates',
        mandate,
        { token: tokens.principal, requestOrigin: authorizationOrigin },
      );
      expect(grant.status).toBe(201);

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

      const secondMint = await postJson(
        authorizationOrigin,
        '/w/w-demo/case-session-handoffs',
        { case_id: 'case_demo' },
        { token: tokens.caseOfficer, requestOrigin: authorizationOrigin },
      );
      expect(secondMint.status).toBe(201);
      const secondMinted = (await secondMint.json()) as typeof minted;
      const { expires_at: ignoredSecondExpiry, ...secondHandoff } = secondMinted;
      void ignoredSecondExpiry;
      const secondRedeem = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        secondHandoff,
        { requestOrigin: orchestratorOrigin },
      );
      expect(secondRedeem.status).toBe(201);
      const secondSession = (await secondRedeem.json()) as { session_token: string; session_id: string };
      const walBeforeBrowserSelection = readFileSync(join(recordsRoot, 'w-demo', 'wal.jsonl'), 'utf8');

      const modelTarget = mandate['default_acting_model'] as {
        card_id: string;
        card_version: number;
        requested_id: string;
      };
      const alternateApproval = (mandate['approved_models'] as Array<Record<string, unknown>>)[1];
      if (alternateApproval === undefined) throw new Error('demo mandate needs a second approved model');
      const alternateTarget = {
        card_id: String(alternateApproval['card_id']),
        card_version: Number(alternateApproval['card_version']),
        requested_id: String(alternateApproval['requested_id']),
      };
      const modelsRead = await fetch(`${orchestratorOrigin}/w/w-demo/models`, {
        headers: { authorization: `Bearer ${created.session_token}`, origin: orchestratorOrigin },
        signal: AbortSignal.timeout(5_000),
      });
      expect(modelsRead.status).toBe(200);
      const modelsBody = (await modelsRead.json()) as unknown;
      expect(modelsBody).toMatchObject({ default_acting_model: modelTarget });
      for (const hidden of ['card_digest', 'current_card_digest', 'verifying_key_id']) {
        expect(JSON.stringify(modelsBody)).not.toContain(hidden);
      }
      const currentSelectionPath = '/w/w-demo/cases/case_demo/model-selection';
      for (const invalidToken of [
        undefined,
        caseAtOrchestrator,
        tokens.caseOfficer,
        tokens.orchestratorAtAuthz,
        minted.handoff_code,
      ]) {
        const refused = await fetch(`${orchestratorOrigin}${currentSelectionPath}`, {
          headers: {
            ...(invalidToken === undefined ? {} : { authorization: `Bearer ${invalidToken}` }),
            origin: orchestratorOrigin,
          },
          signal: AbortSignal.timeout(5_000),
        });
        expect(refused.status).toBe(401);
      }
      expect(
        (
          await fetch(`${orchestratorOrigin}${currentSelectionPath}`, {
            headers: { authorization: `Bearer ${created.session_token}`, origin: 'null' },
            signal: AbortSignal.timeout(5_000),
          })
        ).status,
      ).toBe(403);
      const currentBefore = await fetch(`${orchestratorOrigin}/w/w-demo/cases/case_demo/model-selection`, {
        headers: { authorization: `Bearer ${created.session_token}`, origin: orchestratorOrigin },
        signal: AbortSignal.timeout(5_000),
      });
      expect(currentBefore.status).toBe(200);
      await expect(currentBefore.json()).resolves.toMatchObject({ state: 'unselected', selection: null });

      const preparationPath = '/w/w-demo/cases/case_demo/model-selection-preparations';
      expect(
        (
          await postJson(
            orchestratorOrigin,
            preparationPath,
            { target: modelTarget },
            { token: created.session_token },
          )
        ).status,
      ).toBe(403);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            preparationPath,
            { target: modelTarget },
            { token: created.session_token, requestOrigin: 'null' },
          )
        ).status,
      ).toBe(403);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            preparationPath,
            { target: modelTarget },
            { token: caseAtOrchestrator, requestOrigin: orchestratorOrigin },
          )
        ).status,
      ).toBe(401);
      for (const invalidToken of [tokens.caseOfficer, tokens.orchestratorAtAuthz, minted.handoff_code]) {
        expect(
          (
            await postJson(
              orchestratorOrigin,
              preparationPath,
              { target: modelTarget },
              { token: invalidToken, requestOrigin: orchestratorOrigin },
            )
          ).status,
        ).toBe(401);
      }
      expect(
        (
          await postJson(
            orchestratorOrigin,
            preparationPath,
            { target: modelTarget, expected_current_selection_id: null },
            { token: created.session_token, requestOrigin: orchestratorOrigin },
          )
        ).status,
      ).toBe(422);

      const [firstPreparationResponse, secondPreparationResponse] = await Promise.all([
        postJson(
          orchestratorOrigin,
          preparationPath,
          { target: modelTarget },
          { token: created.session_token, requestOrigin: orchestratorOrigin },
        ),
        postJson(
          orchestratorOrigin,
          preparationPath,
          { target: modelTarget },
          { token: secondSession.session_token, requestOrigin: orchestratorOrigin },
        ),
      ]);
      expect(firstPreparationResponse.status).toBe(201);
      expect(secondPreparationResponse.status).toBe(201);
      const firstPreparation = (await firstPreparationResponse.json()) as {
        preparation: { preparation_id: string };
      };
      const secondPreparation = (await secondPreparationResponse.json()) as {
        preparation: { preparation_id: string };
      };
      expect(parseBrowserSelectionPreparation(firstPreparation)).not.toBeNull();
      expect(parseBrowserSelectionPreparation(secondPreparation)).not.toBeNull();
      expect(firstPreparation.preparation.preparation_id).not.toBe(secondPreparation.preparation.preparation_id);
      for (const browserBody of [firstPreparation, secondPreparation]) {
        expect(JSON.stringify(browserBody)).not.toMatch(
          /check_id|card_digest|current_card_digest|verifying_key_id|system_use_decision|policy_version/,
        );
      }

      const selectionPath = '/w/w-demo/cases/case_demo/model-selections';
      expect(
        (
          await postJson(
            orchestratorOrigin,
            selectionPath,
            { preparation_id: firstPreparation.preparation.preparation_id },
            { token: created.session_token },
          )
        ).status,
      ).toBe(403);
      for (const invalidToken of [caseAtOrchestrator, tokens.caseOfficer, tokens.orchestratorAtAuthz, minted.handoff_code]) {
        expect(
          (
            await postJson(
              orchestratorOrigin,
              selectionPath,
              { preparation_id: firstPreparation.preparation.preparation_id },
              { token: invalidToken, requestOrigin: orchestratorOrigin },
            )
          ).status,
        ).toBe(401);
      }
      const initialRace = await Promise.all([
        postJson(
          orchestratorOrigin,
          selectionPath,
          { preparation_id: firstPreparation.preparation.preparation_id },
          { token: created.session_token, requestOrigin: orchestratorOrigin },
        ),
        postJson(
          orchestratorOrigin,
          selectionPath,
          { preparation_id: secondPreparation.preparation.preparation_id },
          { token: secondSession.session_token, requestOrigin: orchestratorOrigin },
        ),
      ]);
      expect(initialRace.map((response) => response.status).sort()).toEqual([200, 409]);
      const initialSelectionBody = await initialRace.find((response) => response.status === 200)?.json();
      expect(initialSelectionBody).toMatchObject({
        selection: { kind: 'initial', predecessor_selection_id: null, target: modelTarget, authority_effect: 'none' },
      });
      expect(JSON.stringify(initialSelectionBody)).not.toMatch(/check_id|card_digest|system_use_decision/);
      for (const [preparation, session] of [
        [firstPreparation, created],
        [secondPreparation, secondSession],
      ] as const) {
        expect(
          (
            await postJson(
              orchestratorOrigin,
              selectionPath,
              { preparation_id: preparation.preparation.preparation_id },
              { token: session.session_token, requestOrigin: orchestratorOrigin },
            )
          ).status,
        ).toBe(409);
      }

      const noOp = await postJson(
        orchestratorOrigin,
        preparationPath,
        { target: modelTarget },
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(noOp.status).toBe(201);
      const noOpPreparation = (await noOp.json()) as { preparation: { preparation_id: string } };
      const refusedNoOp = await postJson(
        orchestratorOrigin,
        selectionPath,
        { preparation_id: noOpPreparation.preparation.preparation_id },
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(refusedNoOp.status).toBe(409);
      const switchPreparationResponse = await postJson(
        orchestratorOrigin,
        preparationPath,
        { target: alternateTarget },
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(switchPreparationResponse.status).toBe(201);
      const switchPreparation = (await switchPreparationResponse.json()) as {
        preparation: { preparation_id: string };
      };
      const switched = await postJson(
        orchestratorOrigin,
        selectionPath,
        { preparation_id: switchPreparation.preparation.preparation_id },
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(switched.status).toBe(200);
      const switchedBody = (await switched.json()) as { selection: { selection_id: string } };
      expect(switchedBody).toMatchObject({ selection: { kind: 'switch', target: alternateTarget } });
      const returnPreparationResponse = await postJson(
        orchestratorOrigin,
        preparationPath,
        { target: modelTarget },
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(returnPreparationResponse.status).toBe(201);
      const returnPreparation = (await returnPreparationResponse.json()) as {
        preparation: { preparation_id: string };
      };
      const returned = await postJson(
        orchestratorOrigin,
        selectionPath,
        { preparation_id: returnPreparation.preparation.preparation_id },
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(returned.status).toBe(200);
      const returnedBody = (await returned.json()) as { selection: { selection_id: string } };
      expect(returnedBody).toMatchObject({ selection: { kind: 'switch', target: modelTarget } });
      expect(new Set([
        (initialSelectionBody as { selection: { selection_id: string } }).selection.selection_id,
        switchedBody.selection.selection_id,
        returnedBody.selection.selection_id,
      ]).size).toBe(3);
      const messages = await postJson(
        orchestratorOrigin,
        '/w/w-demo/cases/case_demo/messages',
        { message: 'Synthetic message.' },
        { token: created.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(messages.status).toBe(501);
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
          await fetch(`${orchestratorOrigin}${currentSelectionPath}`, {
            headers: { authorization: `Bearer ${created.session_token}`, origin: orchestratorOrigin },
            signal: AbortSignal.timeout(5_000),
          })
        ).status,
      ).toBe(401);
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
      const restartPreparationResponse = await postJson(
        orchestratorOrigin,
        preparationPath,
        { target: alternateTarget },
        { token: restartSession.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(restartPreparationResponse.status).toBe(201);
      const restartPreparation = (await restartPreparationResponse.json()) as {
        preparation: { preparation_id: string };
      };
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
      expect(
        (
          await postJson(
            orchestratorOrigin,
            selectionPath,
            { preparation_id: restartPreparation.preparation.preparation_id },
            { token: restartSession.session_token, requestOrigin: orchestratorOrigin },
          )
        ).status,
      ).toBe(401);

      const authPrepMint = await postJson(
        authorizationOrigin,
        '/w/w-demo/case-session-handoffs',
        { case_id: 'case_demo' },
        { token: tokens.caseOfficer, requestOrigin: authorizationOrigin },
      );
      expect(authPrepMint.status).toBe(201);
      const authPrepMinted = (await authPrepMint.json()) as typeof minted;
      const { expires_at: ignoredAuthPrepExpiry, ...authPrepHandoff } = authPrepMinted;
      void ignoredAuthPrepExpiry;
      const authPrepRedeem = await postJson(
        orchestratorOrigin,
        '/w/w-demo/case-sessions/redeem',
        authPrepHandoff,
        { requestOrigin: orchestratorOrigin },
      );
      expect(authPrepRedeem.status).toBe(201);
      const authPrepSession = (await authPrepRedeem.json()) as { session_token: string; session_id: string };
      const authRestartPreparationResponse = await postJson(
        orchestratorOrigin,
        preparationPath,
        { target: alternateTarget },
        { token: authPrepSession.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(authRestartPreparationResponse.status).toBe(201);
      const authRestartPreparation = (await authRestartPreparationResponse.json()) as {
        preparation: { preparation_id: string };
      };

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
      const oldBootUse = await postJson(
        orchestratorOrigin,
        selectionPath,
        { preparation_id: authRestartPreparation.preparation.preparation_id },
        { token: authPrepSession.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(oldBootUse.status).toBe(409);
      expect(
        (
          await postJson(
            orchestratorOrigin,
            selectionPath,
            { preparation_id: authRestartPreparation.preparation.preparation_id },
            { token: authPrepSession.session_token, requestOrigin: orchestratorOrigin },
          )
        ).status,
      ).toBe(409);
      const oldBootPrepare = await postJson(
        orchestratorOrigin,
        preparationPath,
        { target: alternateTarget },
        { token: authPrepSession.session_token, requestOrigin: orchestratorOrigin },
      );
      expect(oldBootPrepare.status).toBe(401);
      await expect(oldBootPrepare.json()).resolves.toEqual({ error: 'session-restart-required' });
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
        for (const secret of [
          minted.handoff_code,
          secondMinted.handoff_code,
          restartMinted.handoff_code,
          authPrepMinted.handoff_code,
          bootMinted.handoff_code,
          created.session_token,
          secondSession.session_token,
          restartSession.session_token,
          authPrepSession.session_token,
        ]) {
          expect(content).not.toContain(secret);
        }
      }
      expect(verifyChain(join(worldDir, 'wal.jsonl'), 'wal-entry').ok).toBe(true);
      expect(verifyChain(join(worldDir, 'access.jsonl'), 'access-entry').ok).toBe(true);
      const access = readFileSync(join(worldDir, 'access.jsonl'), 'utf8');
      expect(access).toContain('case-session-handoffs');
      expect(access).toContain('model-selection-checks');
      expect(access).toContain('model-selections');
      expect(access).toContain(created.session_id);
      expect(access).toContain(secondSession.session_id);
      expect(access).toContain(authPrepSession.session_id);
      expect(access).toContain('proc:orchestrator');
      expect(access).toContain('case_officer');
      const wal = readFileSync(join(worldDir, 'wal.jsonl'), 'utf8');
      expect(wal).toContain('case_session_handoff.expire');
      expect(wal).toContain(bootHandoff.handoff_id);
      for (const operation of ['model_call.begin', 'conversation_items_put', 'output_release']) {
        expect(occurrences(wal, operation)).toBe(occurrences(walBeforeBrowserSelection, operation));
      }

      for (const processHandle of processHandles) {
        for (const secret of [
          minted.handoff_code,
          secondMinted.handoff_code,
          restartMinted.handoff_code,
          authPrepMinted.handoff_code,
          bootMinted.handoff_code,
          created.session_token,
          secondSession.session_token,
          restartSession.session_token,
          authPrepSession.session_token,
        ]) {
          expect(processHandle.stdout()).not.toContain(secret);
          expect(processHandle.stderr()).not.toContain(secret);
        }
      }
    },
    60_000,
  );
});
