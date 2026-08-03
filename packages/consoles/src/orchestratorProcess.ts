// SPDX-License-Identifier: MIT
/** Model-side orchestrator process bootstrap. */
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { id, worldId } from 'gate-core';

import {
  OrchestratorHttpServer,
  loadCaseConsoleAssets,
  type OrchestratorListeningAddress,
} from './orchestratorHttpServer.js';
import {
  OrchestratorAuthorizationHttpClient,
  OrchestratorServicesHttpClient,
} from './runtimeHttpClients.js';

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.length === 0) throw new Error(`missing required runtime variable ${name}`);
  return value;
}

function credential(env: NodeJS.ProcessEnv, name: string): string {
  const value = required(env, name);
  if (!/^[0-9a-fA-F]{64,}$/.test(value)) throw new Error(`${name} is not a valid runtime credential`);
  return value;
}

function portFrom(env: NodeJS.ProcessEnv, name: string, fallback: number): number {
  const raw = env[name];
  if (raw === undefined || raw === '') return fallback;
  const port = Number(raw);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) throw new Error(`${name} must be a TCP port`);
  return port;
}

function loopbackHost(env: NodeJS.ProcessEnv): string {
  const host = env['RUNTIME_HOST'] ?? '127.0.0.1';
  if (host !== '127.0.0.1') throw new Error('RUNTIME_HOST must be 127.0.0.1 for the local POC');
  return host;
}

function loopbackOrigin(input: string, name: string): string {
  const parsed = new URL(input);
  if (
    parsed.protocol !== 'http:' ||
    parsed.hostname !== '127.0.0.1' ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.pathname !== '/' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new Error(`${name} must be an http://127.0.0.1 origin for the local POC`);
  }
  return parsed.origin;
}

async function requireHealthy(
  origin: string,
  name: string,
  expectedService: 'authorization' | 'services',
): Promise<void> {
  let response: Response;
  try {
    response = await fetch(new URL('/healthz', origin), {
      redirect: 'error',
      signal: AbortSignal.timeout(2_000),
    });
  } catch {
    throw new Error(`${name} is not reachable at startup`);
  }
  if (!response.ok) throw new Error(`${name} is not ready at startup`);
  try {
    const body = (await response.json()) as { status?: unknown; service?: unknown };
    if (body.status !== 'ready' || body.service !== expectedService) throw new Error('wrong health identity');
  } catch {
    throw new Error(`${name} returned an invalid startup health response`);
  }
}

export interface OrchestratorProcessHandle {
  readonly address: OrchestratorListeningAddress;
  close(): Promise<void>;
}

export async function startOrchestratorProcess(
  env: NodeJS.ProcessEnv = process.env,
): Promise<OrchestratorProcessHandle> {
  const host = loopbackHost(env);
  const port = portFrom(env, 'ORCHESTRATOR_PORT', 7802);
  const authzPort = portFrom(env, 'AUTHZ_PORT', 7801);
  const servicesPort = portFrom(env, 'SERVICES_PORT', 7803);
  const authorizationToken = credential(env, 'AUTHZ_TOKEN_PROC_ORCHESTRATOR');
  const servicesToken = credential(env, 'SERVICES_TOKEN_PROC_ORCHESTRATOR');
  const caseOfficerToken = credential(env, 'ORCHESTRATOR_TOKEN_CASE_OFFICER');
  const credentialSet = [authorizationToken, servicesToken, caseOfficerToken];
  if (new Set(credentialSet.map((value) => value.toLowerCase())).size !== credentialSet.length) {
    throw new Error('orchestrator runtime credentials must be mutually distinct');
  }
  const authorizationOrigin = loopbackOrigin(
    env['AUTHZ_ORIGIN'] ?? `http://${host}:${authzPort}`,
    'AUTHZ_ORIGIN',
  );
  const servicesOrigin = loopbackOrigin(
    env['SERVICES_ORIGIN'] ?? `http://${host}:${servicesPort}`,
    'SERVICES_ORIGIN',
  );
  const consolesRoot = fileURLToPath(new URL('../', import.meta.url));
  const caseConsoleAssetsRoot = resolve(
    env['RUNTIME_CASE_CONSOLE_ASSETS_ROOT'] ?? join(consolesRoot, 'assets', 'case-console'),
  );
  const caseConsoleAssets = loadCaseConsoleAssets({
    shell: join(caseConsoleAssetsRoot, 'handoff.html'),
    stylesheet: join(caseConsoleAssetsRoot, 'styles.css'),
    script: resolve(env['RUNTIME_CASE_CONSOLE_SCRIPT'] ?? join(consolesRoot, 'dist', 'caseHandoffConsole.js')),
  });
  await requireHealthy(authorizationOrigin, 'authorization service', 'authorization');
  await requireHealthy(servicesOrigin, 'services host', 'services');
  const server = new OrchestratorHttpServer({
    authorization: new OrchestratorAuthorizationHttpClient({
      origin: authorizationOrigin,
      token: authorizationToken,
    }),
    services: new OrchestratorServicesHttpClient({
      origin: servicesOrigin,
      token: servicesToken,
    }),
    worldId: worldId.parse(env['DEMO_WORLD_ID'] ?? 'w-demo'),
    demoCaseId: id.parse(env['DEMO_CASE_ID'] ?? 'case_demo'),
    demoMandateId: id.parse(env['DEMO_MANDATE_ID'] ?? 'mdt_demo_grant'),
    caseOfficerToken,
    authorizationOrigin,
    caseConsoleAssets,
    host,
    port,
  });
  const address = await server.listen();
  return { address, close: () => server.close() };
}

async function main(): Promise<void> {
  let handle: OrchestratorProcessHandle | undefined;
  let stopRequested = false;
  let closePromise: Promise<void> | undefined;
  const onMessage = (message: unknown) => {
    if (message === 'runtime-shutdown') requestStop();
  };
  const cleanup = () => {
    process.off('SIGINT', requestStop);
    process.off('SIGTERM', requestStop);
    process.off('disconnect', requestStop);
    process.off('message', onMessage);
  };
  const close = (): Promise<void> => {
    if (closePromise !== undefined) return closePromise;
    closePromise = (async () => {
      cleanup();
      await handle?.close();
      if (process.connected) process.disconnect();
      process.exitCode ??= 0;
    })();
    return closePromise;
  };
  function requestStop(): void {
    stopRequested = true;
    if (handle !== undefined) void close().catch(() => (process.exitCode = 1));
  }
  process.once('SIGINT', requestStop);
  process.once('SIGTERM', requestStop);
  process.once('disconnect', requestStop);
  process.on('message', onMessage);
  try {
    handle = await startOrchestratorProcess();
    if (stopRequested) {
      await close();
      return;
    }
    process.stdout.write(`${JSON.stringify({ event: 'ready', service: 'orchestrator', ...handle.address })}\n`);
  } catch (error) {
    cleanup();
    if (process.connected) process.disconnect();
    if (stopRequested) {
      process.exitCode ??= 0;
      return;
    }
    throw error;
  }
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'unknown startup error';
    process.stderr.write(`orchestrator startup failed: ${message}\n`);
    process.exitCode = 1;
  });
}
