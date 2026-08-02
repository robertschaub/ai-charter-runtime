// SPDX-License-Identifier: MIT
/** Executing-services process bootstrap; the listener binds only after local recovery. */
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { loadKeyring, worldId } from 'gate-core';

import { ServicesAuthorizationHttpClient } from './authorizationHttpClient.js';
import { EffectLedger } from './effectLedger.js';
import { ServicesHttpServer, type ServicesListeningAddress } from './servicesHttpServer.js';
import { MockServicesHost } from './servicesHost.js';

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

function runtimeId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
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

async function requireHealthy(origin: string): Promise<void> {
  let response: Response;
  try {
    response = await fetch(new URL('/healthz', origin), {
      redirect: 'error',
      signal: AbortSignal.timeout(2_000),
    });
  } catch {
    throw new Error('authorization service is not reachable at startup');
  }
  if (!response.ok) throw new Error('authorization service is not ready at startup');
  try {
    const body = (await response.json()) as { status?: unknown; service?: unknown };
    if (body.status !== 'ready' || body.service !== 'authorization') throw new Error('wrong health identity');
  } catch {
    throw new Error('authorization service returned an invalid startup health response');
  }
}

export interface ServicesProcessHandle {
  readonly address: ServicesListeningAddress;
  close(): Promise<void>;
}

export async function startServicesProcess(env: NodeJS.ProcessEnv = process.env): Promise<ServicesProcessHandle> {
  const host = loopbackHost(env);
  const port = portFrom(env, 'SERVICES_PORT', 7803);
  const authzPort = portFrom(env, 'AUTHZ_PORT', 7801);
  const authorizationServiceToken = credential(env, 'AUTHZ_TOKEN_PROC_SERVICES_HOST');
  const orchestratorToken = credential(env, 'SERVICES_TOKEN_PROC_ORCHESTRATOR');
  const authorizationProbeToken = credential(env, 'SERVICES_TOKEN_PROC_AUTHZ');
  const credentialSet = [authorizationServiceToken, orchestratorToken, authorizationProbeToken];
  if (new Set(credentialSet.map((value) => value.toLowerCase())).size !== credentialSet.length) {
    throw new Error('services runtime credentials must be mutually distinct');
  }
  const authorizationOrigin = loopbackOrigin(
    env['AUTHZ_ORIGIN'] ?? `http://${host}:${authzPort}`,
    'AUTHZ_ORIGIN',
  );
  await requireHealthy(authorizationOrigin);
  const world = worldId.parse(env['DEMO_WORLD_ID'] ?? 'w-demo');
  const keyring = loadKeyring({ env });
  const ledger = new EffectLedger({
    recordsRoot: resolve(env['RUNTIME_RECORDS_ROOT'] ?? 'records'),
    worldId: world,
    bootId: runtimeId('services_boot'),
    keyring,
  });
  const authorization = new ServicesAuthorizationHttpClient({
    origin: authorizationOrigin,
    token: authorizationServiceToken,
  });
  const services = new MockServicesHost(ledger, authorization);
  const server = new ServicesHttpServer({
    services,
    ledger,
    worldId: world,
    orchestratorToken,
    authorizationToken: authorizationProbeToken,
    host,
    port,
  });
  const address = await server.listen();
  return { address, close: () => server.close() };
}

async function main(): Promise<void> {
  const handle = await startServicesProcess();
  process.stdout.write(`${JSON.stringify({ event: 'ready', service: 'services', ...handle.address })}\n`);
  const stop = async () => {
    await handle.close();
    process.exitCode = 0;
  };
  process.once('SIGINT', () => void stop());
  process.once('SIGTERM', () => void stop());
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'unknown startup error';
    process.stderr.write(`services startup failed: ${message}\n`);
    process.exitCode = 1;
  });
}
