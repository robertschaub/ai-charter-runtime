// SPDX-License-Identifier: AGPL-3.0-only
/** Authorization process: replay, sweep, and service reconciliation complete before listen. */
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { AuthorizationCore } from './authorizationCore.js';
import { AuthorizationHttpAdapter, type CredentialBinding } from './authorizationHttpAdapter.js';
import { AuthorizationHttpServer, type ListeningAddress } from './authorizationHttpServer.js';
import { CardRegistry } from './cardRegistry.js';
import { digestFileSet } from './fileSetDigest.js';
import { loadKeyring } from './keyring.js';
import { loadPolicyFile } from './policyLoader.js';
import { runRuntimeMaintenance } from './runtimeMaintenance.js';
import { worldId } from './schemas/index.js';
import { ServicesProbeHttpClient } from './servicesProbeHttpClient.js';
import { WalStore } from './walStore.js';

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

function intervalFrom(env: NodeJS.ProcessEnv): number {
  const raw = env['SWEEP_INTERVAL_MS'];
  if (raw === undefined || raw === '') return 5_000;
  const value = Number(raw);
  if (!Number.isSafeInteger(value) || value < 1) throw new Error('SWEEP_INTERVAL_MS must be positive');
  return value;
}

function runtimeId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
}

export interface AuthorizationProcessHandle {
  readonly address: ListeningAddress;
  readonly failure: Promise<Error>;
  close(): Promise<void>;
}

export async function startAuthorizationProcess(
  env: NodeJS.ProcessEnv = process.env,
): Promise<AuthorizationProcessHandle> {
  const host = loopbackHost(env);
  const port = portFrom(env, 'AUTHZ_PORT', 7801);
  const servicesPort = portFrom(env, 'SERVICES_PORT', 7803);
  const servicesOrigin = loopbackOrigin(
    env['SERVICES_ORIGIN'] ?? `http://${host}:${servicesPort}`,
    'SERVICES_ORIGIN',
  );
  const maintenanceIntervalMs = intervalFrom(env);
  const world = worldId.parse(env['DEMO_WORLD_ID'] ?? 'w-demo');
  const servicesProbeToken = credential(env, 'SERVICES_TOKEN_PROC_AUTHZ');
  const credentials: CredentialBinding[] = [
    { label: 'role:principal', token: credential(env, 'AUTHZ_TOKEN_PRINCIPAL'), worldId: world },
    { label: 'role:case_officer', token: credential(env, 'AUTHZ_TOKEN_CASE_OFFICER'), worldId: world },
    { label: 'role:applicant', token: credential(env, 'AUTHZ_TOKEN_APPLICANT'), worldId: world },
    { label: 'proc:orchestrator', token: credential(env, 'AUTHZ_TOKEN_PROC_ORCHESTRATOR'), worldId: world },
    { label: 'proc:services_host', token: credential(env, 'AUTHZ_TOKEN_PROC_SERVICES_HOST'), worldId: world },
  ];
  const allCredentials = [...credentials.map((binding) => binding.token), servicesProbeToken];
  if (new Set(allCredentials.map((value) => value.toLowerCase())).size !== allCredentials.length) {
    throw new Error('authorization runtime credentials must be mutually distinct');
  }
  const recordsRoot = resolve(env['RUNTIME_RECORDS_ROOT'] ?? 'records');
  const policyFile = resolve(env['RUNTIME_POLICY_FILE'] ?? 'packages/gate-core/policy/v1.yaml');
  const policyRoot = resolve(env['RUNTIME_POLICY_ROOT'] ?? 'packages/gate-core/policy');
  const sourceRoot = resolve(env['RUNTIME_GATE_SOURCE_ROOT'] ?? 'packages/gate-core/src');
  const cardsRoot = resolve(env['RUNTIME_CARDS_ROOT'] ?? 'docs/cards');
  const keyring = loadKeyring({ env });
  const loadedPolicy = loadPolicyFile(policyFile, digestFileSet(sourceRoot, 'evaluator-build'));
  const policy = { ...loadedPolicy, policyContentDigest: digestFileSet(policyRoot, 'policy-set') };
  const cards = CardRegistry.load(cardsRoot);
  const servicesProbe = new ServicesProbeHttpClient({
    origin: servicesOrigin,
    token: servicesProbeToken,
    worldId: world,
  });
  const bootId = runtimeId('authz_boot');
  const store = WalStore.open({
    recordsRoot,
    worldId: world,
    runId: runtimeId('run'),
    bootId,
    policyVersion: policy.policy.policy_version,
    policyContentDigest: policy.policyContentDigest,
    evaluatorBuildDigest: policy.evaluatorBuildDigest,
  });
  let server: AuthorizationHttpServer | undefined;
  let maintenanceTimer: NodeJS.Timeout | undefined;
  let maintenancePromise: Promise<void> | undefined;
  let closed = false;
  let resolveFailure: (error: Error) => void = () => undefined;
  const failure = new Promise<Error>((resolveFailurePromise) => {
    resolveFailure = resolveFailurePromise;
  });
  try {
    await servicesProbe.requireHealthy();
    const authorization = new AuthorizationCore({
      store,
      keyring,
      policy,
      resolveAuthorizedAgent: (actor) =>
        actor.credential === 'proc:orchestrator' ? (env['RUNTIME_AUTHORIZED_AGENT_ID'] ?? 'agent_demo') : undefined,
      resolveScreeningSignals: () => [],
      resolveModelEvidence: (proposal) => cards.resolve(proposal),
    });
    await authorization.activatePolicy();
    const maintain = async () => {
      await runRuntimeMaintenance({
        authorization,
        store,
        keyring,
        policy,
        probe: (idempotencyKey) => servicesProbe.probe(idempotencyKey),
      });
    };
    await maintain();
    const adapter = new AuthorizationHttpAdapter({
      authorization,
      ownOrigin: `http://${host}:${port}`,
      demoWorldId: world,
      credentials,
    });
    server = new AuthorizationHttpServer({ authorization, adapter, keyring, host, port });
    const address = await server.listen();
    const scheduleMaintenance = () => {
      if (maintenancePromise !== undefined || closed) return;
      maintenancePromise = maintain()
        .catch(async (error: unknown) => {
          if (closed) return;
          if (maintenanceTimer !== undefined) clearInterval(maintenanceTimer);
          maintenanceTimer = undefined;
          await server?.close().catch(() => undefined);
          resolveFailure(error instanceof Error ? error : new Error('unknown maintenance error'));
        })
        .finally(() => {
          maintenancePromise = undefined;
        });
    };
    maintenanceTimer = setInterval(scheduleMaintenance, maintenanceIntervalMs);
    maintenanceTimer.unref();
    return {
      address,
      failure,
      close: async () => {
        if (closed) return;
        closed = true;
        if (maintenanceTimer !== undefined) clearInterval(maintenanceTimer);
        maintenanceTimer = undefined;
        await maintenancePromise;
        await server?.close();
        store.close();
      },
    };
  } catch (error) {
    await server?.close().catch(() => undefined);
    store.close();
    throw error;
  }
}

async function main(): Promise<void> {
  const handle = await startAuthorizationProcess();
  process.stdout.write(`${JSON.stringify({ event: 'ready', service: 'authorization', ...handle.address })}\n`);
  void handle.failure.then(async (error) => {
    process.stderr.write(`authorization maintenance failed: ${error.message}\n`);
    await handle.close();
    if (process.connected) process.disconnect();
    process.exitCode = 1;
  });
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    await handle.close();
    if (process.connected) process.disconnect();
    process.exitCode ??= 0;
  };
  process.once('SIGINT', () => void stop());
  process.once('SIGTERM', () => void stop());
  process.on('message', (message: unknown) => {
    if (message === 'runtime-shutdown') void stop();
  });
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'unknown startup error';
    process.stderr.write(`authorization startup failed: ${message}\n`);
    process.exitCode = 1;
  });
}
