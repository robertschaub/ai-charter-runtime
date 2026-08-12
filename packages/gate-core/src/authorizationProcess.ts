// SPDX-License-Identifier: AGPL-3.0-only
/** Authorization process: replay, sweep, and service reconciliation complete before listen. */
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { z } from 'zod';

import { AuthorizationCore } from './authorizationCore.js';
import { AuthorizationHttpAdapter, type CredentialBinding } from './authorizationHttpAdapter.js';
import {
  AuthorizationHttpServer,
  loadGovernanceConsoleAssets,
  type ListeningAddress,
} from './authorizationHttpServer.js';
import { AuthorizationReadSide } from './authorizationReadSide.js';
import { CaseSessionHandoffService } from './caseSessionHandoff.js';
import { CardRegistry } from './cardRegistry.js';
import { ConversationProjectionService } from './conversationProjectionService.js';
import { ConversationTransportService } from './conversationTransport.js';
import { ProposalIntakeService } from './proposalIntake.js';
import { ProposalPrecommitService } from './proposalPrecommit.js';
import {
  recordVerificationAccess,
  verifyRecords,
  type RecordsVerificationReport,
} from './checkpoint.js';
import { digestFileSet } from './fileSetDigest.js';
import { loadKeyring } from './keyring.js';
import { loadPolicyFile } from './policyLoader.js';
import { runRuntimeMaintenance } from './runtimeMaintenance.js';
import { screeningFixtureSet } from './screeningFixture.js';
import { id, storeItem, systemUseDecisionRecord, worldId } from './schemas/index.js';
import { ServicesProbeHttpClient } from './servicesProbeHttpClient.js';
import { SystemUseDecisionService } from './systemUseDecision.js';
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

function localCheckpointVerification(env: NodeJS.ProcessEnv): boolean {
  const raw = env['CHECKPOINT_VERIFY_LOCAL'];
  if (raw === undefined || raw === '' || raw === '0') return false;
  if (raw === '1') return true;
  throw new Error('CHECKPOINT_VERIFY_LOCAL must be 0 or 1');
}

function runtimeId(prefix: string): string {
  return `${prefix}_${randomUUID().replaceAll('-', '')}`;
}

export interface AuthorizationProcessHandle {
  readonly address: ListeningAddress;
  readonly failure: Promise<Error>;
  readonly recordVerification: RecordsVerificationReport;
  close(): Promise<void>;
}

export interface AuthorizationProcessDependencies {
  readonly runMaintenance?: typeof runRuntimeMaintenance;
  readonly verifyRecordLayer?: typeof verifyRecords;
}

export async function startAuthorizationProcess(
  env: NodeJS.ProcessEnv = process.env,
  dependencies: AuthorizationProcessDependencies = {},
): Promise<AuthorizationProcessHandle> {
  const host = loopbackHost(env);
  const port = portFrom(env, 'AUTHZ_PORT', 7801);
  const orchestratorPort = portFrom(env, 'ORCHESTRATOR_PORT', 7802);
  const servicesPort = portFrom(env, 'SERVICES_PORT', 7803);
  const servicesOrigin = loopbackOrigin(
    env['SERVICES_ORIGIN'] ?? `http://${host}:${servicesPort}`,
    'SERVICES_ORIGIN',
  );
  const orchestratorOrigin = loopbackOrigin(
    env['ORCHESTRATOR_ORIGIN'] ?? `http://${host}:${orchestratorPort}`,
    'ORCHESTRATOR_ORIGIN',
  );
  const maintenanceIntervalMs = intervalFrom(env);
  const world = worldId.parse(env['DEMO_WORLD_ID'] ?? 'w-demo');
  const demoCaseId = id.parse(env['DEMO_CASE_ID'] ?? 'case_demo');
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
  const checkpointsRoot = resolve(env['RUNTIME_CHECKPOINTS_ROOT'] ?? 'docs/checkpoints');
  const verifyLocally = localCheckpointVerification(env);
  const policyFile = resolve(env['RUNTIME_POLICY_FILE'] ?? 'packages/gate-core/policy/v1.yaml');
  const policyRoot = resolve(env['RUNTIME_POLICY_ROOT'] ?? 'packages/gate-core/policy');
  const sourceRoot = resolve(env['RUNTIME_GATE_SOURCE_ROOT'] ?? 'packages/gate-core/src');
  const cardsRoot = resolve(env['RUNTIME_CARDS_ROOT'] ?? 'docs/cards');
  const conversationFixture = resolve(
    env['RUNTIME_CONVERSATION_FIXTURE'] ?? 'fixtures/demo/conversation.json',
  );
  const screeningFixtureFile = resolve(
    env['RUNTIME_SCREENING_FIXTURE'] ?? 'fixtures/demo/screening.json',
  );
  const systemUseFixtureFile = resolve(
    env['RUNTIME_SYSTEM_USE_FIXTURE'] ?? 'fixtures/demo/system-use-decision.json',
  );
  const consolesRoot = fileURLToPath(new URL('../../consoles/', import.meta.url));
  const consoleAssetsRoot = resolve(
    env['RUNTIME_CONSOLE_ASSETS_ROOT'] ?? join(consolesRoot, 'assets', 'governance-console'),
  );
  const consoleAssets = loadGovernanceConsoleAssets({
    shell: join(consoleAssetsRoot, 'index.html'),
    stylesheet: join(consoleAssetsRoot, 'styles.css'),
    script: resolve(env['RUNTIME_CONSOLE_SCRIPT'] ?? join(consolesRoot, 'dist', 'governanceConsole.js')),
  });
  const keyring = loadKeyring({ env });
  const loadedPolicy = loadPolicyFile(policyFile, digestFileSet(sourceRoot, 'evaluator-build'));
  const policy = { ...loadedPolicy, policyContentDigest: digestFileSet(policyRoot, 'policy-set') };
  const cards = CardRegistry.load(cardsRoot);
  const screeningFixtures = screeningFixtureSet.parse(
    JSON.parse(readFileSync(screeningFixtureFile, 'utf8')),
  );
  const systemUseFixture = systemUseDecisionRecord.parse(
    JSON.parse(readFileSync(systemUseFixtureFile, 'utf8')),
  );
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
    deferRunHeader: true,
  });
  const caseHandoffs = new CaseSessionHandoffService({
    store,
    worldId: world,
    authorizationBootId: bootId,
    targetOrigin: orchestratorOrigin,
    caseExists: (caseId) => caseId === demoCaseId,
  });
  const systemUse = new SystemUseDecisionService(store, {
    systemId: 'ai-charter-runtime-poc',
    useCaseId: 'public-grant-decision',
    jurisdictions: ['synthetic-demo'],
    hardConditions: { 'no-external-effect': true, 'synthetic-data-only': true },
  });
  let server: AuthorizationHttpServer | undefined;
  let maintenanceTimer: NodeJS.Timeout | undefined;
  let maintenancePromise: Promise<void> | undefined;
  let closed = false;
  let resolveFailure: (error: Error) => void = () => undefined;
  const failure = new Promise<Error>((resolveFailurePromise) => {
    resolveFailure = resolveFailurePromise;
  });
  const runMaintenance = dependencies.runMaintenance ?? runRuntimeMaintenance;
  const verifyRecordLayer = dependencies.verifyRecordLayer ?? verifyRecords;
  try {
    const verifyCurrentRecords = () =>
      verifyRecordLayer({
        recordsRoot,
        checkpointsRoot,
        worldId: world,
        local: verifyLocally,
        repoRoot: process.cwd(),
        ...(env['RUNTIME_CHECKPOINT_BRANCH'] === undefined
          ? {}
          : { branch: env['RUNTIME_CHECKPOINT_BRANCH'] }),
        ...(env['RUNTIME_CHECKPOINT_REPO_URL'] === undefined
          ? {}
          : { repoUrl: env['RUNTIME_CHECKPOINT_REPO_URL'] }),
      });
    const recordVerification = await verifyCurrentRecords();
    store.beginRun();
    await recordVerificationAccess(store, recordVerification.readLengths);
    await systemUse.installFixture(systemUseFixture, { credential: 'proc:authz', claimed_role: null });
    await caseHandoffs.expireIssued();
    await servicesProbe.requireHealthy();
    const conversationTransport = new ConversationTransportService({
      store,
      cards,
      keyring,
      systemUse,
      caseId: demoCaseId,
      authorizationBootId: bootId,
    });
    await conversationTransport.expireReleases({ credential: 'proc:authz', claimed_role: null });
    const proposalIntakes = new ProposalIntakeService({
      store,
      cards,
      keyring,
      systemUse,
      caseId: demoCaseId,
      authorizationBootId: bootId,
    });
    await proposalIntakes.expire();
    const conversationProjections = new ConversationProjectionService({
      store,
      cards,
      keyring,
      caseId: demoCaseId,
      authorizationBootId: bootId,
      screeningFixtures,
      systemUse,
      conversationTransport,
      proposalIntakes,
    });
    const authorization = new AuthorizationCore({
      store,
      keyring,
      policy,
      systemUse,
      resolveAuthorizedAgent: (actor) =>
        actor.credential === 'proc:orchestrator' ? (env['RUNTIME_AUTHORIZED_AGENT_ID'] ?? 'agent_demo') : undefined,
      resolveScreening: (proposal, gate, caseId) =>
        conversationProjections.screening({ proposal, gate, ...(caseId === undefined ? {} : { caseId }) }),
      validateScreeningResolution: (resolution, proposal, gate, caseId) =>
        conversationProjections.validateScreeningResolution(resolution, proposal, gate, caseId),
      resolveModelEvidence: (proposal) => cards.resolve(proposal),
      resolveRegistryEvidence: (citation) => servicesProbe.resolveRegistryEvidence(citation),
    });
    await authorization.activatePolicy();
    const proposalPrecommit = new ProposalPrecommitService({ store, authorization, proposalIntakes });
    const initialConversationItems = z.array(storeItem).parse(JSON.parse(readFileSync(conversationFixture, 'utf8')));
    await authorization.putConversationItems({
      caseId: demoCaseId,
      items: initialConversationItems,
      actor: { credential: 'proc:authz', claimed_role: null },
    });
    const maintain = async () => {
      await runMaintenance({
        authorization,
        store,
        keyring,
        policy,
        systemUse,
        probe: (idempotencyKey) => servicesProbe.probe(idempotencyKey),
      });
      await caseHandoffs.expireIssued();
      await conversationTransport.expireReleases({ credential: 'proc:authz', claimed_role: null });
      await proposalIntakes.expire();
    };
    await maintain();
    const adapter = new AuthorizationHttpAdapter({
      authorization,
      ownOrigin: `http://${host}:${port}`,
      demoWorldId: world,
      credentials,
    });
    const reads = new AuthorizationReadSide({
      store,
      cards,
      recordsRoot,
      worldId: world,
      verifyRecordLayer: verifyCurrentRecords,
    });
    server = new AuthorizationHttpServer({
      authorization,
      conversationProjections,
      conversationTransport,
      proposalIntakes,
      proposalPrecommit,
      reads,
      adapter,
      keyring,
      caseHandoffs,
      systemUse,
      runtimeConfig: {
        authorization_origin: `http://${host}:${port}`,
        orchestrator_origin: orchestratorOrigin,
      },
      consoleAssets,
      caseId: demoCaseId,
      host,
      port,
    });
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
      recordVerification,
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

export async function runAuthorizationProcess(
  env: NodeJS.ProcessEnv = process.env,
  dependencies: AuthorizationProcessDependencies = {},
): Promise<void> {
  let handle: AuthorizationProcessHandle | undefined;
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
    handle = await startAuthorizationProcess(env, dependencies);
    if (stopRequested) {
      await close();
      return;
    }
    process.stdout.write(`${JSON.stringify({ event: 'ready', service: 'authorization', ...handle.address })}\n`);
    void handle.failure
      .then(async (error) => {
        cleanup();
        process.stderr.write(`authorization maintenance failed: ${error.message}\n`);
        await handle?.close();
        if (process.connected) process.disconnect();
        process.exitCode = 1;
      })
      .catch(() => {
        cleanup();
        if (process.connected) process.disconnect();
        process.exitCode = 1;
      });
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
  runAuthorizationProcess().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'unknown startup error';
    process.stderr.write(`authorization startup failed: ${message}\n`);
    process.exitCode = 1;
  });
}
