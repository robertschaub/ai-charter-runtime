// SPDX-License-Identifier: MIT
/** Local supervisor: derives audience credentials, then boots the three data-path processes in order. */
import { spawn, type ChildProcess } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

import { deriveAudienceToken } from 'gate-core';

type RuntimeChild = ChildProcess;
const SHUTDOWN_MESSAGE = 'runtime-shutdown';

function hasExited(child: RuntimeChild): boolean {
  return child.exitCode !== null || child.signalCode !== null;
}

function required(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (value === undefined || value.length === 0) throw new Error(`missing required runtime variable ${name}`);
  return value;
}

function systemEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const names = ['SystemRoot', 'TEMP', 'TMP', 'ComSpec', 'PATHEXT', 'Path', 'PATH'];
  return Object.fromEntries(names.flatMap((name) => (env[name] === undefined ? [] : [[name, env[name]]])));
}

function runtimeSettings(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const names = [
    'RUNTIME_HOST',
    'AUTHZ_PORT',
    'ORCHESTRATOR_PORT',
    'SERVICES_PORT',
    'DEMO_WORLD_ID',
    'DEMO_CASE_ID',
    'DEMO_MANDATE_ID',
    'RUNTIME_RECORDS_ROOT',
    'RUNTIME_POLICY_FILE',
    'RUNTIME_POLICY_ROOT',
    'RUNTIME_GATE_SOURCE_ROOT',
    'RUNTIME_CARDS_ROOT',
    'RUNTIME_AUTHORIZED_AGENT_ID',
    'GATE_KEYRING_PATH',
    'SWEEP_INTERVAL_MS',
  ];
  return Object.fromEntries(names.flatMap((name) => (env[name] === undefined ? [] : [[name, env[name]]])));
}

function checkpointSettings(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const names = [
    'RUNTIME_CHECKPOINTS_ROOT',
    'RUNTIME_CHECKPOINT_BRANCH',
    'RUNTIME_CHECKPOINT_REPO_URL',
    'CHECKPOINT_VERIFY_LOCAL',
  ];
  return Object.fromEntries(names.flatMap((name) => (env[name] === undefined ? [] : [[name, env[name]]])));
}

export interface RuntimeChildEnvironments {
  readonly authorization: NodeJS.ProcessEnv;
  readonly services: NodeJS.ProcessEnv;
  readonly orchestrator: NodeJS.ProcessEnv;
}

/** Build the exact child custody sets without spawning, so partitioning is directly testable. */
export function runtimeChildEnvironments(env: NodeJS.ProcessEnv): RuntimeChildEnvironments {
  const base = { ...systemEnvironment(env), ...runtimeSettings(env) };
  const caseAtOrchestrator = deriveAudienceToken(
    required(env, 'AUTHZ_TOKEN_CASE_OFFICER'),
    'orchestrator-case-officer',
  );
  const orchestratorAtServices = deriveAudienceToken(
    required(env, 'AUTHZ_TOKEN_PROC_ORCHESTRATOR'),
    'services-proc-orchestrator',
  );
  const hmac = {
    GATE_HMAC_KEY: required(env, 'GATE_HMAC_KEY'),
    GATE_HMAC_KEY_ID: required(env, 'GATE_HMAC_KEY_ID'),
  };
  return {
    authorization: {
      ...base,
      ...checkpointSettings(env),
      ...hmac,
      AUTHZ_TOKEN_PRINCIPAL: required(env, 'AUTHZ_TOKEN_PRINCIPAL'),
      AUTHZ_TOKEN_CASE_OFFICER: required(env, 'AUTHZ_TOKEN_CASE_OFFICER'),
      AUTHZ_TOKEN_APPLICANT: required(env, 'AUTHZ_TOKEN_APPLICANT'),
      AUTHZ_TOKEN_PROC_ORCHESTRATOR: required(env, 'AUTHZ_TOKEN_PROC_ORCHESTRATOR'),
      AUTHZ_TOKEN_PROC_SERVICES_HOST: required(env, 'AUTHZ_TOKEN_PROC_SERVICES_HOST'),
      SERVICES_TOKEN_PROC_AUTHZ: required(env, 'SERVICES_TOKEN_PROC_AUTHZ'),
    },
    services: {
      ...base,
      ...hmac,
      AUTHZ_TOKEN_PROC_SERVICES_HOST: required(env, 'AUTHZ_TOKEN_PROC_SERVICES_HOST'),
      SERVICES_TOKEN_PROC_AUTHZ: required(env, 'SERVICES_TOKEN_PROC_AUTHZ'),
      SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
    },
    orchestrator: {
      ...base,
      AUTHZ_TOKEN_PROC_ORCHESTRATOR: required(env, 'AUTHZ_TOKEN_PROC_ORCHESTRATOR'),
      SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
      ORCHESTRATOR_TOKEN_CASE_OFFICER: caseAtOrchestrator,
    },
  };
}

async function startChild(
  script: string,
  service: 'authorization' | 'services' | 'orchestrator',
  env: NodeJS.ProcessEnv,
  onSpawn: (child: RuntimeChild) => void,
): Promise<RuntimeChild> {
  const child = spawn(process.execPath, [script], {
    cwd: process.cwd(),
    env,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
    windowsHide: true,
  });
  onSpawn(child);
  const childStdout = child.stdout;
  const childStderr = child.stderr;
  if (childStdout === null || childStderr === null) throw new Error(`${service} stdio was not piped`);
  childStdout.setEncoding('utf8');
  childStderr.setEncoding('utf8');
  let stderr = '';
  childStderr.on('data', (chunk: string) => {
    stderr = `${stderr}${chunk}`.slice(-8_192);
  });
  await new Promise<void>((resolveReady, reject) => {
    let ready = false;
    let lineBuffer = '';
    const cleanup = () => {
      clearTimeout(timer);
      childStdout.off('data', inspect);
      child.off('error', onError);
      child.off('exit', onExit);
    };
    const fail = (error: Error) => {
      if (ready) return;
      ready = true;
      cleanup();
      if (!hasExited(child)) child.kill('SIGTERM');
      reject(error);
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
          const event = JSON.parse(line) as { event?: string; service?: string };
          if (event.event === 'ready' && event.service === service) {
            ready = true;
            cleanup();
            resolveReady();
            return;
          }
        } catch {}
      }
    };
    const onError = () => fail(new Error(`${service} process could not be started`));
    const onExit = (code: number | null) =>
      fail(
        new Error(
          `${service} exited during startup with code ${code}${stderr.length === 0 ? '' : `: ${stderr.trim()}`}`,
        ),
      );
    const timer = setTimeout(
      () => fail(new Error(`${service} startup timed out`)),
      service === 'authorization' ? 60_000 : 10_000,
    );
    childStdout.on('data', inspect);
    child.once('error', onError);
    child.once('exit', onExit);
  });
  return child;
}

async function stopChild(child: RuntimeChild): Promise<void> {
  if (hasExited(child)) return;
  const exited = new Promise<void>((resolveExit) => child.once('exit', () => resolveExit()));
  const hardStop = () => {
    if (!hasExited(child)) child.kill('SIGTERM');
  };
  try {
    if (child.connected) child.send(SHUTDOWN_MESSAGE, (error) => error && hardStop());
    else hardStop();
  } catch {
    hardStop();
  }
  const fallback = setTimeout(hardStop, 5_000);
  await exited;
  clearTimeout(fallback);
}

export async function runRuntimeSupervisor(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const root = process.cwd();
  const childEnvironments = runtimeChildEnvironments(env);
  const children: RuntimeChild[] = [];
  let stopping = false;
  let stopPromise: Promise<void> | undefined;
  let shutdownRequested = false;
  let unexpectedExit: Error | undefined;
  let resolveDone: (() => void) | undefined;
  let rejectDone: ((error: unknown) => void) | undefined;
  const stop = (): Promise<void> => {
    if (stopPromise !== undefined) return stopPromise;
    stopping = true;
    stopPromise = (async () => {
      for (const child of [...children].reverse()) await stopChild(child);
    })();
    return stopPromise;
  };
  const settle = () => {
    if (!children.every(hasExited) || resolveDone === undefined || rejectDone === undefined) return;
    if (unexpectedExit === undefined) resolveDone();
    else rejectDone(unexpectedExit);
  };
  const trackChild = (child: RuntimeChild) => {
    children.push(child);
    child.once('exit', (code) => {
      if (!stopping) {
        unexpectedExit ??= new Error(`runtime child exited unexpectedly with code ${code}`);
        void stop().then(settle, (error: unknown) => rejectDone?.(error));
        return;
      }
      settle();
    });
  };
  const requestStop = () => {
    shutdownRequested = true;
    void stop().catch((error: unknown) => rejectDone?.(error));
  };
  const onMessage = (message: unknown) => {
    if (message === SHUTDOWN_MESSAGE) requestStop();
  };
  process.once('SIGINT', requestStop);
  process.once('SIGTERM', requestStop);
  process.once('disconnect', requestStop);
  process.on('message', onMessage);

  try {
    try {
      await startChild(
        resolve(root, 'packages/services-mock/dist/servicesProcess.js'),
        'services',
        childEnvironments.services,
        trackChild,
      );
      if (stopping) {
        await stop();
        if (unexpectedExit !== undefined) throw unexpectedExit;
        return;
      }
      await startChild(
        resolve(root, 'packages/gate-core/dist/authorizationProcess.js'),
        'authorization',
        childEnvironments.authorization,
        trackChild,
      );
      if (stopping) {
        await stop();
        if (unexpectedExit !== undefined) throw unexpectedExit;
        return;
      }
      await startChild(
        resolve(root, 'packages/consoles/dist/orchestratorProcess.js'),
        'orchestrator',
        childEnvironments.orchestrator,
        trackChild,
      );
    } catch (error) {
      await stop();
      if (shutdownRequested) return;
      if (unexpectedExit !== undefined) throw unexpectedExit;
      throw error;
    }
    if (stopping || shutdownRequested) {
      await stop();
      if (unexpectedExit !== undefined) throw unexpectedExit;
      return;
    }
    if (unexpectedExit !== undefined) {
      await stop();
      throw unexpectedExit;
    }
    await new Promise<void>((resolve, reject) => {
      resolveDone = resolve;
      rejectDone = reject;
      process.stdout.write(
        `${JSON.stringify({ event: 'ready', services: ['authorization', 'services', 'orchestrator'] })}\n`,
      );
    });
  } finally {
    resolveDone = undefined;
    rejectDone = undefined;
    process.off('SIGINT', requestStop);
    process.off('SIGTERM', requestStop);
    process.off('disconnect', requestStop);
    process.off('message', onMessage);
  }
}

async function main(): Promise<void> {
  await runRuntimeSupervisor();
}

const invokedPath = process.argv[1];
if (invokedPath !== undefined && pathToFileURL(resolve(invokedPath)).href === import.meta.url) {
  main().catch((error: unknown) => {
    const message = error instanceof Error ? error.message : 'unknown runtime error';
    process.stderr.write(`runtime startup failed: ${message}\n`);
    process.exitCode = 1;
  });
}
