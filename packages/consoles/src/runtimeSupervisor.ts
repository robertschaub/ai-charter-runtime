// SPDX-License-Identifier: MIT
/** Local supervisor: derives audience credentials, then boots the three data-path processes in order. */
import { spawn, type ChildProcessByStdio } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { Readable } from 'node:stream';

import { deriveAudienceToken } from 'gate-core';

type RuntimeChild = ChildProcessByStdio<null, Readable, Readable>;

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
    'RUNTIME_RECORDS_ROOT',
    'RUNTIME_POLICY_FILE',
    'RUNTIME_POLICY_ROOT',
    'RUNTIME_GATE_SOURCE_ROOT',
    'RUNTIME_CARDS_ROOT',
    'RUNTIME_AUTHORIZED_AGENT_ID',
    'GATE_KEYRING_PATH',
  ];
  return Object.fromEntries(names.flatMap((name) => (env[name] === undefined ? [] : [[name, env[name]]])));
}

async function startChild(
  script: string,
  service: 'authorization' | 'services' | 'orchestrator',
  env: NodeJS.ProcessEnv,
): Promise<RuntimeChild> {
  const child = spawn(process.execPath, [script], {
    cwd: process.cwd(),
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
  });
  child.stdout.setEncoding('utf8');
  child.stderr.setEncoding('utf8');
  let stderr = '';
  child.stderr.on('data', (chunk: string) => {
    stderr = `${stderr}${chunk}`.slice(-8_192);
  });
  await new Promise<void>((resolveReady, reject) => {
    let ready = false;
    let lineBuffer = '';
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off('data', inspect);
      child.off('error', onError);
      child.off('exit', onExit);
    };
    const fail = (error: Error) => {
      if (ready) return;
      ready = true;
      cleanup();
      if (child.exitCode === null) child.kill('SIGTERM');
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
    const timer = setTimeout(() => fail(new Error(`${service} startup timed out`)), 10_000);
    child.stdout.on('data', inspect);
    child.once('error', onError);
    child.once('exit', onExit);
  });
  return child;
}

export async function runRuntimeSupervisor(env: NodeJS.ProcessEnv = process.env): Promise<void> {
  const root = process.cwd();
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
  const children: RuntimeChild[] = [];
  let stopping = false;
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    for (const child of [...children].reverse()) {
      if (child.exitCode === null) child.kill('SIGTERM');
    }
    await Promise.all(
      children.map(
        (child) =>
          new Promise<void>((resolveExit) => {
            if (child.exitCode !== null) return resolveExit();
            child.once('exit', () => resolveExit());
          }),
      ),
    );
  };

  try {
    children.push(
      await startChild(resolve(root, 'packages/gate-core/dist/authorizationProcess.js'), 'authorization', {
        ...base,
        ...hmac,
        AUTHZ_TOKEN_PRINCIPAL: required(env, 'AUTHZ_TOKEN_PRINCIPAL'),
        AUTHZ_TOKEN_CASE_OFFICER: required(env, 'AUTHZ_TOKEN_CASE_OFFICER'),
        AUTHZ_TOKEN_APPLICANT: required(env, 'AUTHZ_TOKEN_APPLICANT'),
        AUTHZ_TOKEN_PROC_ORCHESTRATOR: required(env, 'AUTHZ_TOKEN_PROC_ORCHESTRATOR'),
        AUTHZ_TOKEN_PROC_SERVICES_HOST: required(env, 'AUTHZ_TOKEN_PROC_SERVICES_HOST'),
      }),
    );
    children.push(
      await startChild(resolve(root, 'packages/services-mock/dist/servicesProcess.js'), 'services', {
        ...base,
        ...hmac,
        AUTHZ_TOKEN_PROC_SERVICES_HOST: required(env, 'AUTHZ_TOKEN_PROC_SERVICES_HOST'),
        SERVICES_TOKEN_PROC_AUTHZ: required(env, 'SERVICES_TOKEN_PROC_AUTHZ'),
        SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
      }),
    );
    children.push(
      await startChild(resolve(root, 'packages/consoles/dist/orchestratorProcess.js'), 'orchestrator', {
        ...base,
        AUTHZ_TOKEN_PROC_ORCHESTRATOR: required(env, 'AUTHZ_TOKEN_PROC_ORCHESTRATOR'),
        SERVICES_TOKEN_PROC_ORCHESTRATOR: orchestratorAtServices,
        ORCHESTRATOR_TOKEN_CASE_OFFICER: caseAtOrchestrator,
      }),
    );
  } catch (error) {
    await stop();
    throw error;
  }

  process.stdout.write(`${JSON.stringify({ event: 'ready', services: ['authorization', 'services', 'orchestrator'] })}\n`);
  process.once('SIGINT', () => void stop());
  process.once('SIGTERM', () => void stop());
  await new Promise<void>((resolveDone, reject) => {
    for (const child of children) {
      child.once('exit', (code) => {
        if (stopping) {
          if (children.every((candidate) => candidate.exitCode !== null)) resolveDone();
          return;
        }
        void stop().then(() => reject(new Error(`runtime child exited unexpectedly with code ${code}`)));
      });
    }
  });
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
