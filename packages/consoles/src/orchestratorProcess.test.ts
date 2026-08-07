// SPDX-License-Identifier: MIT
import { createServer, type Server } from 'node:http';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer as createTcpServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { startOrchestratorProcess } from './orchestratorProcess.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const closeables: Array<() => Promise<void>> = [];
const roots: string[] = [];

afterEach(async () => {
  for (const close of closeables.splice(0).reverse()) await close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

async function listen(server: Server): Promise<{ readonly port: number; readonly origin: string }> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('test listener has no address');
  closeables.push(() => new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  }));
  return { port: address.port, origin: `http://127.0.0.1:${address.port}` };
}

async function health(service: 'authorization' | 'services') {
  return listen(createServer((request, response) => {
    if (request.url !== '/healthz') {
      response.writeHead(404).end();
      return;
    }
    const body = JSON.stringify({ status: 'ready', service });
    response.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
    response.end(body);
  }));
}

async function freePort(): Promise<number> {
  const server = createTcpServer();
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('no free port');
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
  return address.port;
}

async function environment(overrides: NodeJS.ProcessEnv = {}): Promise<NodeJS.ProcessEnv> {
  const [authorization, services, orchestratorPort] = await Promise.all([
    health('authorization'),
    health('services'),
    freePort(),
  ]);
  return {
    RUNTIME_HOST: '127.0.0.1',
    AUTHZ_PORT: String(authorization.port),
    SERVICES_PORT: String(services.port),
    ORCHESTRATOR_PORT: String(orchestratorPort),
    AUTHZ_ORIGIN: authorization.origin,
    SERVICES_ORIGIN: services.origin,
    DEMO_WORLD_ID: 'w-demo',
    DEMO_CASE_ID: 'case_demo',
    DEMO_MANDATE_ID: 'mdt_demo_grant',
    AUTHZ_TOKEN_PROC_ORCHESTRATOR: '4'.repeat(64),
    SERVICES_TOKEN_PROC_ORCHESTRATOR: '5'.repeat(64),
    ORCHESTRATOR_TOKEN_CASE_OFFICER: '6'.repeat(64),
    PUBLICAI_API_KEY: 'synthetic-publicai-key',
    OPENAI_API_KEY: 'synthetic-openai-key',
    RUNTIME_CARDS_ROOT: join(ROOT, 'docs', 'cards'),
    ...overrides,
  };
}

function adapters() {
  return {
    publicai: {
      lane: 'publicai' as const,
      requestedId: 'swiss-ai/apertus-v1.5-70b',
      act: vi.fn(),
    },
    openai: {
      lane: 'openai' as const,
      requestedId: 'gpt-5.5',
      act: vi.fn(),
    },
  };
}

describe('M5.9 native orchestrator startup', () => {
  it('constructs both injected test lanes before binding and makes no provider request at startup', async () => {
    const injected = adapters();
    const handle = await startOrchestratorProcess(await environment(), { adapters: injected });
    closeables.push(() => handle.close());
    expect(handle.address.origin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
    expect(injected.publicai.act).not.toHaveBeenCalled();
    expect(injected.openai.act).not.toHaveBeenCalled();
  });

  it('does not bind when configuration or signed-card evidence is absent or invalid', async () => {
    const missingKey = await environment({ PUBLICAI_API_KEY: '' });
    await expect(startOrchestratorProcess(missingKey, { adapters: adapters() })).rejects.toThrow();
    await expect(fetch(`http://127.0.0.1:${missingKey['ORCHESTRATOR_PORT']}/healthz`)).rejects.toThrow();

    const redirected = await environment({ PUBLICAI_BASE_URL: 'https://redirect.invalid/v1' });
    await expect(startOrchestratorProcess(redirected, { adapters: adapters() })).rejects.toThrow();
    await expect(fetch(`http://127.0.0.1:${redirected['ORCHESTRATOR_PORT']}/healthz`)).rejects.toThrow();

    const cardsRoot = mkdtempSync(join(tmpdir(), 'native-model-cards-'));
    roots.push(cardsRoot);
    cpSync(join(ROOT, 'docs', 'cards'), cardsRoot, { recursive: true });
    const cardPath = join(cardsRoot, 'publicai-apertus-v1.5-70b.json');
    const card = JSON.parse(readFileSync(cardPath, 'utf8')) as Record<string, unknown>;
    card['endpoint'] = { value: 'https://redirect.invalid/v1', provenance: 'probe-tested', date: '2026-08-01' };
    writeFileSync(cardPath, `${JSON.stringify(card, null, 2)}\n`, 'utf8');
    const invalidCard = await environment({ RUNTIME_CARDS_ROOT: cardsRoot });
    await expect(startOrchestratorProcess(invalidCard, { adapters: adapters() })).rejects.toThrow();
    await expect(fetch(`http://127.0.0.1:${invalidCard['ORCHESTRATOR_PORT']}/healthz`)).rejects.toThrow();
  });
});
