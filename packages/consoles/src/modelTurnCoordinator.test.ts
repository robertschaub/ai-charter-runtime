// SPDX-License-Identifier: MIT
import { createServer, type Server } from 'node:http';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import {
  AuthorizationCore,
  AuthorizationHttpAdapter,
  AuthorizationHttpServer,
  AuthorizationReadSide,
  bindMandate,
  CardRegistry,
  type CaseSessionHandoffService,
  ConversationProjectionService,
  digestFor,
  Keyring,
  loadPolicyFile,
  syntheticSystemUseForTests,
  storeItem,
  WalStore,
  type Mandate,
  type StoreItem,
} from 'gate-core';
import { ModelAdapterError, OpenAiCompatibleAdapter } from 'model-adapters';
import { afterEach, describe, expect, it } from 'vitest';

import {
  ModelOutputQuarantine,
  ModelTurnCoordinator,
  ModelTurnError,
  type ModelTurnLaneConfig,
} from './modelTurnCoordinator.js';
import { OrchestratorAuthorizationHttpClient } from './runtimeHttpClients.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const POLICY_FILE = join(ROOT, 'packages', 'gate-core', 'policy', 'v1.yaml');
const CARDS = join(ROOT, 'docs', 'cards');
const DEMO = join(ROOT, 'fixtures', 'demo');
const KEY_ID = 'hmac-test';
const KEY = 'a'.repeat(64);
const ORCHESTRATOR_TOKEN = '4'.repeat(64);
const ROLE_TOKENS = {
  principal: '1'.repeat(64),
  caseOfficer: '2'.repeat(64),
  applicant: '3'.repeat(64),
  services: '5'.repeat(64),
} as const;
const AUTHZ = { credential: 'proc:authz', claimed_role: null } as const;
const PRINCIPAL = { credential: 'role:principal', claimed_role: 'principal' } as const;
const roots: string[] = [];
const stores: WalStore[] = [];
const closeables: Array<() => Promise<void>> = [];

afterEach(async () => {
  for (const close of closeables.splice(0).reverse()) await close();
  for (const store of stores.splice(0)) store.close();
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function readJson(path: string): unknown {
  return JSON.parse(readFileSync(path, 'utf8')) as unknown;
}

interface ProviderReply {
  readonly model?: string;
  readonly content?: string | null;
  readonly toolCalls?: readonly unknown[];
  readonly status?: number;
  readonly rawBody?: string;
  readonly beforeReply?: () => Promise<void>;
}

interface LoopbackProvider {
  readonly baseUrl: string;
  readonly requests: Record<string, unknown>[];
  enqueue(reply: ProviderReply): void;
}

async function listen(server: Server): Promise<string> {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const address = server.address();
  if (address === null || typeof address === 'string') throw new Error('loopback server has no TCP address');
  return `http://127.0.0.1:${address.port}`;
}

async function loopbackProvider(): Promise<LoopbackProvider> {
  const replies: ProviderReply[] = [];
  const requests: Record<string, unknown>[] = [];
  const server = createServer((request, response) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const chunk of request) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      requests.push(JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown>);
      const reply = replies.shift();
      if (reply === undefined) throw new Error('synthetic provider reply queue is empty');
      await reply.beforeReply?.();
      const status = reply.status ?? 200;
      const body =
        reply.rawBody ??
        JSON.stringify({
          ...(reply.model === undefined ? {} : { model: reply.model }),
          choices: [
            {
              message: {
                content: reply.content ?? 'Synthetic admitted model output.',
                tool_calls: reply.toolCalls ?? [],
              },
            },
          ],
        });
      response.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      response.end(body);
    })().catch(() => response.destroy());
  });
  const origin = await listen(server);
  closeables.push(
    () =>
      new Promise<void>((resolve, reject) => {
        server.close((error) => (error === undefined ? resolve() : reject(error)));
      }),
  );
  return {
    baseUrl: `${origin}/v1`,
    requests,
    enqueue(reply) {
      replies.push(reply);
    },
  };
}

async function authorizationHarness() {
  const root = mkdtempSync(join(tmpdir(), 'model-turn-coordinator-'));
  roots.push(root);
  const buildDigest = digestFor('evaluator-build', { package: 'runtime-consoles', test: 'model-turn-coordinator' });
  const policy = loadPolicyFile(POLICY_FILE, buildDigest);
  const keyring = new Keyring(new Map([[KEY_ID, KEY]]), KEY_ID);
  const store = WalStore.open({
    recordsRoot: root,
    worldId: 'w-demo',
    runId: 'run_model_turn_1',
    bootId: 'authz_boot_model_turn_1',
    policyVersion: policy.policy.policy_version,
    policyContentDigest: policy.policyContentDigest,
    evaluatorBuildDigest: buildDigest,
    now: () => '2026-08-01T09:00:00.000Z',
  });
  stores.push(store);
  const systemUse = syntheticSystemUseForTests(store);
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
    systemUse,
    resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
    resolveScreening: () => ({ performed: false, signals: [], evidenceRefs: [] }),
    validateScreeningResolution: () => false,
    resolveModelEvidence: () => ({
      servedModelAccepted: true,
      cardStatus: 'current',
      cardKeyId: 'card-test',
      cardDigest: 'c'.repeat(64),
    }),
  });
  await core.activatePolicy();
  const mandateBody = readJson(join(DEMO, 'mandate.json')) as Omit<Mandate, 'binding'>;
  await core.grantMandate(bindMandate(keyring, mandateBody), PRINCIPAL);
  const conversation = storeItem.array().parse(readJson(join(DEMO, 'conversation.json')));
  const restricted: StoreItem = {
    id: 'said_turn_restricted',
    store: 'said',
    turn: 'turn_restricted',
    text: 'Synthetic detail that this provider is not cleared to receive.',
    provenance: { derived_from: [], hops: [] },
    tags: ['conf:sensitive', 'purpose:grant-assessment'],
    origin_actor: 'applicant',
  };
  await core.putConversationItems({ caseId: 'case_demo', items: [...conversation, restricted], actor: AUTHZ });
  const projections = new ConversationProjectionService({
    store,
    cards: CardRegistry.load(CARDS),
    keyring,
    caseId: 'case_demo',
    authorizationBootId: 'authz_boot_model_turn_1',
    screeningFixtures: [],
    systemUse,
    now: () => '2026-08-01T09:00:00.000Z',
  });
  const adapter = new AuthorizationHttpAdapter({
    authorization: core,
    ownOrigin: 'http://127.0.0.1:7801',
    demoWorldId: 'w-demo',
    credentials: [
      { label: 'role:principal', token: ROLE_TOKENS.principal, worldId: 'w-demo' },
      { label: 'role:case_officer', token: ROLE_TOKENS.caseOfficer, worldId: 'w-demo' },
      { label: 'role:applicant', token: ROLE_TOKENS.applicant, worldId: 'w-demo' },
      { label: 'proc:orchestrator', token: ORCHESTRATOR_TOKEN, worldId: 'w-demo' },
      { label: 'proc:services_host', token: ROLE_TOKENS.services, worldId: 'w-demo' },
    ],
  });
  const server = new AuthorizationHttpServer({
    authorization: core,
    conversationProjections: projections,
    reads: {} as AuthorizationReadSide,
    adapter,
    keyring,
    caseHandoffs: {} as CaseSessionHandoffService,
    systemUse,
    runtimeConfig: {
      authorization_origin: 'http://127.0.0.1:7801',
      orchestrator_origin: 'http://127.0.0.1:7802',
    },
    consoleAssets: { shell: '', script: '', stylesheet: '' },
    caseId: 'case_demo',
    host: '127.0.0.1',
    port: 0,
  });
  const address = await server.listen();
  closeables.push(() => server.close());
  return {
    core,
    store,
    systemUse,
    authorization: new OrchestratorAuthorizationHttpClient({
      origin: address.origin,
      token: ORCHESTRATOR_TOKEN,
    }),
  };
}

function lane(provider: LoopbackProvider, overrides: Partial<ModelTurnLaneConfig> = {}): ModelTurnLaneConfig {
  const base = {
    lane: 'publicai' as const,
    cardId: 'publicai-apertus-v1.5-70b',
    cardVersion: 1,
    requestedId: 'swiss-ai/apertus-v1.5-70b',
  };
  return {
    ...base,
    adapter: new OpenAiCompatibleAdapter({
      lane: base.lane,
      baseUrl: provider.baseUrl,
      requestedModel: overrides.requestedId ?? base.requestedId,
      apiKey: 'test-loopback-key',
      tokenParameter: 'max_tokens',
      timeoutMs: 2_000,
    }),
    ...overrides,
  };
}

const turn = {
  turnId: 'turn_model_1',
  mandateId: 'mdt_demo_grant',
  mandateVersion: 1,
  cardId: 'publicai-apertus-v1.5-70b',
  cardVersion: 1,
  requestedId: 'swiss-ai/apertus-v1.5-70b',
  maxOutputTokens: 256,
} as const;

describe('M5.4 containment with M5.5 durable model-call evidence', () => {
  it('seals admitted bytes behind metadata-only quarantine after both real HTTP boundaries', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = 'Synthetic admitted model output for quarantine.';
    let enteredProvider!: () => void;
    let releaseProvider!: () => void;
    const providerEntered = new Promise<void>((resolve) => {
      enteredProvider = resolve;
    });
    const providerRelease = new Promise<void>((resolve) => {
      releaseProvider = resolve;
    });
    provider.enqueue({
      model: turn.requestedId,
      content,
      beforeReply: async () => {
        enteredProvider();
        await providerRelease;
      },
    });
    const quarantine = new ModelOutputQuarantine();
    expect('seal' in quarantine).toBe(false);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(quarantine))).not.toContain('seal');
    expect(Object.getOwnPropertySymbols(Object.getPrototypeOf(quarantine))).toHaveLength(0);
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
      quarantine,
    });

    const pending = coordinator.run(turn);
    await providerEntered;
    expect([...h.store.snapshot().modelCalls.values()].find((call) => call.turn_id === turn.turnId)).toMatchObject({
      state: 'open',
      outcome: 'indeterminate',
      provider_disclosure: 'possible',
    });
    expect(h.store.snapshot().accessRecords).toContainEqual(
      expect.objectContaining({
        route: 'POST /w/{world_id}/model-calls/begin',
        operation_evidence: expect.objectContaining({ turn_id: turn.turnId, state: 'open' }),
      }),
    );
    await expect(coordinator.run({ ...turn, turnId: 'turn_model_concurrent' })).rejects.toEqual(
      expect.objectContaining({ code: 'lane-busy' }),
    );
    releaseProvider();
    const outcome = await pending;
    if (outcome.disposition !== 'quarantined') throw new Error('expected quarantined output');
    expect(outcome).toMatchObject({
      disposition: 'quarantined',
      admission: { disposition: 'admitted', authority_effect: 'none' },
      quarantine: { release_state: 'sealed-no-release-path' },
    });
    expect(quarantine.has(turn.turnId)).toBe(true);
    expect(quarantine.metadata(turn.turnId)).toEqual(
      expect.objectContaining({ turn_id: turn.turnId, output_digest: outcome.admission.output_digest }),
    );
    expect(JSON.stringify(outcome)).not.toContain(content);
    expect(JSON.stringify(quarantine)).not.toContain(content);
    expect(JSON.stringify(h.store.snapshot().accessRecords)).not.toContain(content);
    expect(h.store.snapshot().modelCalls.get(outcome.quarantine.call_id)).toMatchObject({
      state: 'terminal',
      outcome: 'admitted',
      provider_disclosure: 'confirmed',
      output_digest: outcome.admission.output_digest,
    });
    expect(provider.requests).toHaveLength(1);
    expect(JSON.stringify(provider.requests[0])).toContain('The synthetic grant criterion is published for public review.');
    expect(JSON.stringify(provider.requests[0])).not.toContain('Synthetic detail that this provider is not cleared to receive.');
    await expect(coordinator.run(turn)).rejects.toEqual(expect.objectContaining({ code: 'turn-replay' }));
    expect(provider.requests).toHaveLength(1);
    expect(quarantine.destroy(turn.turnId)).toBe(true);
    expect(quarantine.size).toBe(0);
  });

  it('records served-model substitution, adds no quarantine entry, and halts the lane', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = 'Synthetic output from an unapproved served model.';
    provider.enqueue({ model: 'substitute-model', content });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });

    const outcome = await coordinator.run({ ...turn, turnId: 'turn_model_mismatch' });
    expect(outcome).toMatchObject({
      disposition: 'withheld',
      admission: { model_resolution: 'mismatch', reasons: ['served-model-mismatch'] },
    });
    expect(coordinator.quarantine.size).toBe(0);
    expect(coordinator.isLaneHalted(turn.cardId, turn.cardVersion, turn.requestedId)).toBe(true);
    await expect(coordinator.run({ ...turn, turnId: 'turn_model_after_mismatch' })).rejects.toEqual(
      expect.objectContaining({ code: 'lane-halted' }),
    );
    expect(provider.requests).toHaveLength(1);
    expect(JSON.stringify(h.store.snapshot().accessRecords)).not.toContain(content);
    expect(h.store.snapshot().accessRecords).toContainEqual(
      expect.objectContaining({
        operation_evidence: expect.objectContaining({
          kind: 'model_call_admission',
          decision: expect.objectContaining({
            disposition: 'withheld',
            reasons: ['served-model-mismatch'],
          }),
        }),
      }),
    );
    expect([...h.store.snapshot().modelCalls.values()].find((call) => call.turn_id === 'turn_model_mismatch')).toMatchObject({
      state: 'terminal',
      outcome: 'withheld',
      served_id: 'substitute-model',
      provider_disclosure: 'confirmed',
    });
  });

  it('withholds a configured red-line match without treating it as releasable output', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = 'I am conscious and I will always love you.';
    provider.enqueue({ model: turn.requestedId, content });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });

    const outcome = await coordinator.run({ ...turn, turnId: 'turn_model_redline' });
    expect(outcome).toMatchObject({
      disposition: 'withheld',
      admission: {
        reasons: ['claimed-feeling-or-consciousness', 'relational-dependency-language'],
        authority_effect: 'none',
      },
    });
    expect(coordinator.quarantine.size).toBe(0);
    expect(JSON.stringify(outcome)).not.toContain(content);
  });

  it('stops before disclosure for an unapproved lane and after disclosure if authority is revoked', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    expect(
      () =>
        new ModelTurnCoordinator({
          worldId: 'w-demo',
          caseId: 'case_demo',
          authorization: h.authorization,
          lanes: [{ ...lane(provider), requestedId: 'synthetic-config-mismatch' }],
        }),
    ).toThrowError(expect.objectContaining({ code: 'invalid-configuration' }));
    expect(provider.requests).toHaveLength(0);
    const unapproved = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [
        lane(provider, {
          cardId: 'synthetic-unapproved-card',
          requestedId: 'synthetic-unapproved-model',
        }),
      ],
    });
    await expect(
      unapproved.run({
        ...turn,
        turnId: 'turn_model_unapproved',
        cardId: 'synthetic-unapproved-card',
        requestedId: 'synthetic-unapproved-model',
      }),
    ).rejects.toEqual(expect.objectContaining({ code: 'authorization-refused' }));
    expect(provider.requests).toHaveLength(0);

    provider.enqueue({
      model: turn.requestedId,
      content: 'Synthetic output produced just before revocation.',
      beforeReply: () => h.core.revokeMandate('mdt_demo_grant', 1, PRINCIPAL),
    });
    const revoked = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    await expect(revoked.run({ ...turn, turnId: 'turn_model_revoked' })).rejects.toEqual(
      expect.objectContaining({ code: 'authorization-refused' }),
    );
    expect(provider.requests).toHaveLength(1);
    expect(revoked.quarantine.size).toBe(0);
    expect([...h.store.snapshot().modelCalls.values()].find((call) => call.turn_id === 'turn_model_revoked')).toMatchObject({
      state: 'terminal',
      outcome: 'failed',
      failure_reason: 'authorization-invalidated',
      provider_disclosure: 'confirmed',
    });
  });

  it('records evidence-honest system-use invalidation after provider disclosure and persists no output', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = 'Synthetic output produced immediately before the decision is suspended.';
    provider.enqueue({
      model: turn.requestedId,
      content,
      beforeReply: () => h.systemUse.transition('sud_test_fixture', 1, 'suspended', AUTHZ),
    });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });

    await expect(coordinator.run({ ...turn, turnId: 'turn_system_use_suspended' })).rejects.toEqual(
      expect.objectContaining({ code: 'authorization-refused' }),
    );
    expect(coordinator.quarantine.size).toBe(0);
    expect([...h.store.snapshot().storeItems.values()].some((entry) => entry.item.text === content)).toBe(false);
    expect(
      [...h.store.snapshot().modelCalls.values()].find((call) => call.turn_id === 'turn_system_use_suspended'),
    ).toMatchObject({
      state: 'terminal',
      outcome: 'failed',
      failure_reason: 'system-use-invalidated',
      provider_disclosure: 'confirmed',
    });
  });

  it('durably records timeout and outage metadata without provider error detail', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    for (const failure of [
      { turnId: 'turn_model_timeout', error: new ModelAdapterError('timeout', 'synthetic secret timeout detail') },
      { turnId: 'turn_model_outage', error: new ModelAdapterError('provider-http', 'synthetic secret outage detail') },
    ]) {
      const coordinator = new ModelTurnCoordinator({
        worldId: 'w-demo',
        caseId: 'case_demo',
        authorization: h.authorization,
        lanes: [
          {
            ...lane(provider),
            adapter: {
              lane: 'publicai',
              requestedId: turn.requestedId,
              act: async () => {
                throw failure.error;
              },
            },
          },
        ],
      });
      await expect(coordinator.run({ ...turn, turnId: failure.turnId })).rejects.toEqual(
        expect.objectContaining({ code: 'provider-failure' }),
      );
    }
    const calls = [...h.store.snapshot().modelCalls.values()];
    expect(calls.find((call) => call.turn_id === 'turn_model_timeout')).toMatchObject({
      outcome: 'failed',
      failure_reason: 'provider-timeout',
      provider_disclosure: 'possible',
    });
    expect(calls.find((call) => call.turn_id === 'turn_model_outage')).toMatchObject({
      outcome: 'failed',
      failure_reason: 'provider-unavailable',
      provider_disclosure: 'possible',
    });
    const evidence = JSON.stringify(h.store.snapshot().accessRecords);
    expect(evidence).not.toContain('synthetic secret timeout detail');
    expect(evidence).not.toContain('synthetic secret outage detail');
    expect(provider.requests).toHaveLength(0);
  });

  it('totalizes non-object custom-adapter results and preserves indeterminate state only if reporting fails', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const malformed = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [
        {
          ...lane(provider),
          adapter: {
            lane: 'publicai',
            requestedId: turn.requestedId,
            act: async () => null as never,
          },
        },
      ],
    });
    await expect(malformed.run({ ...turn, turnId: 'turn_model_null_result' })).rejects.toEqual(
      expect.objectContaining({ code: 'provider-protocol' }),
    );
    expect(malformed.isLaneHalted(turn.cardId, turn.cardVersion, turn.requestedId)).toBe(true);
    expect([...h.store.snapshot().modelCalls.values()].find((call) => call.turn_id === 'turn_model_null_result')).toMatchObject({
      state: 'terminal',
      outcome: 'failed',
      failure_reason: 'malformed-response',
      provider_disclosure: 'confirmed',
      served_id: null,
    });

    const hostileResult = new Proxy(
      {},
      {
        get(_target, property) {
          if (property === 'then') return undefined;
          throw new Error('synthetic hostile result detail');
        },
      },
    );
    const hostile = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [
        {
          ...lane(provider),
          adapter: {
            lane: 'publicai',
            requestedId: turn.requestedId,
            act: async () => hostileResult as never,
          },
        },
      ],
    });
    await expect(hostile.run({ ...turn, turnId: 'turn_model_hostile_result' })).rejects.toEqual(
      expect.objectContaining({ code: 'provider-protocol' }),
    );
    expect(hostile.isLaneHalted(turn.cardId, turn.cardVersion, turn.requestedId)).toBe(true);
    expect(
      [...h.store.snapshot().modelCalls.values()].find((call) => call.turn_id === 'turn_model_hostile_result'),
    ).toMatchObject({
      state: 'terminal',
      outcome: 'failed',
      failure_reason: 'malformed-response',
      served_id: null,
    });
    expect(JSON.stringify(h.store.snapshot().accessRecords)).not.toContain('synthetic hostile result detail');

    const interrupted = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: {
        beginModelCall: (input) => h.authorization.beginModelCall(input),
        admitModelOutput: (world, callId, input) => h.authorization.admitModelOutput(world, callId, input),
        failModelCall: async () => {
          throw new Error('synthetic failure-report interruption');
        },
      },
      lanes: [
        {
          ...lane(provider),
          adapter: {
            lane: 'publicai',
            requestedId: turn.requestedId,
            act: async () => undefined as never,
          },
        },
      ],
    });
    await expect(interrupted.run({ ...turn, turnId: 'turn_model_undefined_result' })).rejects.toEqual(
      expect.objectContaining({ code: 'provider-protocol' }),
    );
    expect(interrupted.isLaneHalted(turn.cardId, turn.cardVersion, turn.requestedId)).toBe(true);
    expect(
      [...h.store.snapshot().modelCalls.values()].find((call) => call.turn_id === 'turn_model_undefined_result'),
    ).toMatchObject({
      state: 'open',
      outcome: 'indeterminate',
      provider_disclosure: 'possible',
    });
    expect(provider.requests).toHaveLength(0);
  });

  it('halts on tool calls, malformed provider evidence, or a changed admission binding', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const toolContent = 'Synthetic tool-bearing response that must not escape.';
    provider.enqueue({ model: turn.requestedId, content: toolContent, toolCalls: [{ id: 'call_1' }] });
    const toolCoordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    let toolError: unknown;
    try {
      await toolCoordinator.run({ ...turn, turnId: 'turn_model_tool_call' });
    } catch (error) {
      toolError = error;
    }
    expect(toolError).toEqual(expect.objectContaining<Partial<ModelTurnError>>({ code: 'provider-protocol' }));
    expect(String(toolError)).not.toContain(toolContent);
    expect(toolCoordinator.quarantine.size).toBe(0);

    provider.enqueue({ content: 'Synthetic response without served-model evidence.' });
    const malformedCoordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    await expect(malformedCoordinator.run({ ...turn, turnId: 'turn_model_malformed' })).rejects.toEqual(
      expect.objectContaining({ code: 'provider-failure' }),
    );
    expect(malformedCoordinator.quarantine.size).toBe(0);

    provider.enqueue({ model: turn.requestedId, content: '\ud800' });
    const unicodeCoordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    await expect(unicodeCoordinator.run({ ...turn, turnId: 'turn_model_malformed_unicode' })).rejects.toEqual(
      expect.objectContaining({ code: 'provider-protocol' }),
    );
    expect(unicodeCoordinator.quarantine.size).toBe(0);

    const bindingContent = 'Synthetic output whose returned admission binding is altered.';
    provider.enqueue({ model: turn.requestedId, content: bindingContent });
    const changedBindingCoordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: {
        beginModelCall: (input) => h.authorization.beginModelCall(input),
        admitModelOutput: async (world, callId, input) => {
          const admission = await h.authorization.admitModelOutput(world, callId, input);
          return { ...admission, decision: { ...admission.decision, output_digest: '0'.repeat(64) } };
        },
        failModelCall: (world, input) => h.authorization.failModelCall(world, input),
      },
      lanes: [lane(provider)],
    });
    await expect(changedBindingCoordinator.run({ ...turn, turnId: 'turn_model_binding_changed' })).rejects.toEqual(
      expect.objectContaining({ code: 'admission-binding-invalid' }),
    );
    expect(changedBindingCoordinator.quarantine.size).toBe(0);
    expect(provider.requests).toHaveLength(4);
    expect(String(new ModelTurnError('admission-binding-invalid'))).not.toContain(bindingContent);
    const calls = [...h.store.snapshot().modelCalls.values()];
    expect(calls.find((call) => call.turn_id === 'turn_model_tool_call')).toMatchObject({
      outcome: 'failed',
      failure_reason: 'tool-calls-refused',
      provider_disclosure: 'confirmed',
    });
    expect(calls.find((call) => call.turn_id === 'turn_model_malformed')).toMatchObject({
      outcome: 'failed',
      failure_reason: 'malformed-response',
      provider_disclosure: 'confirmed',
      served_id: null,
    });
    expect(calls.find((call) => call.turn_id === 'turn_model_malformed_unicode')).toMatchObject({
      outcome: 'failed',
      failure_reason: 'malformed-response',
      served_id: turn.requestedId,
    });
    expect(calls.find((call) => call.turn_id === 'turn_model_binding_changed')).toMatchObject({
      outcome: 'admitted',
    });
    expect(JSON.stringify(h.store.snapshot().accessRecords)).not.toContain(toolContent);
    expect(JSON.stringify(h.store.snapshot().accessRecords)).not.toContain(bindingContent);
  });
});
