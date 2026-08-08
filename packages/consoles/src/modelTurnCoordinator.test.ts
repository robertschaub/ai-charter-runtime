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
  CaseSessionHandoffService,
  ConversationProjectionService,
  ConversationTransportService,
  ProposalIntakeService,
  ProposalPrecommitService,
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
  type ModelTurnAuthorizationClient,
  type ModelTurnLaneConfig,
} from './modelTurnCoordinator.js';
import { OrchestratorAuthorizationHttpClient, RuntimeDependencyError } from './runtimeHttpClients.js';

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
const CASE_OFFICER = { credential: 'role:case_officer', claimed_role: 'case_officer' } as const;
const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: null } as const;
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
  let at = '2026-08-01T09:00:00.000Z';
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
    now: () => at,
  });
  stores.push(store);
  const systemUse = syntheticSystemUseForTests(store);
  const cards = CardRegistry.load(CARDS);
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
    systemUse,
    resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
    resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
    validateScreeningResolution: () => true,
    resolveModelEvidence: (value) => cards.resolve(value),
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
  const conversationTransport = new ConversationTransportService({
    store,
    cards,
    keyring,
    systemUse,
    caseId: 'case_demo',
    authorizationBootId: 'authz_boot_model_turn_1',
    now: () => at,
  });
  const handoffs = new CaseSessionHandoffService({
    store,
    worldId: 'w-demo',
    authorizationBootId: 'authz_boot_model_turn_1',
    targetOrigin: 'http://127.0.0.1:7802',
    caseExists: (caseId) => caseId === 'case_demo',
  });
  const minted = await handoffs.mint('case_demo', CASE_OFFICER);
  const { expires_at: ignoredHandoffExpiry, ...handoffInput } = minted;
  void ignoredHandoffExpiry;
  const sessionId = 'session_message_turn';
  await handoffs.redeem({ ...handoffInput, session_id: sessionId }, ORCHESTRATOR);
  const proposalIntakes = new ProposalIntakeService({
    store,
    cards,
    keyring,
    systemUse,
    caseId: 'case_demo',
    authorizationBootId: 'authz_boot_model_turn_1',
    now: () => at,
    nextIntakeId: () => 'pint_test_native',
    nextProposalId: () => 'prp_test_native',
    nextActionId: () => 'act_test_native',
  });
  const projections = new ConversationProjectionService({
    store,
    cards,
    keyring,
    caseId: 'case_demo',
    authorizationBootId: 'authz_boot_model_turn_1',
    screeningFixtures: [],
    systemUse,
    conversationTransport,
    proposalIntakes,
    now: () => at,
  });
  const proposalPrecommit = new ProposalPrecommitService({ store, authorization: core, proposalIntakes });
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
    conversationTransport,
    proposalIntakes,
    proposalPrecommit,
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
  let authorizationServerClosed = false;
  const closeAuthorization = async () => {
    if (authorizationServerClosed) return;
    authorizationServerClosed = true;
    await server.close();
  };
  closeables.push(closeAuthorization);
  const authorization = new OrchestratorAuthorizationHttpClient({
    origin: address.origin,
    token: ORCHESTRATOR_TOKEN,
  });
  const checked = await authorization.checkModelSelection('w-demo', 'case_demo', {
    expected_current_selection_id: null,
    target: mandateBody.default_acting_model,
  });
  const selected = await authorization.selectModel('w-demo', 'case_demo', {
    check_id: checked.check.check_id,
    expected_current_selection_id: null,
  });
  return {
    core,
    store,
    systemUse,
    cards,
    keyring,
    authorization,
    authorizationOrigin: address.origin,
    mandateBody,
    selectionId: selected.selection.selection_id,
    sessionId,
    conversationTransport,
    proposalIntakes,
    proposalPrecommit,
    root,
    policy,
    buildDigest,
    closeAuthorization,
    setAt(value: string) {
      at = value;
    },
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

const turnBase = {
  turnId: 'turn_model_1',
  cardId: 'publicai-apertus-v1.5-70b',
  cardVersion: 1,
  requestedId: 'swiss-ai/apertus-v1.5-70b',
  maxOutputTokens: 256,
} as const;

function nativeProposalContent(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    declared_objective: 'File the synthetic grant application.',
    proposed_action: 'Submit the synthetic grant filing.',
    target: { recipient: 'grant-office', resource: 'application-42' },
    exact_parameters: { amount_minor_units: 5000, reference: 'screening-fixture' },
    material_input_ids: ['said_public'],
    derived_claim_ids: [],
    data_to_be_disclosed: ['applicant_name'],
    cost_obligation: { amount_minor_units: 5000, description: 'Synthetic grant amount.' },
    material_consequences: ['Creates a synthetic public-funds commitment.'],
    reversibility_class: 'partially-reversible',
    commercial_influence: { applicable: false, note: 'Not applicable.' },
    ...overrides,
  });
}

describe('M5.4 containment with M5.5 durable model-call evidence', () => {
  it('enforces selection and conversation transport routes on a real listener with bounded access evidence', async () => {
    const h = await authorizationHarness();
    const routes = [
      { method: 'GET', path: '/w/w-demo/cases/case_demo/model-selection' },
      { method: 'POST', path: '/w/w-demo/cases/case_demo/model-selection-checks' },
      { method: 'POST', path: '/w/w-demo/cases/case_demo/model-selections' },
      { method: 'POST', path: '/w/w-demo/cases/case_demo/conversation/messages', requiresSession: true },
      { method: 'POST', path: '/w/w-demo/model-output-releases/rel_denied/consume', requiresSession: true },
      { method: 'GET', path: '/w/w-demo/model-output-releases/rel_denied', requiresSession: true },
      { method: 'GET', path: '/w/w-demo/cases/case_demo/conversation', requiresSession: true },
    ] as const;
    const nonOrchestratorTokens = [
      ROLE_TOKENS.principal,
      ROLE_TOKENS.caseOfficer,
      ROLE_TOKENS.applicant,
      ROLE_TOKENS.services,
    ];
    const request = (route: (typeof routes)[number], token: string, body?: unknown, origin?: string) =>
      fetch(new URL(route.path, h.authorizationOrigin), {
        method: route.method,
        headers: {
          authorization: `Bearer ${token}`,
          ...(origin === undefined ? {} : { origin }),
          ...(route.method === 'POST' ? { 'content-type': 'application/json' } : {}),
        },
        ...(route.method === 'POST' ? { body: JSON.stringify(body ?? {}) } : {}),
      });

    for (const route of routes) {
      for (const token of nonOrchestratorTokens) {
        expect((await request(route, token)).status, `${route.method} ${route.path}`).toBe(403);
      }
      expect((await request(route, ORCHESTRATOR_TOKEN, {}, 'http://foreign.invalid')).status).toBe(403);
      if ('requiresSession' in route) expect((await request(route, ORCHESTRATOR_TOKEN)).status).toBe(403);
    }

    const read = await request(routes[0], ORCHESTRATOR_TOKEN);
    expect(read.status).toBe(200);
    await expect(read.json()).resolves.toMatchObject({
      state: 'selected',
      selection: { selection_id: h.selectionId },
    });
    expect(
      (
        await request(routes[1], ORCHESTRATOR_TOKEN, {
          expected_current_selection_id: h.selectionId,
          target: h.mandateBody.default_acting_model,
          unexpected: true,
        })
      ).status,
    ).toBe(422);
    expect(
      (
        await request(routes[2], ORCHESTRATOR_TOKEN, {
          check_id: 'msc_nonexistent',
          expected_current_selection_id: h.selectionId,
          unexpected: true,
        })
      ).status,
    ).toBe(422);

    expect(h.store.snapshot().accessRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          route: 'POST /w/{world_id}/cases/{case_id}/model-selection-checks',
          operation_evidence: expect.objectContaining({ kind: 'model_selection_check' }),
        }),
        expect.objectContaining({
          route: 'POST /w/{world_id}/cases/{case_id}/model-selections',
          operation_evidence: expect.objectContaining({ kind: 'model_selection_result' }),
        }),
        expect.objectContaining({
          route: 'GET /w/{world_id}/cases/{case_id}/model-selection',
          operation_evidence: {
            kind: 'model_selection_read',
            case_id: 'case_demo',
            current_selection_id: h.selectionId,
            latest_observation_id: null,
          },
        }),
      ]),
    );
  });

  it('destroys prior-selection quarantine only after authorization confirms a bound switch', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const turn = { ...turnBase, selectionId: h.selectionId, turnId: 'turn_selection_quarantine' };
    provider.enqueue({ model: turn.requestedId, content: 'Synthetic quarantined output before switching.' });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    await expect(coordinator.run(turn)).resolves.toMatchObject({ disposition: 'quarantined' });
    expect(coordinator.quarantine.has(turn.turnId)).toBe(true);

    const switched = await coordinator.select({
      expectedCurrentSelectionId: h.selectionId,
      target: {
        card_id: 'openai-gpt-5.5',
        card_version: 1,
        requested_id: 'gpt-5.5',
      },
    });
    expect(switched.selection).toMatchObject({
      kind: 'switch',
      predecessor_selection_id: h.selectionId,
      target: { card_id: 'openai-gpt-5.5', requested_id: 'gpt-5.5' },
    });
    expect(coordinator.quarantine.size).toBe(0);
    await expect(coordinator.currentSelection()).resolves.toMatchObject({
      state: 'selected',
      selection: { selection_id: switched.selection.selection_id },
    });
  });

  it('seals admitted bytes behind metadata-only quarantine after both real HTTP boundaries', async () => {
    const h = await authorizationHarness();
    const turn = { ...turnBase, selectionId: h.selectionId };
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

    const caller = { role: 'case_officer' as const, session_id: 'session_model_turn' };
    const pending = coordinator.run(turn, { onBehalfOf: caller });
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
    expect(h.store.snapshot().accessRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          route: 'POST /w/{world_id}/model-calls/begin',
          authenticated_actor: 'proc:orchestrator',
          claimed_actor: { role: 'case_officer', session: 'session_model_turn' },
        }),
        expect.objectContaining({
          route: 'POST /w/{world_id}/model-outputs/admit',
          authenticated_actor: 'proc:orchestrator',
          claimed_actor: { role: 'case_officer', session: 'session_model_turn' },
        }),
      ]),
    );
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
    const turn = { ...turnBase, selectionId: h.selectionId };
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
    const turn = { ...turnBase, selectionId: h.selectionId };
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
    const turn = { ...turnBase, selectionId: h.selectionId };
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
    const turn = { ...turnBase, selectionId: h.selectionId };
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
      served_id: turn.requestedId,
    });
  });

  it('durably records timeout and outage metadata without provider error detail', async () => {
    const h = await authorizationHarness();
    const turn = { ...turnBase, selectionId: h.selectionId };
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
      await expect(coordinator.run(
        { ...turn, turnId: failure.turnId },
        { onBehalfOf: { role: 'case_officer', session_id: 'session_failure_claim' } },
      )).rejects.toEqual(
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
    expect(h.store.snapshot().accessRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          route: 'POST /w/{world_id}/model-calls/failures',
          authenticated_actor: 'proc:orchestrator',
          claimed_actor: { role: 'case_officer', session: 'session_failure_claim' },
        }),
      ]),
    );
    expect(provider.requests).toHaveLength(0);
  });

  it('totalizes non-object custom-adapter results and preserves indeterminate state only if reporting fails', async () => {
    const h = await authorizationHarness();
    const turn = { ...turnBase, selectionId: h.selectionId };
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
        currentModelSelection: (world, caseId) => h.authorization.currentModelSelection(world, caseId),
        checkModelSelection: (world, caseId, input) => h.authorization.checkModelSelection(world, caseId, input),
        selectModel: (world, caseId, input) => h.authorization.selectModel(world, caseId, input),
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
    const turn = { ...turnBase, selectionId: h.selectionId };
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
        currentModelSelection: (world, caseId) => h.authorization.currentModelSelection(world, caseId),
        checkModelSelection: (world, caseId, input) => h.authorization.checkModelSelection(world, caseId, input),
        selectModel: (world, caseId, input) => h.authorization.selectModel(world, caseId, input),
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

  it('ingests one session-bound message and releases admitted bytes only through the durable transcript', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = 'Synthetic released inference for the case officer.';
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    const message = 'Please summarize only the synthetic case evidence.';
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const outcome = await coordinator.runMessage(
      {
        messageId: 'msg_release_1',
        text: message,
        turnId: 'turn_release_1',
        selectionId: h.selectionId,
        cardId: h.mandateBody.default_acting_model.card_id,
        cardVersion: h.mandateBody.default_acting_model.card_version,
        requestedId: h.mandateBody.default_acting_model.requested_id,
        maxOutputTokens: 256,
      },
      { onBehalfOf: claim },
    );
    expect(outcome.disposition).toBe('released');
    expect(coordinator.quarantine.size).toBe(0);
    expect(provider.requests).toHaveLength(1);
    const snapshot = h.store.snapshot();
    expect(snapshot.conversationVersionByCase.get('case_demo')).toBe(3);
    expect([...snapshot.conversationEvents.values()].map((event) => event.kind)).toEqual([
      'message_ingress',
      'model_output_ingress',
    ]);
    expect([...snapshot.outputReleases.values()]).toHaveLength(1);
    const release = [...snapshot.outputReleases.values()][0];
    expect(release).toMatchObject({ state: 'consumed', session_id: h.sessionId, message_id: 'msg_release_1' });
    const processProjection = await h.authorization.conversation('w-demo', 'case_demo', claim);
    expect(processProjection.events).toEqual([
      expect.objectContaining({ speaker: 'case_officer', message_id: 'msg_release_1', text: message }),
      expect.objectContaining({
        speaker: 'model',
        message_id: 'msg_release_1',
        text: content,
        classification: 'inferred-unconfirmed',
      }),
    ]);
    expect(JSON.stringify(snapshot.accessRecords)).not.toContain(message);
    expect(JSON.stringify(snapshot.accessRecords)).not.toContain(content);
    if (release === undefined || outcome.disposition !== 'released') throw new Error('expected consumed release');
    await expect(
      h.authorization.consumeOutputRelease('w-demo', release.release_id, content, claim),
    ).resolves.toEqual(outcome.ingestion);
    await expect(
      h.authorization.consumeOutputRelease('w-demo', release.release_id, `${content} changed`, claim),
    ).rejects.toBeInstanceOf(RuntimeDependencyError);
    const replay = await h.authorization.ingestConversationMessage(
      'w-demo',
      'case_demo',
      { message_id: 'msg_release_1', turn_id: 'turn_release_1', text: message },
      claim,
    );
    expect(replay.conversation_version).toBe(2);
    expect(h.store.snapshot().conversationVersionByCase.get('case_demo')).toBe(3);
  });

  it('uses native JSON schema for one proposal-purpose call, freezes through the distinct intake, and stops before Commit', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = nativeProposalContent();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const outcome = await coordinator.runProposal(
      {
        proposalRunId: 'prun_native_test',
        conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
        turnId: 'turn_native_proposal',
        selectionId: h.selectionId,
        cardId: h.mandateBody.default_acting_model.card_id,
        cardVersion: h.mandateBody.default_acting_model.card_version,
        requestedId: h.mandateBody.default_acting_model.requested_id,
      },
      { onBehalfOf: claim },
    );
    expect(outcome).toMatchObject({
      disposition: 'proposal-frozen',
      proposal: { proposal_run_id: 'prun_native_test', proposal_id: 'prp_test_native', state: 'consumed' },
    });
    expect(coordinator.quarantine.size).toBe(0);
    expect(provider.requests).toHaveLength(1);
    expect(provider.requests[0]).toMatchObject({
      max_tokens: 512,
      response_format: { type: 'json_schema', json_schema: { name: 'proposal_draft_v1', strict: true } },
    });
    expect(provider.requests[0]).not.toHaveProperty('tools');
    const snapshotAfterFreeze = h.store.snapshot();
    expect([...snapshotAfterFreeze.proposalIntakes.values()]).toEqual([
      expect.objectContaining({ state: 'consumed', proposal_id: 'prp_test_native', proposal_run_id: 'prun_native_test' }),
    ]);
    expect(snapshotAfterFreeze.proposalOrigins.get('prp_test_native')).toMatchObject({
      proposal_run_id: 'prun_native_test',
      case_id: 'case_demo',
      service: h.mandateBody.connected_service,
      action_class: h.mandateBody.action_class,
    });
    expect(snapshotAfterFreeze.outputReleases.size).toBe(0);
    await expect(
      h.authorization.consumeProposalIntake('w-demo', 'pint_test_native', content, claim),
    ).resolves.toEqual(outcome.proposal);
    await expect(
      h.authorization.consumeProposalIntake('w-demo', 'pint_test_native', `${content} `, claim),
    ).rejects.toBeInstanceOf(RuntimeDependencyError);

    const intakeStatus = await h.authorization.proposalIntakeStatus('w-demo', 'pint_test_native', claim);
    expect(Object.keys(intakeStatus).sort()).toEqual([
      'call_id', 'case_id', 'expires_at', 'issued_at', 'kind', 'proposal_id', 'proposal_intake_id',
      'proposal_run_id', 'refusal_reason', 'state', 'state_changed_at',
    ]);
    expect(JSON.stringify(intakeStatus)).not.toContain(content);
    const callerSelectedGate = await fetch(
      `${h.authorizationOrigin}/w/w-demo/proposals/${outcome.proposal.proposal_id}/precommit`,
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${ORCHESTRATOR_TOKEN}`,
          origin: 'http://127.0.0.1:7801',
          'content-type': 'application/json',
          'x-on-behalf-of-role': claim.role,
          'x-session-id': claim.session_id,
        },
        body: JSON.stringify({ gate: 'commit' }),
      },
    );
    expect(callerSelectedGate.status).toBe(422);
    expect(h.store.snapshot().rulings.size).toBe(0);

    const precommit = await h.authorization.runProposalPrecommit('w-demo', outcome.proposal.proposal_id, claim);
    expect(precommit.proposal_run_id).toBe('prun_native_test');
    expect(precommit.state).toBe('verified');
    expect(precommit.gates.map((entry) => entry.gate)).toEqual(['authorize', 'submit', 'verify']);
    const final = h.store.snapshot();
    expect([...final.rulings.values()].some((ruling) => ruling.gate === 'commit')).toBe(false);
    expect(final.reservations.size).toBe(0);
    expect(final.commitments.size).toBe(0);
    expect(final.effects.size).toBe(0);
    expect(JSON.stringify(final.accessRecords)).not.toContain(content);
    await expect(
      h.authorization.proposalRunStatus('w-demo', 'case_demo', 'prun_native_test', claim),
    ).resolves.toEqual(precommit);

    await h.closeAuthorization();
    h.store.close();
    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_model_turn_replay',
      bootId: 'authz_boot_model_turn_replay',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.buildDigest,
      now: () => '2026-08-01T09:00:00.000Z',
    });
    stores.push(reopened);
    const replayed = reopened.snapshot();
    expect(replayed.proposalIntakes.get('pint_test_native')).toMatchObject({
      state: 'consumed',
      proposal_id: 'prp_test_native',
      proposal_run_id: 'prun_native_test',
    });
    expect(replayed.proposals.get('prp_test_native')).toEqual(final.proposals.get('prp_test_native'));
    expect(replayed.proposalOrigins.get('prp_test_native')).toEqual(final.proposalOrigins.get('prp_test_native'));
    expect([...replayed.rulings.values()].filter(
      (ruling) => ruling.binding.frozen_proposal_hash === final.proposals.get('prp_test_native')?.proposal_hash,
    ).map((ruling) => ruling.gate)).toEqual(['authorize', 'submit', 'verify']);
    const restartedIntakes = new ProposalIntakeService({
      store: reopened,
      cards: h.cards,
      keyring: h.keyring,
      systemUse: syntheticSystemUseForTests(reopened),
      caseId: 'case_demo',
      authorizationBootId: 'authz_boot_model_turn_replay',
    });
    await expect(restartedIntakes.expire()).resolves.toBe(3);
    expect([...reopened.snapshot().rulings.values()].filter(
      (ruling) => ruling.binding.frozen_proposal_hash === final.proposals.get('prp_test_native')?.proposal_hash,
    ).map((ruling) => ruling.status)).toEqual(['invalidated', 'invalidated', 'invalidated']);
  });

  it('refuses malformed admitted proposal bytes atomically and exposes no proposal or conversation release', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = nativeProposalContent().replace(
      '"declared_objective":',
      '"declared_objective":"duplicate","declared_objective":',
    );
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    await expect(coordinator.runProposal({
      proposalRunId: 'prun_malformed_test',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_malformed_proposal',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: { role: 'case_officer', session_id: h.sessionId } })).rejects.toMatchObject({
      code: 'authorization-refused',
      providerDisclosure: 'confirmed',
    });
    const snapshot = h.store.snapshot();
    expect([...snapshot.proposalIntakes.values()]).toEqual([
      expect.objectContaining({ state: 'refused', refusal_reason: 'invalid-content', proposal_id: null }),
    ]);
    expect(snapshot.proposals.size).toBe(0);
    expect(snapshot.proposalOrigins.size).toBe(0);
    expect(snapshot.outputReleases.size).toBe(0);
    expect(coordinator.quarantine.size).toBe(0);
    expect(provider.requests).toHaveLength(1);
    expect(JSON.stringify(snapshot.accessRecords)).not.toContain(content);
  });

  it('refuses a projected item used under the wrong proposal-evidence standing', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    provider.enqueue({
      model: h.mandateBody.default_acting_model.requested_id,
      content: nativeProposalContent({ material_input_ids: [], derived_claim_ids: ['said_public'] }),
    });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    await expect(coordinator.runProposal({
      proposalRunId: 'prun_wrong_standing',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_wrong_standing',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: { role: 'case_officer', session_id: h.sessionId } })).rejects.toMatchObject({
      code: 'authorization-refused',
    });
    expect([...h.store.snapshot().proposalIntakes.values()]).toEqual([
      expect.objectContaining({ state: 'refused', refusal_reason: 'invalid-evidence', proposal_id: null }),
    ]);
    expect(h.store.snapshot().proposals.size).toBe(0);
    expect(h.store.snapshot().proposalOrigins.size).toBe(0);
  });

  it('refuses the first precommit gate after the authorization conversation changes', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: nativeProposalContent() });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_stale_test',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_stale_proposal',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    await h.authorization.ingestConversationMessage('w-demo', 'case_demo', {
      message_id: 'msg_after_proposal',
      turn_id: 'turn_after_proposal',
      text: 'Synthetic conversation mutation after proposal freeze.',
    }, claim);
    await expect(
      h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim),
    ).rejects.toBeInstanceOf(RuntimeDependencyError);
    const proposal = h.store.snapshot().proposals.get(frozen.proposal.proposal_id)!;
    expect([...h.store.snapshot().rulings.values()].filter(
      (ruling) => ruling.binding.frozen_proposal_hash === proposal.proposal_hash,
    )).toHaveLength(0);
  });

  it('allows new ingress after an open call expires while refusing its late admission and release', async () => {
    const h = await authorizationHarness();
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const first = await h.authorization.ingestConversationMessage(
      'w-demo',
      'case_demo',
      {
        message_id: 'msg_expired_call_one',
        turn_id: 'turn_expired_call_one',
        text: 'Synthetic first message before the orchestrator stops.',
      },
      claim,
    );
    const started = await h.authorization.beginModelCall(
      {
        worldId: 'w-demo',
        turnId: first.turn_id,
        selectionId: h.selectionId,
        ingressBinding: {
          message_id: first.message_id,
          message_item_id: first.message_item_id,
          conversation_version: first.conversation_version,
          message_digest: first.message_digest,
        },
      },
      claim,
    );
    h.setAt(new Date(Date.parse(started.call.expires_at) + 1).toISOString());
    await expect(
      h.authorization.ingestConversationMessage(
        'w-demo',
        'case_demo',
        {
          message_id: 'msg_expired_call_two',
          turn_id: 'turn_expired_call_two',
          text: 'Synthetic second message after the first call TTL.',
        },
        claim,
      ),
    ).resolves.toMatchObject({ conversation_version: 3 });
    await expect(
      h.authorization.admitModelOutput(
        'w-demo',
        started.call.call_id,
        {
          turn_id: started.call.turn_id,
          selection_id: started.call.selection_id,
          mandate_id: started.call.mandate_id,
          mandate_version: started.call.mandate_version,
          card_id: started.call.card_id,
          card_version: started.call.card_version,
          requested_id: started.call.requested_id,
          served_id: started.call.requested_id,
          projection_digest: started.call.projection_digest,
          content: 'Synthetic late output.',
        },
        claim,
      ),
    ).rejects.toMatchObject({ httpStatus: 422, responseCode: 'invalid-scope' });
    expect(h.store.snapshot().modelCalls.get(started.call.call_id)).toMatchObject({
      state: 'open',
      outcome: 'indeterminate',
    });
    expect(h.store.snapshot().outputReleases.size).toBe(0);
  });

  it('recovers a lost consume response by status only, without retransmitting content or retrying the provider', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = 'Synthetic output durably consumed before its HTTP response was lost.';
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content });
    let dropConsumeResponse = true;
    const lossyFetch: typeof fetch = async (input, init) => {
      const response = await fetch(input, init);
      const requested =
        typeof input === 'string' ? input : input instanceof URL ? input.href : input.url;
      if (dropConsumeResponse && requested.endsWith('/consume')) {
        dropConsumeResponse = false;
        await response.arrayBuffer();
        return new Response(JSON.stringify({ error: 'synthetic-post-commit-response-loss' }), {
          status: 500,
          headers: { 'content-type': 'application/json' },
        });
      }
      return response;
    };
    const lossyAuthorization = new OrchestratorAuthorizationHttpClient({
      origin: h.authorizationOrigin,
      token: ORCHESTRATOR_TOKEN,
      fetchImplementation: lossyFetch,
    });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: lossyAuthorization,
      lanes: [lane(provider)],
    });
    await expect(
      coordinator.runMessage(
        {
          messageId: 'msg_lost_release_response',
          text: 'Exercise status-only recovery with synthetic content.',
          turnId: 'turn_lost_release_response',
          selectionId: h.selectionId,
          cardId: h.mandateBody.default_acting_model.card_id,
          cardVersion: h.mandateBody.default_acting_model.card_version,
          requestedId: h.mandateBody.default_acting_model.requested_id,
          maxOutputTokens: 256,
        },
        { onBehalfOf: { role: 'case_officer', session_id: h.sessionId } },
      ),
    ).resolves.toMatchObject({ disposition: 'released', ingestion: { state: 'consumed' } });
    expect(provider.requests).toHaveLength(1);
    expect(coordinator.quarantine.size).toBe(0);
    const releaseRoutes = h.store
      .snapshot()
      .accessRecords.filter(
        (record): record is Extract<typeof record, { readonly route: string }> =>
          'route' in record && record.route.includes('/model-output-releases/'),
      );
    expect(releaseRoutes.map((record) => record.route)).toEqual([
      'POST /w/{world_id}/model-output-releases/{id}/consume',
      'GET /w/{world_id}/model-output-releases/{id}',
    ]);
  });

  it('fails closed without retransmission when conversation currentness changes after release issue', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const content = 'Synthetic output that must never enter the inferred store.';
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content });
    const authorization = new Proxy(h.authorization, {
      get(target, property, receiver) {
        if (property === 'admitModelOutput') {
          return async (...args: Parameters<ModelTurnAuthorizationClient['admitModelOutput']>) => {
            const result = await target.admitModelOutput(...args);
            await h.core.putConversationItems({
              caseId: 'case_demo',
              items: [
                {
                  id: 'said_release_race',
                  store: 'said',
                  turn: 'turn_release_race_external',
                  text: 'Synthetic authorization-owned mutation after release issue.',
                  provenance: { derived_from: [], hops: [] },
                  tags: ['conf:case', 'purpose:grant-assessment'],
                  origin_actor: 'officer',
                },
              ],
              actor: AUTHZ,
            });
            return result;
          };
        }
        const value = Reflect.get(target, property, receiver) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      },
    }) as unknown as ModelTurnAuthorizationClient;
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization,
      lanes: [lane(provider)],
    });
    await expect(
      coordinator.runMessage(
        {
          messageId: 'msg_release_race',
          text: 'Trigger the synthetic currentness race.',
          turnId: 'turn_release_race',
          selectionId: h.selectionId,
          cardId: h.mandateBody.default_acting_model.card_id,
          cardVersion: h.mandateBody.default_acting_model.card_version,
          requestedId: h.mandateBody.default_acting_model.requested_id,
          maxOutputTokens: 256,
        },
        { onBehalfOf: { role: 'case_officer', session_id: h.sessionId } },
      ),
    ).rejects.toMatchObject({ code: 'authorization-refused', providerDisclosure: 'confirmed' });
    expect(provider.requests).toHaveLength(1);
    expect(coordinator.quarantine.size).toBe(0);
    expect([...h.store.snapshot().outputReleases.values()]).toEqual([
      expect.objectContaining({ state: 'invalidated', invalidation_reason: 'conversation-items-put' }),
    ]);
    expect([...h.store.snapshot().storeItems.values()].some((entry) => entry.item.text === content)).toBe(false);
    const releaseRoutes = h.store
      .snapshot()
      .accessRecords.filter(
        (record): record is Extract<typeof record, { readonly route: string }> =>
          'route' in record && record.route.includes('/model-output-releases/'),
      );
    expect(releaseRoutes.map((record) => record.route)).toEqual([
      'POST /w/{world_id}/model-output-releases/{id}/consume',
    ]);
  });
});
