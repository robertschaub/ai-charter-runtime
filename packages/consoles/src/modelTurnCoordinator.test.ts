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
  ExecutionPreparationService,
  ScreeningCallService,
  proposalRevisionPreparationBlocksReplacement,
  digestFor,
  Keyring,
  loadPolicyFile,
  policySet,
  runSweeper,
  syntheticSystemUseForTests,
  storeItem,
  WalStore,
  type Mandate,
  type ScreeningResolution,
  type StoreItem,
} from 'gate-core';
import {
  EffectLedger,
  MockServicesHost,
  ServicesAuthorizationHttpClient,
  ServicesHttpServer,
} from 'services-mock';
import { ModelAdapterError, OpenAiCompatibleAdapter } from 'model-adapters';
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  ModelOutputQuarantine,
  ModelTurnCoordinator,
  ModelTurnError,
  type ModelTurnAuthorizationClient,
  type ModelTurnLaneConfig,
} from './modelTurnCoordinator.js';
import {
  OrchestratorAuthorizationHttpClient,
  OrchestratorServicesHttpClient,
  RuntimeDependencyError,
} from './runtimeHttpClients.js';

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
const SERVICES_HOST = { credential: 'proc:services_host', claimed_role: null } as const;
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

async function authorizationHarness(options: {
  readonly liveScreening?: boolean;
  readonly commitVerdict?: 'deny' | 'escalate';
  readonly preparationTtlMs?: number;
} = {}) {
  const root = mkdtempSync(join(tmpdir(), 'model-turn-coordinator-'));
  roots.push(root);
  let at = '2026-08-01T09:00:00.000Z';
  const buildDigest = digestFor('evaluator-build', { package: 'runtime-consoles', test: 'model-turn-coordinator' });
  const loadedPolicy = loadPolicyFile(POLICY_FILE, buildDigest);
  const changedPolicy = options.commitVerdict === undefined
    ? loadedPolicy.policy
    : policySet.parse({
        ...loadedPolicy.policy,
        rules: [
          ...loadedPolicy.policy.rules.map((rule) => rule.id !== 'allow-grant-filing'
            ? rule
            : options.commitVerdict === 'deny'
              ? {
                  ...rule,
                  verdict: 'deny',
                  ux_class: 'flag',
                  reason_template: 'Synthetic M6.2 policy denies Commit.',
                }
              : {
                  ...rule,
                  matcher: {
                    kind: 'all' as const,
                    matchers: [
                      rule.matcher,
                      {
                        kind: 'field' as const,
                        source: 'context' as const,
                        path: ['intervention_disposition'],
                        operator: 'exists' as const,
                        value: false,
                      },
                    ],
                  },
                  verdict: 'escalate',
                  ux_class: 'stop',
                  reason_template: 'Synthetic M6.2 policy escalates Commit.',
                  intervention_contract: loadedPolicy.policy.default_escalation_contract,
                }),
          ...(options.commitVerdict === 'escalate'
            ? [{
                id: 'allow-native-commit-disposition-evidence',
                priority: 200,
                gate: 'commit' as const,
                matcher: {
                  kind: 'field' as const,
                  source: 'context' as const,
                  path: ['intervention_disposition'],
                  operator: 'eq' as const,
                  value: 'allow-within-scope',
                },
                verdict: 'allow' as const,
                ux_class: 'silent' as const,
                reason_template: 'Synthetic disposition successor is evidence only.',
              }]
            : []),
        ],
      });
  const policy = changedPolicy === loadedPolicy.policy
    ? loadedPolicy
    : {
        ...loadedPolicy,
        policy: changedPolicy,
        policyContentDigest: digestFor('policy-set', changedPolicy),
      };
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
  const screeningByGate = new Map<'submit' | 'verify', ScreeningResolution>();
  let screeningCalls: ScreeningCallService | undefined;
  const core = new AuthorizationCore({
    store,
    keyring,
    policy,
    systemUse,
    resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
    resolveScreening: (proposal, gate, caseId) => options.liveScreening === true
      ? screeningCalls?.resolve(proposal, gate, caseId) ?? { performed: false, signals: [], evidenceRefs: [] }
      : screeningByGate.get(gate) ?? { performed: true, signals: [], evidenceRefs: [] },
    validateScreeningResolution: (resolution, proposal, gate, caseId, state, now) =>
      options.liveScreening === true && screeningCalls !== undefined && state !== undefined && now !== undefined
        ? screeningCalls.validate(resolution, proposal, gate, caseId, state, now)
        : true,
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
  let intakeSequence = 0;
  let proposalSequence = 0;
  let revisionPreparationSequence = 0;
  let revisionRunSequence = 0;
  const proposalIntakes = new ProposalIntakeService({
    store,
    cards,
    keyring,
    systemUse,
    caseId: 'case_demo',
    authorizationBootId: 'authz_boot_model_turn_1',
    now: () => at,
    nextIntakeId: () => (++intakeSequence === 1 ? 'pint_test_native' : `pint_test_native_${intakeSequence}`),
    nextProposalId: () => (++proposalSequence === 1 ? 'prp_test_native' : `prp_test_native_${proposalSequence}`),
    nextActionId: () => 'act_test_native',
    nextRevisionPreparationId: () =>
      ++revisionPreparationSequence === 1 ? 'rprep_test_native' : `rprep_test_native_${revisionPreparationSequence}`,
    nextRevisionRunId: () =>
      ++revisionRunSequence === 1 ? 'prun_test_revision' : `prun_test_revision_${revisionRunSequence}`,
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
  screeningCalls = new ScreeningCallService({
    store,
    projections,
    policy,
    authorizationBootId: 'authz_boot_model_turn_1',
    now: () => at,
  });
  const proposalPrecommit = new ProposalPrecommitService({
    store,
    authorization: core,
    proposalIntakes,
    ...(options.liveScreening === true ? { screeningCalls } : {}),
    now: () => at,
  });
  let executionPreparationSequence = 0;
  const executionPreparations = new ExecutionPreparationService({
    store,
    authorization: core,
    proposalIntakes,
    authorizationBootId: 'authz_boot_model_turn_1',
    authorizedAgentId: 'agent_demo',
    ...(options.preparationTtlMs === undefined ? {} : { ttlMs: options.preparationTtlMs }),
    now: () => at,
    nextId: () => ++executionPreparationSequence === 1
      ? 'xpr_test_native'
      : `xpr_test_native_${executionPreparationSequence}`,
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
    conversationTransport,
    proposalIntakes,
    proposalPrecommit,
    executionPreparations,
    screeningCalls,
    reads: {} as AuthorizationReadSide,
    adapter,
    keyring,
    caseHandoffs: handoffs,
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
    executionPreparations,
    handoffs,
    root,
    policy,
    buildDigest,
    closeAuthorization,
    setScreening(gate: 'submit' | 'verify', resolution: ScreeningResolution | null) {
      if (resolution === null) screeningByGate.delete(gate);
      else screeningByGate.set(gate, resolution);
    },
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

function screeningLane(provider: LoopbackProvider): ModelTurnLaneConfig {
  return {
    lane: 'openai',
    cardId: 'openai-gpt-5.5',
    cardVersion: 1,
    requestedId: 'gpt-5.5',
    adapter: new OpenAiCompatibleAdapter({
      lane: 'openai',
      baseUrl: provider.baseUrl,
      requestedModel: 'gpt-5.5',
      apiKey: 'test-loopback-screening-key',
      tokenParameter: 'max_completion_tokens',
      timeoutMs: 2_000,
    }),
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

  it('freezes one schema-bound proposal, reuses a durable precommit prefix on retry, and stops before Commit', async () => {
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

    // Simulate recovery after Authorize became durable but before Submit began.
    const durablePrefixState = h.store.snapshot();
    const durableProposal = durablePrefixState.proposals.get(outcome.proposal.proposal_id);
    const durableOrigin = durablePrefixState.proposalOrigins.get(outcome.proposal.proposal_id);
    if (durableProposal === undefined || durableOrigin === undefined) throw new Error('expected native proposal origin');
    const durableAuthorize = await h.core.ruleProposalWithCurrentness(
      {
        gate: 'authorize',
        proposal: durableProposal,
        service: durableOrigin.service,
        actionClass: durableOrigin.action_class,
        caseId: durableOrigin.case_id,
        actor: ORCHESTRATOR,
      },
      (lockedState, at) => h.proposalIntakes.assertProposalCurrent(
        lockedState,
        at,
        outcome.proposal.proposal_id,
      ),
    );
    expect(durableAuthorize.ruling.verdict).toBe('allow');

    const precommit = await h.authorization.runProposalPrecommit('w-demo', outcome.proposal.proposal_id, claim);
    expect(precommit.proposal_run_id).toBe('prun_native_test');
    expect(precommit.state).toBe('verified');
    expect(precommit.gates.map((entry) => entry.gate)).toEqual(['authorize', 'submit', 'verify']);
    const final = h.store.snapshot();
    expect([...final.rulings.values()].filter(
      (ruling) => ruling.gate === 'authorize' && ruling.binding.frozen_proposal_hash === durableProposal.proposal_hash,
    ).map((ruling) => ruling.ruling_id)).toEqual([durableAuthorize.ruling.ruling_id]);
    expect(final.actionRecords.filter(
      (record) => record.admissibility_decision.ruling_id === durableAuthorize.ruling.ruling_id,
    )).toHaveLength(1);
    expect([...final.rulings.values()].some((ruling) => ruling.gate === 'commit')).toBe(false);
    expect(final.reservations.size).toBe(0);
    expect(final.commitments.size).toBe(0);
    expect(final.effects.size).toBe(0);
    expect(final.screeningCalls.size).toBe(0);
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

  it('continues one verified native proposal through an atomic Commit and exactly one local mock effect', async () => {
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
      proposalRunId: 'prun_native_execution',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_native_execution',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const precommit = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(precommit).toMatchObject({ state: 'verified', execution: { state: 'available' } });

    const preparation = await h.authorization.prepareExecution('w-demo', 'case_demo', 'prun_native_execution', claim);
    await expect(
      h.authorization.prepareExecution('w-demo', 'case_demo', 'prun_native_execution', claim),
    ).resolves.toEqual(preparation);
    const durable = h.store.snapshot().executionPreparations.get(preparation.execution_preparation_id);
    const proposal = h.store.snapshot().proposals.get(frozen.proposal.proposal_id);
    const origin = h.store.snapshot().proposalOrigins.get(frozen.proposal.proposal_id);
    if (proposal === undefined || origin === undefined) throw new Error('expected native proposal lineage');
    expect(Object.keys(durable ?? {}).sort()).toContain('effect_intent_basis_digest');
    expect(durable?.effect_intent_basis_digest).toBe(digestFor('execution-effect-intent-basis', durable?.effect_intent_basis));
    expect(durable?.effect_intent_basis).toEqual({
      world_id: 'w-demo',
      frozen_proposal_hash: proposal.proposal_hash,
      service: h.mandateBody.connected_service,
      action_class: h.mandateBody.action_class,
      target: proposal.target,
      exact_parameters: proposal.exact_parameters,
      data_to_be_disclosed: proposal.data_to_be_disclosed,
    });
    await expect(h.core.ruleProposal({
      gate: 'commit',
      proposal,
      service: origin.service,
      actionClass: origin.action_class,
      caseId: origin.case_id,
      actor: ORCHESTRATOR,
    })).rejects.toMatchObject({ code: 'native-commit-requires-preparation' });
    expect([...h.store.snapshot().rulings.values()].filter((ruling) => ruling.gate === 'commit')).toHaveLength(0);

    const handler = vi.fn(() => ({ outcome: 'success' as const, detail: 'Synthetic native filing accepted.' }));
    const ledger = new EffectLedger({
      recordsRoot: join(h.root, 'services-ledger'),
      worldId: 'w-demo',
      bootId: 'services_boot_native',
      keyring: h.keyring,
      now: () => '2026-08-01T09:00:01.000Z',
    });
    const smuggledCommit = await fetch(
      new URL(
        `/w/w-demo/execution-preparations/${preparation.execution_preparation_id}/commit-verify`,
        h.authorizationOrigin,
      ),
      {
        method: 'POST',
        headers: {
          authorization: `Bearer ${ROLE_TOKENS.services}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          services_host_boot_id: ledger.bootId,
          services_ledger_id: ledger.ledgerId,
          proposal: { caller_asserted: true },
        }),
      },
    );
    expect(smuggledCommit.status).toBe(422);
    expect([...h.store.snapshot().rulings.values()].filter((ruling) => ruling.gate === 'commit')).toHaveLength(0);
    const servicesAuthorization = new ServicesAuthorizationHttpClient({
      origin: h.authorizationOrigin,
      token: ROLE_TOKENS.services,
    });
    const services = new MockServicesHost(
      ledger,
      servicesAuthorization,
      { [`${h.mandateBody.connected_service}:${h.mandateBody.action_class}`]: handler },
    );
    const servicesServer = new ServicesHttpServer({
      services,
      ledger,
      worldId: 'w-demo',
      orchestratorToken: '6'.repeat(64),
      authorizationToken: '7'.repeat(64),
      accessRecorder: servicesAuthorization,
      host: '127.0.0.1',
      port: 0,
    });
    const servicesAddress = await servicesServer.listen();
    closeables.push(() => servicesServer.close());
    const servicesClient = new OrchestratorServicesHttpClient({
      origin: servicesAddress.origin,
      token: '6'.repeat(64),
    });
    const [executed, concurrent] = await Promise.all([
      servicesClient.executePrepared('w-demo', preparation.execution_preparation_id),
      servicesClient.executePrepared('w-demo', preparation.execution_preparation_id),
    ]);
    expect(executed).toEqual({
      execution_preparation_id: preparation.execution_preparation_id,
      state: 'effect-recorded',
      effect_outcome: 'success',
      recorded_at: '2026-08-01T09:00:01.000Z',
    });
    expect(concurrent).toEqual(executed);
    const repeated = await servicesClient.executePrepared('w-demo', preparation.execution_preparation_id);
    expect(repeated).toEqual(executed);
    expect(handler).toHaveBeenCalledOnce();

    const final = h.store.snapshot();
    const commitRulings = [...final.rulings.values()].filter((ruling) =>
      ruling.gate === 'commit' && ruling.binding.frozen_proposal_hash === proposal.proposal_hash);
    expect(commitRulings).toHaveLength(1);
    expect(commitRulings[0]).toMatchObject({ verdict: 'allow', status: 'consumed' });
    expect(final.executionPreparations.get(preparation.execution_preparation_id)).toMatchObject({
      state: 'consumed',
      commit_ruling_id: commitRulings[0]!.ruling_id,
      effect_outcome: 'success',
      effect_recorded_at: '2026-08-01T09:00:01.000Z',
    });
    expect(final.commitments.size).toBe(1);
    expect(final.effects.size).toBe(1);
    await expect(h.core.commitVerify({
      rulingId: commitRulings[0]!.ruling_id,
      intent: {
        ...final.executionPreparations.get(preparation.execution_preparation_id)!.effect_intent_basis,
        ruling_id: commitRulings[0]!.ruling_id,
      },
      servicesHostBootId: ledger.bootId,
      servicesLedgerId: ledger.ledgerId,
      actor: SERVICES_HOST,
    })).resolves.toEqual({ ok: false, defect: 'native-proposal-requires-preparation' });

    const restartedHandler = vi.fn(() => ({ outcome: 'success' as const }));
    const restartedLedger = new EffectLedger({
      recordsRoot: join(h.root, 'services-ledger'),
      worldId: 'w-demo',
      bootId: 'services_boot_native_restart',
      keyring: h.keyring,
      now: () => '2026-08-01T09:00:02.000Z',
    });
    expect(restartedLedger.ledgerId).toBe(ledger.ledgerId);
    const restartedServices = new MockServicesHost(
      restartedLedger,
      servicesAuthorization,
      { [`${h.mandateBody.connected_service}:${h.mandateBody.action_class}`]: restartedHandler },
    );
    await expect(restartedServices.executePrepared('w-demo', preparation.execution_preparation_id)).resolves.toEqual(executed);
    expect(restartedHandler).not.toHaveBeenCalled();

    const wal = readFileSync(join(h.root, 'w-demo', 'wal.jsonl'), 'utf8');
    expect(wal).not.toContain('commit_token');
    expect(wal).not.toContain('raw_mac');
    expect(JSON.stringify(final.accessRecords)).not.toContain('commit_token');
    await h.closeAuthorization();
    h.store.close();
    const replayedStore = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_native_execution_replay',
      bootId: 'authz_boot_native_execution_replay',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.buildDigest,
      now: () => '2026-08-01T09:00:02.000Z',
    });
    stores.push(replayedStore);
    const replayed = replayedStore.snapshot();
    expect(replayed.executionPreparations.get(preparation.execution_preparation_id)).toEqual(
      final.executionPreparations.get(preparation.execution_preparation_id),
    );
    expect(replayed.rulings.get(commitRulings[0]!.ruling_id)).toEqual(commitRulings[0]);
    expect(replayed.commitments.size).toBe(1);
    expect(replayed.effects.size).toBe(1);
  });

  it.each(['deny', 'escalate'] as const)(
    'consumes a preparation on Commit %s without returning a token or invoking a service handler',
    async (commitVerdict) => {
      const h = await authorizationHarness({ commitVerdict });
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
        proposalRunId: `prun_native_${commitVerdict}`,
        conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
        turnId: `turn_native_${commitVerdict}`,
        selectionId: h.selectionId,
        cardId: h.mandateBody.default_acting_model.card_id,
        cardVersion: h.mandateBody.default_acting_model.card_version,
        requestedId: h.mandateBody.default_acting_model.requested_id,
      }, { onBehalfOf: claim });
      await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
      const preparation = await h.authorization.prepareExecution(
        'w-demo',
        'case_demo',
        `prun_native_${commitVerdict}`,
        claim,
      );
      const handler = vi.fn(() => ({ outcome: 'success' as const }));
      const ledger = new EffectLedger({
        recordsRoot: join(h.root, `services-ledger-${commitVerdict}`),
        worldId: 'w-demo',
        bootId: `services_boot_${commitVerdict}`,
        keyring: h.keyring,
        now: () => '2026-08-01T09:00:01.000Z',
      });
      const services = new MockServicesHost(ledger, {
        commitVerify: (input) => h.core.commitVerify(input),
        commitVerifyPreparation: (_worldId, preparationId, bootId, ledgerId) =>
          h.executionPreparations.commitVerify(preparationId, bootId, ledgerId, SERVICES_HOST),
        reportEffectOutcome: (input) => h.core.reportEffectOutcome(input),
      }, { [`${h.mandateBody.connected_service}:${h.mandateBody.action_class}`]: handler });
      const result = await services.executePrepared('w-demo', preparation.execution_preparation_id);
      expect(result).toEqual({
        execution_preparation_id: preparation.execution_preparation_id,
        state: commitVerdict === 'deny' ? 'commit-denied' : 'commit-escalated',
        effect_outcome: null,
        recorded_at: null,
      });
      expect(JSON.stringify(result)).not.toContain('token');
      expect(handler).not.toHaveBeenCalled();
      const state = h.store.snapshot();
      const commitRulings = [...state.rulings.values()].filter((ruling) => ruling.gate === 'commit');
      expect(commitRulings).toHaveLength(1);
      expect(commitRulings[0]?.verdict).toBe(commitVerdict);
      expect(state.executionPreparations.get(preparation.execution_preparation_id)).toMatchObject({
        state: 'consumed',
        commit_ruling_id: commitRulings[0]?.ruling_id,
        commitment_id: null,
      });
      expect(state.escalations.size).toBe(commitVerdict === 'escalate' ? 1 : 0);
      expect(state.commitments.size).toBe(0);
      expect(state.effects.size).toBe(0);
      if (commitVerdict === 'escalate') {
        const escalation = [...state.escalations.values()][0];
        if (escalation === undefined) throw new Error('expected native Commit escalation');
        const disposed = await h.core.disposeEscalation({
          escalationId: escalation.escalation_id,
          disposition: 'allow-within-scope',
          actor: PRINCIPAL,
        });
        expect(disposed).toMatchObject({
          accepted: true,
          successor: { ruling: { gate: 'commit', verdict: 'allow' } },
        });
        if (!disposed.accepted || disposed.successor === null) throw new Error('expected native Commit successor evidence');
        await expect(h.core.commitVerify({
          rulingId: disposed.successor.ruling.ruling_id,
          intent: {
            ...state.executionPreparations.get(preparation.execution_preparation_id)!.effect_intent_basis,
            ruling_id: disposed.successor.ruling.ruling_id,
          },
          servicesHostBootId: ledger.bootId,
          servicesLedgerId: ledger.ledgerId,
          actor: SERVICES_HOST,
        })).resolves.toEqual({ ok: false, defect: 'native-proposal-requires-preparation' });
        expect(h.store.snapshot().commitments.size).toBe(0);
        expect(h.store.snapshot().effects.size).toBe(0);
      }
    },
  );

  it('recovers a lost outcome-report request from the one durable services ledger effect without rerunning it', async () => {
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
      proposalRunId: 'prun_native_report_recovery',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_native_report_recovery',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    const preparation = await h.authorization.prepareExecution(
      'w-demo',
      'case_demo',
      'prun_native_report_recovery',
      claim,
    );
    const handler = vi.fn(() => ({ outcome: 'success' as const, detail: 'One durable synthetic effect.' }));
    const ledger = new EffectLedger({
      recordsRoot: join(h.root, 'services-ledger-report-recovery'),
      worldId: 'w-demo',
      bootId: 'services_boot_report_recovery',
      keyring: h.keyring,
      now: () => '2026-08-01T09:00:01.000Z',
    });
    let reportAttempts = 0;
    const services = new MockServicesHost(ledger, {
      commitVerify: (input) => h.core.commitVerify(input),
      commitVerifyPreparation: (_worldId, preparationId, bootId, ledgerId) =>
        h.executionPreparations.commitVerify(preparationId, bootId, ledgerId, SERVICES_HOST),
      reportEffectOutcome: async (input) => {
        reportAttempts += 1;
        if (reportAttempts === 1) throw new Error('synthetic lost outcome-report request');
        return h.core.reportEffectOutcome(input);
      },
    }, { [`${h.mandateBody.connected_service}:${h.mandateBody.action_class}`]: handler });

    await expect(services.executePrepared('w-demo', preparation.execution_preparation_id)).rejects.toThrow(
      'synthetic lost outcome-report request',
    );
    expect(handler).toHaveBeenCalledOnce();
    const afterLoss = h.store.snapshot();
    const commitment = [...afterLoss.commitments.values()][0];
    expect(commitment).toBeDefined();
    expect(afterLoss.executionPreparations.get(preparation.execution_preparation_id)).toMatchObject({
      state: 'consumed',
      effect_outcome: null,
    });
    expect(afterLoss.effects.size).toBe(0);
    expect(ledger.probe(commitment!.idempotency_key).state).toBe('recorded');

    await expect(services.executePrepared('w-demo', preparation.execution_preparation_id)).resolves.toEqual({
      execution_preparation_id: preparation.execution_preparation_id,
      state: 'effect-recorded',
      effect_outcome: 'success',
      recorded_at: '2026-08-01T09:00:01.000Z',
    });
    expect(handler).toHaveBeenCalledOnce();
    expect(reportAttempts).toBe(2);
    expect(h.store.snapshot().effects.size).toBe(1);
  });

  it('expires and replaces a stale preparation, then fail-stops a live replacement on authorization restart', async () => {
    const h = await authorizationHarness({ preparationTtlMs: 1_000 });
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
      proposalRunId: 'prun_native_expiry',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_native_expiry',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    const first = await h.authorization.prepareExecution('w-demo', 'case_demo', 'prun_native_expiry', claim);
    h.setAt('2026-08-01T09:00:01.001Z');
    await expect(h.executionPreparations.commitVerify(
      first.execution_preparation_id,
      'services_boot_expiry',
      'services_ledger_expiry',
      SERVICES_HOST,
    )).rejects.toMatchObject({ code: 'unavailable' });
    expect(h.executionPreparations.statusByRun('case_demo', 'prun_native_expiry', ORCHESTRATOR)).toMatchObject({
      state: 'unavailable',
      execution_preparation_id: first.execution_preparation_id,
    });
    expect([...h.store.snapshot().rulings.values()].filter((ruling) => ruling.gate === 'commit')).toHaveLength(0);

    const replacement = await h.authorization.prepareExecution('w-demo', 'case_demo', 'prun_native_expiry', claim);
    expect(replacement.execution_preparation_id).not.toBe(first.execution_preparation_id);
    expect(h.store.snapshot().executionPreparations.get(first.execution_preparation_id)?.state).toBe('expired');
    expect(h.store.snapshot().executionPreparations.get(replacement.execution_preparation_id)?.state).toBe('issued');

    const restarted = new ExecutionPreparationService({
      store: h.store,
      authorization: h.core,
      proposalIntakes: h.proposalIntakes,
      authorizationBootId: 'authz_boot_model_turn_restart',
      authorizedAgentId: 'agent_demo',
    });
    await expect(restarted.expire()).resolves.toBe(1);
    expect(h.store.snapshot().executionPreparations.get(replacement.execution_preparation_id)).toMatchObject({
      state: 'expired',
    });
    expect(h.store.snapshot().commitments.size).toBe(0);
    expect(h.store.snapshot().effects.size).toBe(0);
  });

  it('durably invalidates an issued preparation when maintenance expires any bound precommit ruling', async () => {
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
      proposalRunId: 'prun_native_ruling_expiry',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_native_ruling_expiry',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    const preparation = await h.authorization.prepareExecution(
      'w-demo',
      'case_demo',
      'prun_native_ruling_expiry',
      claim,
    );
    const state = h.store.snapshot();
    const bound = state.executionPreparations.get(preparation.execution_preparation_id);
    if (bound === undefined) throw new Error('expected issued execution preparation');
    const expiry = state.rulings.get(bound.authorize_ruling_id)?.binding.validity_window.not_after;
    if (expiry === undefined) throw new Error('expected bound Authorize ruling');
    h.setAt(expiry);
    await runSweeper(h.store, h.keyring, h.policy, h.systemUse);
    expect(h.store.snapshot().executionPreparations.get(preparation.execution_preparation_id)).toMatchObject({
      state: 'invalidated',
      invalidation_reason: 'precommit-ruling-expired',
    });
    expect([...h.store.snapshot().rulings.values()].filter((ruling) => ruling.gate === 'commit')).toHaveLength(0);
    expect(h.store.snapshot().commitments.size).toBe(0);
    expect(h.store.snapshot().effects.size).toBe(0);
  });

  it('pauses fixed precommit for two authorization-owned live screening calls and resumes without caller gate control', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    const proposalContent = nativeProposalContent();
    const submitRaw = '[ \n ]';
    const verifyRaw = '[\n  ]';
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: proposalContent });
    provider.enqueue({ model: 'gpt-5.5-2026-04-23', content: submitRaw });
    provider.enqueue({ model: 'gpt-5.5-2026-04-23', content: verifyRaw });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_proposal',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });

    const [first, concurrent] = await Promise.all([
      h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim),
      h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim),
    ]);
    expect(first.kind).toBe('proposal_precommit_screening_required');
    expect(concurrent.kind).toBe('proposal_precommit_screening_required');
    if (
      first.kind !== 'proposal_precommit_screening_required' ||
      concurrent.kind !== 'proposal_precommit_screening_required'
    ) throw new Error('expected Submit screening pause');
    expect(first.current_gate).toBe('submit');
    expect(concurrent.screening_call.call_id).toBe(first.screening_call.call_id);
    expect(first.gates.map((entry) => entry.gate)).toEqual(['authorize']);
    expect(Object.keys(first.screening_call).sort()).toEqual([
      'call_id', 'card_id', 'card_version', 'expires_at', 'gate', 'kind', 'max_output_tokens',
      'projection', 'proposal_id', 'proposal_run_id', 'requested_id', 'response_schema_digest',
      'response_schema_id', 'tools_allowed',
    ]);
    expect(first.screening_call).toMatchObject({
      card_id: 'openai-gpt-5.5',
      requested_id: 'gpt-5.5',
      max_output_tokens: 512,
      tools_allowed: false,
      projection: { role: 'screening', items: [{ id: 'said_public' }] },
    });
    expect(h.store.snapshot().screeningCalls.size).toBe(1);

    const submitTerminal = await coordinator.runScreening(first.screening_call, { onBehalfOf: claim });
    expect(submitTerminal).toMatchObject({ outcome: 'admitted', gate: 'submit', served_id: 'gpt-5.5-2026-04-23' });
    await expect(
      h.authorization.admitScreeningOutput(
        'w-demo',
        first.screening_call.call_id,
        { content: submitRaw, served_id: 'gpt-5.5-2026-04-23' },
        claim,
      ),
    ).resolves.toEqual(submitTerminal);

    const second = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(second.kind).toBe('proposal_precommit_screening_required');
    if (second.kind !== 'proposal_precommit_screening_required') throw new Error('expected Verify screening pause');
    expect(second.current_gate).toBe('verify');
    expect(second.gates.map((entry) => entry.gate)).toEqual(['authorize', 'submit']);
    expect(second.screening_call.call_id).not.toBe(first.screening_call.call_id);
    const verifyTerminal = await coordinator.runScreening(second.screening_call, { onBehalfOf: claim });
    expect(verifyTerminal).toMatchObject({ outcome: 'admitted', gate: 'verify' });

    const final = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(final.kind).toBe('proposal_precommit_status');
    expect(final.state).toBe('verified');
    expect(final.gates.map((entry) => entry.gate)).toEqual(['authorize', 'submit', 'verify']);
    expect(provider.requests).toHaveLength(3);
    for (const request of provider.requests.slice(1)) {
      expect(request).toMatchObject({
        model: 'gpt-5.5',
        max_completion_tokens: 512,
        response_format: { type: 'json_schema', json_schema: { name: 'screening_signals', strict: true } },
      });
      expect(request).not.toHaveProperty('tools');
    }
    const snapshot = h.store.snapshot();
    expect([...snapshot.screeningCalls.values()].map((call) => ({ gate: call.gate, outcome: call.outcome }))).toEqual([
      { gate: 'submit', outcome: 'admitted' },
      { gate: 'verify', outcome: 'admitted' },
    ]);
    expect([...snapshot.rulings.values()].some((ruling) => ruling.gate === 'commit')).toBe(false);
    expect(snapshot.reservations.size).toBe(0);
    expect(snapshot.commitments.size).toBe(0);
    expect(snapshot.effects.size).toBe(0);
    const wal = readFileSync(join(h.root, 'w-demo', 'wal.jsonl'), 'utf8');
    expect(wal).not.toContain(JSON.stringify(submitRaw).slice(1, -1));
    expect(wal).not.toContain(JSON.stringify(verifyRaw).slice(1, -1));
    expect(JSON.stringify(snapshot.accessRecords)).not.toContain(submitRaw);
    expect(JSON.stringify(snapshot.accessRecords)).not.toContain(verifyRaw);

    await h.closeAuthorization();
    h.store.close();
    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_live_screening_replay',
      bootId: 'authz_boot_live_screening_replay',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.buildDigest,
      now: () => '2026-08-01T09:00:00.000Z',
    });
    stores.push(reopened);
    expect([...reopened.snapshot().screeningCalls.values()].map((call) => ({ gate: call.gate, outcome: call.outcome }))).toEqual([
      { gate: 'submit', outcome: 'admitted' },
      { gate: 'verify', outcome: 'admitted' },
    ]);
  });

  it('durably fails an empty authorization projection closed without disclosing to the screening provider', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    provider.enqueue({
      model: h.mandateBody.default_acting_model.requested_id,
      content: nativeProposalContent({ material_input_ids: ['said_3'] }),
    });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_empty_projection',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_empty_projection',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });

    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped).toMatchObject({ kind: 'proposal_precommit_status', state: 'escalated' });
    const state = h.store.snapshot();
    expect([...state.screeningCalls.values()]).toHaveLength(1);
    expect([...state.screeningCalls.values()][0]).toMatchObject({
      gate: 'submit',
      projection_item_count: 0,
      projection_item_ids: [],
      outcome: 'failed',
      failure_reason: 'authorization-invalidated',
      provider_disclosure: 'possible',
      signals: [],
    });
    expect([...state.rulings.values()].find((ruling) => ruling.gate === 'submit')).toMatchObject({
      verdict: 'escalate',
      matched_rule_id: 'default:required-screening-missing',
    });
    expect(provider.requests).toHaveLength(1);
    expect(state.reservations.size).toBe(0);
    expect(state.commitments.size).toBe(0);
    expect(state.effects.size).toBe(0);
  });

  it('terminalizes duplicate-key screening output as malformed and fails required screening closed without a signal path', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    const proposalContent = nativeProposalContent();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: proposalContent });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_malformed',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_malformed',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');
    const raw = '[{"signal":"evidence_conflict","signal":"scope_drift","suspect_item_id":"said_public","confidence_pct":100,"rationale":"must not persist"}]';
    const failed = await h.authorization.admitScreeningOutput(
      'w-demo',
      paused.screening_call.call_id,
      { content: raw, served_id: 'gpt-5.5-2026-04-23' },
      claim,
    );
    expect(failed).toMatchObject({ outcome: 'failed', failure_reason: 'malformed-response', gate: 'submit' });
    await expect(
      h.authorization.admitScreeningOutput(
        'w-demo',
        paused.screening_call.call_id,
        { content: raw, served_id: 'gpt-5.5-2026-04-23' },
        claim,
      ),
    ).resolves.toEqual(failed);
    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped.kind).toBe('proposal_precommit_status');
    expect(stopped.state).toBe('escalated');
    const state = h.store.snapshot();
    const submit = [...state.rulings.values()].find((ruling) => ruling.gate === 'submit');
    expect(submit).toMatchObject({ verdict: 'escalate', matched_rule_id: 'default:required-screening-missing' });
    expect(submit?.evidence_refs.some((entry) => entry.kind === 'screening_signal')).toBe(false);
    expect([...state.screeningCalls.values()]).toHaveLength(1);
    expect([...state.screeningCalls.values()][0]).toMatchObject({ outcome: 'failed', signals: [] });
    expect(provider.requests).toHaveLength(1);
    const wal = readFileSync(join(h.root, 'w-demo', 'wal.jsonl'), 'utf8');
    expect(wal).not.toContain('must not persist');
    expect(JSON.stringify(state.accessRecords)).not.toContain('must not persist');
  });

  it('rejects a model-selected suspect outside the authorization projection before it can become ruling evidence', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: nativeProposalContent() });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_outside',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_outside',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');
    const raw = JSON.stringify([{
      signal: 'evidence_conflict',
      suspect_item_id: 'said_not_in_projection',
      confidence_pct: 100,
      rationale: 'Model-selected out-of-scope item.',
    }]);
    const terminal = await h.authorization.admitScreeningOutput(
      'w-demo',
      paused.screening_call.call_id,
      { content: raw, served_id: 'gpt-5.5-2026-04-23' },
      claim,
    );
    expect(terminal).toMatchObject({ outcome: 'failed', failure_reason: 'malformed-response' });
    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped.state).toBe('escalated');
    const state = h.store.snapshot();
    expect([...state.rulings.values()].flatMap((ruling) => ruling.evidence_refs).some(
      (evidence) => evidence.kind === 'screening_signal',
    )).toBe(false);
    expect(JSON.stringify(state.accessRecords)).not.toContain('Model-selected out-of-scope item.');
  });

  it('fails a substituted served-model identity before screening evidence can be admitted', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: nativeProposalContent() });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_model_mismatch',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_model_mismatch',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');
    await expect(h.authorization.admitScreeningOutput(
      'w-demo',
      paused.screening_call.call_id,
      { content: '[]', served_id: 'substitute-model' },
      claim,
    )).resolves.toMatchObject({
      outcome: 'failed',
      failure_reason: 'authorization-invalidated',
      served_id: 'substitute-model',
    });

    const state = h.store.snapshot();
    expect([...state.screeningCalls.values()][0]).toMatchObject({ model_resolution: 'mismatch', signals: [] });
    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped).toMatchObject({ state: 'escalated' });
    expect([...h.store.snapshot().rulings.values()].some((ruling) =>
      ruling.evidence_refs.some((evidence) => evidence.kind === 'screening_signal'))).toBe(false);
  });

  it('normalizes an admitted live signal as evidence that can only raise allow to escalation', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: nativeProposalContent() });
    provider.enqueue({
      model: 'gpt-5.5-2026-04-23',
      content: JSON.stringify([{
        signal: 'injection_suspicion',
        suspect_item_id: 'said_public',
        confidence_pct: 87,
        rationale: 'Synthetic model-generated signal rationale.',
      }]),
    });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_signal',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_signal',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');
    await coordinator.runScreening(paused.screening_call, { onBehalfOf: claim });
    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped.state).toBe('escalated');
    const state = h.store.snapshot();
    const submit = [...state.rulings.values()].find((ruling) => ruling.gate === 'submit');
    expect(submit).toMatchObject({ verdict: 'escalate', matched_rule_id: 'escalate-submit-signal' });
    expect(submit?.evidence_refs).toContainEqual({
      kind: 'screening_signal',
      signal: 'injection_suspicion',
      suspect_item_id: 'said_public',
      confidence_pct: 87,
      rationale: 'Synthetic model-generated signal rationale.',
      model_id: 'gpt-5.5',
      model_version_reported: 'gpt-5.5-2026-04-23',
    });
    expect([...state.rulings.values()].some((ruling) => ruling.verdict === 'allow' &&
      ruling.evidence_refs.some((evidence) => evidence.kind === 'screening_signal'))).toBe(false);
    expect(state.reservations.size).toBe(0);
    expect(state.commitments.size).toBe(0);
    expect(state.effects.size).toBe(0);
  });

  it('records one closed screening-provider failure and refuses a second provider attempt for the same call', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: nativeProposalContent() });
    provider.enqueue({ status: 503, rawBody: '{"error":"synthetic outage detail must not persist"}' });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_failure',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_failure',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');
    const failed = await coordinator.runScreening(paused.screening_call, { onBehalfOf: claim });
    expect(failed).toMatchObject({
      outcome: 'failed',
      failure_reason: 'provider-unavailable',
      provider_disclosure: 'confirmed',
      served_id: null,
    });
    await expect(coordinator.runScreening(paused.screening_call, { onBehalfOf: claim })).rejects.toMatchObject({
      code: 'turn-replay',
    });
    expect(provider.requests).toHaveLength(2);
    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped.state).toBe('escalated');
    const state = h.store.snapshot();
    expect([...state.rulings.values()].find((ruling) => ruling.gate === 'submit')).toMatchObject({
      verdict: 'escalate',
      matched_rule_id: 'default:required-screening-missing',
    });
    const serialized = JSON.stringify({
      screening: [...state.screeningCalls.values()],
      access: state.accessRecords,
    });
    expect(serialized).not.toContain('synthetic outage detail');
  });

  it('records an unavailable configured screening lane as a terminal failure without a provider attempt', async () => {
    const h = await authorizationHarness({ liveScreening: true });
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
      proposalRunId: 'prun_live_screening_lane_unavailable',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_lane_unavailable',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');

    await expect(coordinator.runScreening(paused.screening_call, { onBehalfOf: claim })).resolves.toMatchObject({
      outcome: 'failed',
      failure_reason: 'provider-unavailable',
      provider_disclosure: 'possible',
      served_id: null,
    });
    expect(provider.requests).toHaveLength(1);
    await expect(coordinator.runScreening(paused.screening_call, { onBehalfOf: claim })).rejects.toMatchObject({ code: 'turn-replay' });
    await expect(
      h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim),
    ).resolves.toMatchObject({ state: 'escalated' });
  });

  it('terminalizes a screening response that exceeds the byte ceiling before admission transport', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: nativeProposalContent() });
    provider.enqueue({ model: 'gpt-5.5-2026-04-23', content: 'é'.repeat(32_769) });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_oversize',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_oversize',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');

    await expect(coordinator.runScreening(paused.screening_call, { onBehalfOf: claim })).resolves.toMatchObject({
      outcome: 'failed',
      failure_reason: 'malformed-response',
      provider_disclosure: 'confirmed',
      served_id: 'gpt-5.5-2026-04-23',
      output_digest: null,
    });
    const state = h.store.snapshot();
    expect(JSON.stringify({ calls: [...state.screeningCalls.values()], access: state.accessRecords })).not.toContain('é');
    await expect(
      h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim),
    ).resolves.toMatchObject({ state: 'escalated' });
  });

  it('revalidates admitted screening inside the ruling lock and durably invalidates an expired binding', async () => {
    const h = await authorizationHarness({ liveScreening: true });
    const provider = await loopbackProvider();
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: nativeProposalContent() });
    provider.enqueue({ model: 'gpt-5.5-2026-04-23', content: '[]' });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider), screeningLane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_live_screening_expired',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_live_screening_expired',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    const paused = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    if (paused.kind !== 'proposal_precommit_screening_required') throw new Error('expected Submit screening pause');
    await coordinator.runScreening(paused.screening_call, { onBehalfOf: claim });
    expect([...h.store.snapshot().screeningCalls.values()][0]).toMatchObject({ outcome: 'admitted' });
    h.setAt('2026-08-01T09:01:01.000Z');
    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped.state).toBe('escalated');
    const state = h.store.snapshot();
    expect([...state.screeningCalls.values()][0]).toMatchObject({
      outcome: 'failed',
      failure_reason: 'authorization-invalidated',
      signals: [],
    });
    expect([...state.rulings.values()].find((ruling) => ruling.gate === 'submit')).toMatchObject({
      verdict: 'escalate',
      matched_rule_id: 'default:required-screening-missing',
    });
  });

  it('runs the bounded dialogue continuation through a semantic-only revision and re-gates without Commit', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    const initialContent = nativeProposalContent({
      material_input_ids: ['said_public'],
      derived_claim_ids: ['inf_7'],
    });
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: initialContent });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    let claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozenInitial = await coordinator.runProposal(
      {
        proposalRunId: 'prun_dialogue_source',
        conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
        turnId: 'turn_dialogue_source',
        selectionId: h.selectionId,
        cardId: h.mandateBody.default_acting_model.card_id,
        cardVersion: h.mandateBody.default_acting_model.card_version,
        requestedId: h.mandateBody.default_acting_model.requested_id,
      },
      { onBehalfOf: claim },
    );
    h.setScreening('verify', {
      performed: true,
      signals: [{
        kind: 'screening_signal',
        signal: 'unconfirmed_inference_as_fact',
        suspect_item_id: 'inf_7',
        confidence_pct: 100,
        rationale: '<b>model prose must not become the question</b>',
        model_id: 'screening-model',
        model_version_reported: 'screening-model-v1',
      }],
      evidenceRefs: [],
    });
    const stopped = await h.authorization.runProposalPrecommit(
      'w-demo',
      frozenInitial.proposal.proposal_id,
      claim,
    );
    expect(stopped.state).toBe('escalated');
    if (stopped.kind !== 'proposal_precommit_status') throw new Error('expected terminal precommit status');
    expect(stopped.continuation).toEqual({ state: 'response-required', source_proposal_run_id: null });
    const sourceState = h.store.snapshot();
    const sourceEscalation = [...sourceState.escalations.values()].find(
      (candidate) => candidate.escalation_id === stopped.escalation_id,
    );
    if (sourceEscalation === undefined) throw new Error('expected bounded dialogue escalation');
    expect(sourceEscalation.dialogue_item_ref).toBe('inf_7');
    expect(sourceEscalation.contract).toEqual({
      trigger_and_state: { trigger: 'unconfirmed-inference-as-fact', state: 'open' },
      decision_and_route: {
        eligible_role: 'case_officer',
        standing_class: 'third-party-fact',
        competence_declared: 'Assigned case officer for the synthetic demo (declared, not verified).',
        independence_declared: 'Not independently verified in this POC.',
        substitute_roles: ['principal'],
        substitute_rule: 'The principal may respond only under the same standing and cannot manufacture a third-party fact.',
      },
      decision_basis_shown: ['frozen-proposal-inference', 'current-evidence-status'],
      response_bound_and_default: {
        response_bound_ms: 900000,
        safe_default: {
          kind: 'stop-remains',
          disposition: 'abstain',
          authority_basis: { kind: 'no-new-authority' },
          reversible: true,
        },
      },
      permitted_dispositions: ['confirm', 'correct', 'narrow', 'abstain', 'route'],
      record_and_feedback: {
        record_events: ['dialogue_trigger_raised', 'dialogue_response_recorded'],
        feedback_consequence: 'Increment the dialogue ask-rate counter.',
      },
    });
    const sourceRuling = sourceState.rulings.get(sourceEscalation.ruling_id);
    expect(sourceRuling?.reason).toBe(
      'What cited evidence confirms, corrects, or narrows this inference: "The synthetic applicant entity is no more than three years old."?',
    );
    expect(sourceRuling?.reason).not.toContain('<b>');
    await expect(h.core.respondDialogue({
      escalationId: sourceEscalation.escalation_id,
      disposition: 'confirm',
      scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
      actor: CASE_OFFICER,
    })).resolves.toMatchObject({ accepted: false, defect: 'evidence-required' });
    await expect(h.core.respondDialogue({
      escalationId: sourceEscalation.escalation_id,
      disposition: 'narrow',
      answerText: 'Caller-selected scope must not redirect the bounded dialogue.',
      scope: { item_ref: 'said_public', applies_to: 'this_case_only' },
      actor: CASE_OFFICER,
    })).resolves.toMatchObject({ accepted: false, defect: 'invalid-response' });
    const response = await h.core.respondDialogue({
      escalationId: sourceEscalation.escalation_id,
      disposition: 'narrow',
      answerText: 'The synthetic registration date remains unconfirmed and must be treated as an applicant assertion.',
      scope: { item_ref: 'inf_7', applies_to: 'this_case_only' },
      actor: CASE_OFFICER,
    });
    expect(response).toMatchObject({ accepted: true, status: 'disposed' });
    expect(h.store.snapshot().storeItems.has('inf_7')).toBe(false);

    const revisionPreparationPath = '/w/w-demo/cases/case_demo/proposal-runs/prun_dialogue_source/revision-preparations';
    const revisionHeaders = {
      authorization: `Bearer ${ORCHESTRATOR_TOKEN}`,
      'content-type': 'application/json',
      'x-on-behalf-of-role': 'case_officer',
      'x-session-id': h.sessionId,
    };
    expect((await fetch(new URL(revisionPreparationPath, h.authorizationOrigin), {
      method: 'POST',
      headers: { ...revisionHeaders, origin: 'http://foreign.invalid' },
      body: '{}',
    })).status).toBe(403);
    expect((await fetch(new URL(revisionPreparationPath, h.authorizationOrigin), {
      method: 'POST',
      headers: { ...revisionHeaders, origin: 'http://127.0.0.1:7801' },
      body: JSON.stringify({ response: 'caller-asserted' }),
    })).status).toBe(422);

    const firstPrepared = await h.authorization.prepareProposalRevision(
      'w-demo',
      'case_demo',
      'prun_dialogue_source',
      claim,
    );
    expect(Object.keys(firstPrepared).sort()).toEqual([
      'expires_at', 'issued_at', 'kind', 'preparation_id', 'proposal_run_id', 'source_proposal_run_id', 'target',
    ]);
    expect(firstPrepared).toMatchObject({
      preparation_id: 'rprep_test_native',
      proposal_run_id: 'prun_test_revision',
      source_proposal_run_id: 'prun_dialogue_source',
    });
    expect(h.store.snapshot().accessRecords.find(
      (record) => 'operation_evidence' in record &&
        record.operation_evidence?.kind === 'proposal_revision_preparation' &&
        record.operation_evidence.preparation_id === firstPrepared.preparation_id,
    )).toMatchObject({
      route: 'POST /w/{world_id}/cases/{case_id}/proposal-runs/{id}/revision-preparations',
      authenticated_actor: 'proc:orchestrator',
      outcome: 'served',
      http_status: 201,
      operation_evidence: firstPrepared,
    });
    await expect(h.authorization.prepareProposalRevision(
      'w-demo',
      'case_demo',
      'prun_dialogue_source',
      claim,
    )).resolves.toEqual(firstPrepared);

    const replacementHandoff = await h.handoffs.mint('case_demo', CASE_OFFICER);
    const { expires_at: ignoredReplacementExpiry, ...replacementInput } = replacementHandoff;
    void ignoredReplacementExpiry;
    const replacementSessionId = 'session_dialogue_replacement';
    await h.handoffs.redeem(
      { ...replacementInput, session_id: replacementSessionId },
      ORCHESTRATOR,
    );
    const replacementClaim = { role: 'case_officer' as const, session_id: replacementSessionId };
    await expect(h.authorization.prepareProposalRevision(
      'w-demo',
      'case_demo',
      'prun_dialogue_source',
      replacementClaim,
    )).rejects.toMatchObject({ httpStatus: 409 });
    await h.handoffs.closeSession(h.sessionId, ORCHESTRATOR);
    expect(h.store.snapshot().proposalRevisionPreparations.get(firstPrepared.preparation_id)).toMatchObject({
      state: 'invalidated',
      invalidation_reason: 'session-ended',
    });
    claim = replacementClaim;
    const prepared = await h.authorization.prepareProposalRevision(
      'w-demo',
      'case_demo',
      'prun_dialogue_source',
      claim,
    );
    expect(prepared).toMatchObject({
      preparation_id: 'rprep_test_native_2',
      proposal_run_id: 'prun_test_revision_2',
      source_proposal_run_id: 'prun_dialogue_source',
    });

    const revisionContent = nativeProposalContent({
      declared_objective: 'File the narrowed synthetic grant application.',
      material_input_ids: ['said_public'],
      derived_claim_ids: [],
    });
    provider.enqueue({ model: h.mandateBody.default_acting_model.requested_id, content: revisionContent });
    const frozenRevision = await coordinator.runProposalRevision(
      {
        preparationId: prepared.preparation_id,
        turnId: 'turn_dialogue_revision',
        selectionId: h.selectionId,
        cardId: prepared.target.card_id,
        cardVersion: prepared.target.card_version,
        requestedId: prepared.target.requested_id,
      },
      { onBehalfOf: claim },
    );
    expect(frozenRevision.proposal.proposal_run_id).toBe(prepared.proposal_run_id);
    const afterFreeze = h.store.snapshot();
    const revision = afterFreeze.proposals.get(frozenRevision.proposal.proposal_id);
    const origin = afterFreeze.proposalOrigins.get(frozenRevision.proposal.proposal_id);
    const consumedPreparation = afterFreeze.proposalRevisionPreparations.get(prepared.preparation_id);
    if (consumedPreparation === undefined) throw new Error('expected consumed revision preparation');
    expect(proposalRevisionPreparationBlocksReplacement(
      afterFreeze,
      consumedPreparation,
      '2026-08-01T09:03:00.000Z',
    )).toBe(true);
    expect(revision).toMatchObject({ action_id: 'act_test_native', revision: 2 });
    expect(origin?.continuation).toMatchObject({
      preparation_id: prepared.preparation_id,
      source_proposal_id: frozenInitial.proposal.proposal_id,
      source_escalation_id: sourceEscalation.escalation_id,
      response_record_entry_id: response.recordEntryId,
    });
    const revisionRequest = provider.requests[1];
    const revisionRequestJson = JSON.stringify(revisionRequest);
    expect(revisionRequestJson).toContain('proposal-revision@1');
    expect(revisionRequestJson).toContain('source_proposal');
    expect(revisionRequestJson).toContain('The synthetic applicant entity is no more than three years old.');
    for (const hidden of [
      frozenInitial.proposal.proposal_id,
      sourceEscalation.escalation_id,
      sourceEscalation.ruling_id,
      prepared.preparation_id,
      response.recordEntryId,
      'dialogue_item_ref',
    ]) expect(revisionRequestJson).not.toContain(hidden);

    if (revision === undefined || origin === undefined) throw new Error('expected frozen revision lineage');
    const durableDeny = await h.core.ruleProposalWithCurrentness(
      {
        gate: 'authorize',
        proposal: revision,
        service: origin.service,
        actionClass: origin.action_class,
        caseId: origin.case_id,
        context: { tool_request_class: 'inadmissible-with-fallback' },
        actor: ORCHESTRATOR,
      },
      (lockedState, at) => h.proposalIntakes.assertProposalCurrent(
        lockedState,
        at,
        frozenRevision.proposal.proposal_id,
      ),
    );
    expect(durableDeny.ruling.verdict).toBe('deny');
    const denied = await h.authorization.runProposalPrecommit(
      'w-demo',
      frozenRevision.proposal.proposal_id,
      claim,
    );
    expect(denied.state).toBe('denied');
    expect(h.store.snapshot().rulings.get(sourceEscalation.ruling_id)?.successor_ruling_id).toBeNull();
    await expect(h.authorization.proposalRunStatus(
      'w-demo',
      'case_demo',
      'prun_dialogue_source',
      claim,
    )).resolves.toMatchObject({ continuation: { state: 'available', source_proposal_run_id: null } });

    const retryPreparation = await h.authorization.prepareProposalRevision(
      'w-demo',
      'case_demo',
      'prun_dialogue_source',
      claim,
    );
    expect(retryPreparation).toMatchObject({
      preparation_id: 'rprep_test_native_3',
      proposal_run_id: 'prun_test_revision_3',
      source_proposal_run_id: 'prun_dialogue_source',
    });
    provider.enqueue({
      model: h.mandateBody.default_acting_model.requested_id,
      content: nativeProposalContent({
        declared_objective: 'File the second narrowed synthetic grant application.',
        material_input_ids: ['said_public'],
        derived_claim_ids: [],
      }),
    });
    const frozenRetryRevision = await coordinator.runProposalRevision(
      {
        preparationId: retryPreparation.preparation_id,
        turnId: 'turn_dialogue_revision_retry',
        selectionId: h.selectionId,
        cardId: retryPreparation.target.card_id,
        cardVersion: retryPreparation.target.card_version,
        requestedId: retryPreparation.target.requested_id,
      },
      { onBehalfOf: claim },
    );
    expect(h.store.snapshot().proposals.get(frozenRetryRevision.proposal.proposal_id)).toMatchObject({
      action_id: 'act_test_native',
      revision: 3,
    });

    h.setScreening('verify', null);
    const concurrentPrecommit = await Promise.allSettled([
      h.authorization.runProposalPrecommit('w-demo', frozenRetryRevision.proposal.proposal_id, claim),
      h.authorization.runProposalPrecommit('w-demo', frozenRetryRevision.proposal.proposal_id, claim),
    ]);
    const verified = concurrentPrecommit.find(
      (outcome): outcome is PromiseFulfilledResult<Awaited<ReturnType<typeof h.authorization.runProposalPrecommit>>> =>
        outcome.status === 'fulfilled' && outcome.value.state === 'verified',
    )?.value;
    if (verified === undefined) throw new Error('expected one verified concurrent precommit result');
    for (const outcome of concurrentPrecommit) {
      if (outcome.status === 'fulfilled') expect(outcome.value).toEqual(verified);
      else expect(outcome.reason).toMatchObject({ httpStatus: 409 });
    }
    expect(verified.state).toBe('verified');
    expect(verified.gates.map((entry) => entry.gate)).toEqual(['authorize', 'submit', 'verify']);
    const final = h.store.snapshot();
    expect([...final.rulings.values()].filter(
      (ruling) => ruling.binding.frozen_proposal_hash ===
        final.proposals.get(frozenRetryRevision.proposal.proposal_id)?.proposal_hash,
    ).map((ruling) => ruling.gate)).toEqual(['authorize', 'submit', 'verify']);
    expect(final.rulings.get(sourceEscalation.ruling_id)?.successor_ruling_id).toBe(
      sourceEscalation.successor_ruling_id ?? verified.gates.find((entry) => entry.gate === 'verify')?.ruling_id,
    );
    expect(final.escalations.get(sourceEscalation.escalation_id)?.successor_ruling_id).toBe(
      verified.gates.find((entry) => entry.gate === 'verify')?.ruling_id,
    );
    expect([...final.rulings.values()].some((ruling) => ruling.gate === 'commit')).toBe(false);
    expect(final.reservations.size).toBe(0);
    expect(final.commitments.size).toBe(0);
    expect(final.effects.size).toBe(0);

    await h.closeAuthorization();
    h.store.close();
    const reopened = WalStore.open({
      recordsRoot: h.root,
      worldId: 'w-demo',
      runId: 'run_model_turn_revision_replay',
      bootId: 'authz_boot_model_turn_revision_replay',
      policyVersion: h.policy.policy.policy_version,
      policyContentDigest: h.policy.policyContentDigest,
      evaluatorBuildDigest: h.buildDigest,
      now: () => '2026-08-01T09:01:00.000Z',
    });
    stores.push(reopened);
    const replayed = reopened.snapshot();
    expect([...replayed.proposalRevisionPreparations.entries()]).toEqual(
      [...final.proposalRevisionPreparations.entries()],
    );
    expect(replayed.proposalOrigins.get(frozenRetryRevision.proposal.proposal_id)).toEqual(
      final.proposalOrigins.get(frozenRetryRevision.proposal.proposal_id),
    );
    expect(replayed.rulings.get(sourceEscalation.ruling_id)?.successor_ruling_id).toBe(
      verified.gates.find((entry) => entry.gate === 'verify')?.ruling_id,
    );
  });

  it('turns a caller-selected non-inference suspect into a general Stop with no native continuation', async () => {
    const h = await authorizationHarness();
    const provider = await loopbackProvider();
    provider.enqueue({
      model: h.mandateBody.default_acting_model.requested_id,
      content: nativeProposalContent({ material_input_ids: ['said_public'], derived_claim_ids: ['inf_7'] }),
    });
    const coordinator = new ModelTurnCoordinator({
      worldId: 'w-demo',
      caseId: 'case_demo',
      authorization: h.authorization,
      lanes: [lane(provider)],
    });
    const claim = { role: 'case_officer' as const, session_id: h.sessionId };
    const frozen = await coordinator.runProposal({
      proposalRunId: 'prun_invalid_dialogue_suspect',
      conversationVersion: h.store.snapshot().conversationVersionByCase.get('case_demo') ?? 0,
      turnId: 'turn_invalid_dialogue_suspect',
      selectionId: h.selectionId,
      cardId: h.mandateBody.default_acting_model.card_id,
      cardVersion: h.mandateBody.default_acting_model.card_version,
      requestedId: h.mandateBody.default_acting_model.requested_id,
    }, { onBehalfOf: claim });
    h.setScreening('verify', {
      performed: true,
      signals: [{
        kind: 'screening_signal',
        signal: 'unconfirmed_inference_as_fact',
        suspect_item_id: 'said_public',
        confidence_pct: 100,
        rationale: 'Caller-selected material item.',
        model_id: 'screening-model',
        model_version_reported: 'screening-model-v1',
      }],
      evidenceRefs: [],
    });
    const stopped = await h.authorization.runProposalPrecommit('w-demo', frozen.proposal.proposal_id, claim);
    expect(stopped.state).toBe('escalated');
    if (stopped.kind !== 'proposal_precommit_status') throw new Error('expected terminal precommit status');
    expect(stopped.continuation).toEqual({ state: 'unavailable', source_proposal_run_id: null });
    const state = h.store.snapshot();
    const escalation = [...state.escalations.values()].find(
      (candidate) => candidate.escalation_id === stopped.escalation_id,
    );
    expect(escalation?.dialogue_item_ref).toBeNull();
    expect(escalation?.contract.trigger_and_state.trigger).toBe('unmatched-consequential');
    expect(state.rulings.get(escalation!.ruling_id)?.reason).toBe(
      'A screening signal requires review, but no bounded dialogue item could be established.',
    );
    await expect(h.authorization.prepareProposalRevision(
      'w-demo',
      'case_demo',
      'prun_invalid_dialogue_suspect',
      claim,
    )).rejects.toMatchObject({ httpStatus: 409 });
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
