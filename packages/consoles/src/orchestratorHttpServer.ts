// SPDX-License-Identifier: MIT
/** Native HTTP host for the model-side orchestrator process. */
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import {
  classToken,
  browserOrigin,
  effectIntent,
  frozenProposal,
  id,
  timingSafeEqualUtf8,
  worldId,
  type CurrentModelSelectionProjection,
  type ModelSelectionProjection,
  type ModelSelectionTarget,
} from 'gate-core';
import { z, ZodError } from 'zod';

import {
  OrchestratorAuthorizationHttpClient,
  OrchestratorServicesHttpClient,
  RuntimeDependencyError,
} from './runtimeHttpClients.js';
import { CaseSessionStore } from './caseSessionStore.js';
import { CaseConsoleStateStore } from './caseConsoleState.js';
import {
  browserModelSelectionPreparationProjection,
  browserModelSelectionPreparationRequest,
  browserModelSelectionUseRequest,
  CaseModelSelectionPreparationError,
  CaseModelSelectionPreparationStore,
  toBrowserApprovedModelEvidence,
  toBrowserApprovedModels,
  toBrowserCurrentModelSelection,
  toBrowserModelSelectionResult,
} from './caseModelSelection.js';

const executeRequest = z
  .object({ proposal: frozenProposal, service: id, action_class: classToken })
  .strict();
const caseSessionRedeemRequest = z
  .object({
    handoff_id: id,
    handoff_code: z.string().regex(/^[0-9a-f]{64,}$/),
    role: z.literal('case_officer'),
    world_id: worldId,
    case_id: id,
    target_origin: browserOrigin,
    authorization_boot_id: id,
  })
  .strict();
const closeSessionRequest = z.object({}).strict();
const caseMessageRequest = z.object({ message: z.string().min(1).max(32_768) }).strict();

async function readJson(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  if (!request.headers['content-type']?.toLowerCase().startsWith('application/json')) throw new Error('json-required');
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > maxBytes) throw new Error('body-too-large');
    chunks.push(bytes);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
}

function bearer(value: string | undefined): string | null {
  if (value === undefined || !value.startsWith('Bearer ')) return null;
  return value.slice('Bearer '.length);
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(JSON.stringify(body), 'utf8');
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': bytes.length,
    'cache-control': 'no-store',
    'content-security-policy': "frame-ancestors 'none'",
    'x-content-type-options': 'nosniff',
  });
  response.end(bytes);
}

const CONSOLE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join('; ');

function sendConsoleAsset(response: ServerResponse, body: string, contentType: string): void {
  const bytes = Buffer.from(body, 'utf8');
  response.writeHead(200, {
    'content-type': `${contentType}; charset=utf-8`,
    'content-length': bytes.length,
    'cache-control': 'no-store',
    'content-security-policy': CONSOLE_CSP,
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
  response.end(bytes);
}

function requestOrigin(request: IncomingMessage): string | undefined {
  const value = request.headers.origin;
  return Array.isArray(value) ? value[0] : value;
}

function sameModelTarget(left: ModelSelectionTarget, right: ModelSelectionTarget): boolean {
  return (
    left.card_id === right.card_id &&
    left.card_version === right.card_version &&
    left.requested_id === right.requested_id
  );
}

function assertCurrentSelectionBinding(
  current: CurrentModelSelectionProjection,
  expectedWorld: string,
  expectedCase: string,
): void {
  if (
    current.case_id !== expectedCase ||
    (current.selection !== null &&
      (current.selection.world_id !== expectedWorld || current.selection.case_id !== expectedCase))
  ) {
    throw new Error('current-selection dependency binding mismatch');
  }
}

function assertSelectionResultBinding(
  selected: ModelSelectionProjection,
  binding: {
    readonly worldId: string;
    readonly caseId: string;
    readonly checkId: string;
    readonly expectedCurrentSelectionId: string | null;
    readonly target: ModelSelectionTarget;
  },
): void {
  const transition = selected.selection;
  if (
    transition.world_id !== binding.worldId ||
    transition.case_id !== binding.caseId ||
    transition.check_id !== binding.checkId ||
    transition.predecessor_selection_id !== binding.expectedCurrentSelectionId ||
    transition.kind !== (binding.expectedCurrentSelectionId === null ? 'initial' : 'switch') ||
    !sameModelTarget(transition.target, binding.target)
  ) {
    throw new Error('model-selection dependency binding mismatch');
  }
}

export interface CaseConsoleAssetPaths {
  readonly shell: string;
  readonly script: string;
  readonly stylesheet: string;
}

export interface CaseConsoleAssets {
  readonly shell: string;
  readonly script: string;
  readonly stylesheet: string;
}

/** Load all browser bytes before the process is allowed to bind its listener. */
export function loadCaseConsoleAssets(paths: CaseConsoleAssetPaths): CaseConsoleAssets {
  return {
    shell: readFileSync(paths.shell, 'utf8'),
    script: readFileSync(paths.script, 'utf8').replace(/\r?\n\/\/# sourceMappingURL=.*\r?\n?$/u, '\n'),
    stylesheet: readFileSync(paths.stylesheet, 'utf8'),
  };
}

export interface OrchestratorHttpServerOptions {
  readonly authorization: OrchestratorAuthorizationHttpClient;
  readonly services: OrchestratorServicesHttpClient;
  readonly worldId: string;
  readonly demoCaseId: string;
  readonly demoMandateId: string;
  readonly caseOfficerToken: string;
  readonly authorizationOrigin: string;
  readonly caseConsoleAssets: CaseConsoleAssets;
  readonly caseSessions?: CaseSessionStore;
  readonly modelSelectionPreparations?: CaseModelSelectionPreparationStore;
  readonly caseState?: CaseConsoleStateStore;
  readonly host: string;
  readonly port: number;
  readonly maxBodyBytes?: number;
}

export interface OrchestratorListeningAddress {
  readonly host: string;
  readonly port: number;
  readonly origin: string;
}

export class OrchestratorHttpServer {
  readonly #server: Server;
  readonly #host: string;
  readonly #port: number;
  #origin: string | null;

  constructor(options: OrchestratorHttpServerOptions) {
    const configuredWorld = worldId.parse(options.worldId);
    const configuredCase = id.parse(options.demoCaseId);
    const configuredMandate = id.parse(options.demoMandateId);
    const authorizationOrigin = browserOrigin.parse(options.authorizationOrigin);
    const sessions = options.caseSessions ?? new CaseSessionStore();
    const preparations = options.modelSelectionPreparations ?? new CaseModelSelectionPreparationStore();
    const caseState = options.caseState ?? new CaseConsoleStateStore();
    const maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
    if (!/^[0-9a-fA-F]{64,}$/.test(options.caseOfficerToken)) throw new Error('invalid case-console credential');
    this.#host = options.host;
    this.#port = options.port;
    this.#origin = options.port === 0 ? null : `http://${options.host}:${options.port}`;
    this.#server = createServer((request, response) => {
      void (async () => {
        try {
          const url = new URL(request.url ?? '/', `http://${options.host}`);
          if (request.method === 'GET' && url.pathname === '/healthz') {
            sendJson(response, 200, { status: 'ready', service: 'orchestrator' });
            return;
          }
          const ownOrigin = this.#origin;
          if (ownOrigin === null) throw new Error('listener origin is unavailable');
          if (request.method === 'GET' && url.pathname === '/console/runtime-config.json') {
            sendJson(response, 200, {
              authorization_origin: authorizationOrigin,
              orchestrator_origin: ownOrigin,
            });
            return;
          }
          if (request.method === 'GET' && (url.pathname === '/console/handoff' || url.pathname === '/console/handoff/')) {
            sendConsoleAsset(response, options.caseConsoleAssets.shell, 'text/html');
            return;
          }
          if (request.method === 'GET' && url.pathname === '/console/handoff.js') {
            sendConsoleAsset(response, options.caseConsoleAssets.script, 'text/javascript');
            return;
          }
          if (request.method === 'GET' && url.pathname === '/console/case-styles.css') {
            sendConsoleAsset(response, options.caseConsoleAssets.stylesheet, 'text/css');
            return;
          }
          const redeemMatch = /^\/w\/([^/]+)\/case-sessions\/redeem$/.exec(url.pathname);
          if (request.method === 'POST' && redeemMatch !== null) {
            const requestedWorld = worldId.safeParse(redeemMatch[1]);
            if (!requestedWorld.success || requestedWorld.data !== configuredWorld) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            if (request.headers.authorization !== undefined) {
              sendJson(response, 403, { error: 'handoff-refused' });
              return;
            }
            const origin = requestOrigin(request);
            if (origin !== undefined && origin !== ownOrigin) {
              sendJson(response, 403, { error: 'handoff-refused' });
              return;
            }
            const parsed = caseSessionRedeemRequest.parse(await readJson(request, maxBodyBytes));
            if (
              parsed.world_id !== configuredWorld ||
              parsed.case_id !== configuredCase ||
              parsed.target_origin !== ownOrigin
            ) {
              sendJson(response, 403, { error: 'handoff-refused' });
              return;
            }
            let claim;
            try {
              claim = await options.authorization.redeemCaseSessionHandoff(parsed);
            } catch {
              sendJson(response, 403, { error: 'handoff-refused' });
              return;
            }
            if (
              claim.world_id !== configuredWorld ||
              claim.case_id !== configuredCase ||
              claim.target_origin !== ownOrigin
            ) {
              sendJson(response, 403, { error: 'handoff-refused' });
              return;
            }
            sendJson(response, 201, sessions.create(claim));
            return;
          }
          const closeMatch = /^\/w\/([^/]+)\/case-sessions\/close$/.exec(url.pathname);
          if (request.method === 'POST' && closeMatch !== null) {
            const requestedWorld = worldId.safeParse(closeMatch[1]);
            if (!requestedWorld.success || requestedWorld.data !== configuredWorld) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            const origin = requestOrigin(request);
            if (origin !== undefined && origin !== ownOrigin) {
              sendJson(response, 403, { error: 'forbidden' });
              return;
            }
            const presented = bearer(request.headers.authorization);
            const session = presented === null ? null : sessions.authenticate(presented, configuredWorld);
            if (presented === null || session === null) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            closeSessionRequest.parse(await readJson(request, maxBodyBytes));
            if (!sessions.close(presented, configuredWorld)) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            preparations.burnForSession(session.session_id);
            sendJson(response, 200, { closed: true });
            return;
          }
          const stateMatch = /^\/w\/([^/]+)\/cases\/([^/]+)\/state$/.exec(url.pathname);
          if (request.method === 'GET' && stateMatch !== null) {
            const requestedWorld = worldId.safeParse(stateMatch[1]);
            const requestedCase = id.safeParse(stateMatch[2]);
            if (
              !requestedWorld.success ||
              requestedWorld.data !== configuredWorld ||
              !requestedCase.success ||
              requestedCase.data !== configuredCase
            ) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            const origin = requestOrigin(request);
            if (origin !== undefined && origin !== ownOrigin) {
              sendJson(response, 403, { error: 'forbidden' });
              return;
            }
            const presented = bearer(request.headers.authorization);
            if (presented === null || sessions.authenticate(presented, configuredWorld, configuredCase) === null) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            const tracked = caseState.tracked(configuredCase);
            const current =
              tracked === null
                ? undefined
                : await options.authorization.rulingStatus(configuredWorld, tracked.rulingId);
            sendJson(response, 200, caseState.project(configuredCase, authorizationOrigin, configuredWorld, current));
            return;
          }
          const modelsMatch = /^\/w\/([^/]+)\/models$/.exec(url.pathname);
          if (request.method === 'GET' && modelsMatch !== null) {
            const requestedWorld = worldId.safeParse(modelsMatch[1]);
            if (!requestedWorld.success || requestedWorld.data !== configuredWorld) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            const origin = requestOrigin(request);
            if (origin !== undefined && origin !== ownOrigin) {
              sendJson(response, 403, { error: 'forbidden' });
              return;
            }
            const presented = bearer(request.headers.authorization);
            if (presented === null || sessions.authenticate(presented, configuredWorld) === null) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            const models = toBrowserApprovedModels(
              await options.authorization.approvedModels(configuredWorld, configuredMandate),
            );
            if (models.mandate_id !== configuredMandate) {
              throw new Error('approved-model dependency binding mismatch');
            }
            sendJson(response, 200, models);
            return;
          }
          const currentSelectionMatch = /^\/w\/([^/]+)\/cases\/([^/]+)\/model-selection$/.exec(url.pathname);
          if (request.method === 'GET' && currentSelectionMatch !== null) {
            const requestedWorld = worldId.safeParse(currentSelectionMatch[1]);
            const requestedCase = id.safeParse(currentSelectionMatch[2]);
            if (
              !requestedWorld.success ||
              requestedWorld.data !== configuredWorld ||
              !requestedCase.success ||
              requestedCase.data !== configuredCase
            ) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            const origin = requestOrigin(request);
            if (origin !== undefined && origin !== ownOrigin) {
              sendJson(response, 403, { error: 'forbidden' });
              return;
            }
            const presented = bearer(request.headers.authorization);
            const session = presented === null
              ? null
              : sessions.authenticate(presented, configuredWorld, configuredCase);
            if (session === null) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            const dependencyCurrent = await options.authorization.currentModelSelection(configuredWorld, configuredCase);
            assertCurrentSelectionBinding(dependencyCurrent, configuredWorld, configuredCase);
            const current = toBrowserCurrentModelSelection(dependencyCurrent);
            preparations.burnStaleForCase(
              configuredWorld,
              configuredCase,
              current.selection?.selection_id ?? null,
            );
            sendJson(response, 200, current);
            return;
          }
          const preparationMatch = /^\/w\/([^/]+)\/cases\/([^/]+)\/model-selection-preparations$/.exec(
            url.pathname,
          );
          if (request.method === 'POST' && preparationMatch !== null) {
            const requestedWorld = worldId.safeParse(preparationMatch[1]);
            const requestedCase = id.safeParse(preparationMatch[2]);
            if (
              !requestedWorld.success ||
              requestedWorld.data !== configuredWorld ||
              !requestedCase.success ||
              requestedCase.data !== configuredCase
            ) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            if (requestOrigin(request) !== ownOrigin) {
              sendJson(response, 403, { error: 'forbidden' });
              return;
            }
            const presented = bearer(request.headers.authorization);
            const session = presented === null
              ? null
              : sessions.authenticate(presented, configuredWorld, configuredCase);
            if (presented === null || session === null) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            const parsed = browserModelSelectionPreparationRequest.parse(await readJson(request, maxBodyBytes));
            preparations.burnForSession(session.session_id);
            try {
              const current = await options.authorization.currentModelSelection(configuredWorld, configuredCase);
              assertCurrentSelectionBinding(current, configuredWorld, configuredCase);
              const expectedCurrentSelectionId = current.selection?.selection_id ?? null;
              const checked = await options.authorization.checkModelSelection(
                configuredWorld,
                configuredCase,
                {
                  expected_current_selection_id: expectedCurrentSelectionId,
                  target: parsed.target,
                },
                { role: session.role, session_id: session.session_id },
              );
              const preparation = preparations.create(session, checked, {
                target: parsed.target,
                expectedCurrentSelectionId,
              });
              sendJson(
                response,
                201,
                browserModelSelectionPreparationProjection.parse({
                  preparation,
                  evidence: toBrowserApprovedModelEvidence(checked.evidence),
                }),
              );
            } catch (error) {
              if (
                error instanceof CaseModelSelectionPreparationError &&
                error.code === 'authorization-boot-mismatch'
              ) {
                preparations.burnForSession(session.session_id);
                sessions.close(presented, configuredWorld);
                sendJson(response, 401, { error: 'session-restart-required' });
                return;
              }
              if (error instanceof RuntimeDependencyError && error.httpStatus >= 400 && error.httpStatus < 500) {
                sendJson(response, 409, { error: 'selection-preparation-refused' });
                return;
              }
              throw error;
            }
            return;
          }
          const browserSelectionMatch = /^\/w\/([^/]+)\/cases\/([^/]+)\/model-selections$/.exec(url.pathname);
          if (request.method === 'POST' && browserSelectionMatch !== null) {
            const requestedWorld = worldId.safeParse(browserSelectionMatch[1]);
            const requestedCase = id.safeParse(browserSelectionMatch[2]);
            if (
              !requestedWorld.success ||
              requestedWorld.data !== configuredWorld ||
              !requestedCase.success ||
              requestedCase.data !== configuredCase
            ) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            if (requestOrigin(request) !== ownOrigin) {
              sendJson(response, 403, { error: 'forbidden' });
              return;
            }
            const presented = bearer(request.headers.authorization);
            const session = presented === null
              ? null
              : sessions.authenticate(presented, configuredWorld, configuredCase);
            if (session === null) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            const parsed = browserModelSelectionUseRequest.parse(await readJson(request, maxBodyBytes));
            const begun = preparations.beginUse(parsed.preparation_id, session);
            if (begun === null) {
              sendJson(response, 409, { error: 'selection-preparation-unavailable' });
              return;
            }
            try {
              const selected = await options.authorization.selectModel(
                configuredWorld,
                configuredCase,
                {
                  check_id: begun.checkId,
                  expected_current_selection_id: begun.expectedCurrentSelectionId,
                },
                { role: session.role, session_id: session.session_id },
              );
              assertSelectionResultBinding(selected, {
                worldId: configuredWorld,
                caseId: configuredCase,
                checkId: begun.checkId,
                expectedCurrentSelectionId: begun.expectedCurrentSelectionId,
                target: begun.target,
              });
              preparations.burnForCase(configuredWorld, configuredCase);
              sendJson(response, 200, toBrowserModelSelectionResult(selected));
            } catch (error) {
              preparations.burn(begun.preparationId);
              if (error instanceof RuntimeDependencyError && error.httpStatus >= 400 && error.httpStatus < 500) {
                sendJson(response, 409, { error: 'model-selection-refused' });
                return;
              }
              throw error;
            }
            return;
          }
          const messageMatch = /^\/w\/([^/]+)\/cases\/([^/]+)\/messages$/.exec(url.pathname);
          if (request.method === 'POST' && messageMatch !== null) {
            const requestedWorld = worldId.safeParse(messageMatch[1]);
            const requestedCase = id.safeParse(messageMatch[2]);
            if (
              !requestedWorld.success ||
              requestedWorld.data !== configuredWorld ||
              !requestedCase.success ||
              requestedCase.data !== configuredCase
            ) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            const origin = requestOrigin(request);
            if (origin !== undefined && origin !== ownOrigin) {
              sendJson(response, 403, { error: 'forbidden' });
              return;
            }
            const presented = bearer(request.headers.authorization);
            if (presented === null || sessions.authenticate(presented, configuredWorld, configuredCase) === null) {
              sendJson(response, 401, { error: 'unauthenticated' });
              return;
            }
            caseMessageRequest.parse(await readJson(request, maxBodyBytes));
            sendJson(response, 501, { error: 'model-interaction-not-active' });
            return;
          }
          const match = /^\/w\/([^/]+)\/actions\/execute$/.exec(url.pathname);
          if (match === null || request.method !== 'POST') {
            sendJson(response, 404, { error: 'not-found' });
            return;
          }
          const presented = bearer(request.headers.authorization);
          if (presented === null || !timingSafeEqualUtf8(presented, options.caseOfficerToken)) {
            sendJson(response, 401, { error: 'unauthenticated' });
            return;
          }
          const requestedWorld = worldId.safeParse(match[1]);
          if (!requestedWorld.success || requestedWorld.data !== configuredWorld) {
            sendJson(response, 404, { error: 'not-found' });
            return;
          }
          const parsed = executeRequest.parse(await readJson(request, maxBodyBytes));
          if (parsed.proposal.world_id !== configuredWorld) {
            sendJson(response, 422, { error: 'binding-mismatch' });
            return;
          }
          const ruled = await options.authorization.ruleCommit({
            proposal: parsed.proposal,
            service: parsed.service,
            actionClass: parsed.action_class,
          });
          caseState.track(configuredCase, ruled);
          if (ruled.ruling.verdict !== 'allow') {
            sendJson(response, 200, { ok: false, stage: 'ruling', ruling: ruled.ruling });
            return;
          }
          const intent = effectIntent.parse({
            world_id: parsed.proposal.world_id,
            ruling_id: ruled.ruling.ruling_id,
            frozen_proposal_hash: parsed.proposal.proposal_hash,
            service: parsed.service,
            action_class: parsed.action_class,
            target: parsed.proposal.target,
            exact_parameters: parsed.proposal.exact_parameters,
            data_to_be_disclosed: parsed.proposal.data_to_be_disclosed,
          });
          const execution = await options.services.execute(ruled.ruling.ruling_id, intent);
          sendJson(response, 200, { ok: execution.ok, ruling_id: ruled.ruling.ruling_id, execution });
        } catch (error) {
          if (error instanceof ZodError || error instanceof SyntaxError) sendJson(response, 422, { error: 'invalid-request' });
          else if (error instanceof Error && error.message === 'body-too-large') sendJson(response, 413, { error: 'body-too-large' });
          else if (!response.headersSent) sendJson(response, 502, { error: 'dependency-failure' });
          else response.destroy();
        }
      })();
    });
  }

  listen(): Promise<OrchestratorListeningAddress> {
    return new Promise((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      this.#server.once('error', onError);
      this.#server.listen(this.#port, this.#host, () => {
        this.#server.off('error', onError);
        const address = this.#server.address();
        if (address === null || typeof address === 'string') return reject(new Error('orchestrator listener has no TCP address'));
        this.#origin = `http://${this.#host}:${address.port}`;
        resolve({ host: this.#host, port: address.port, origin: this.#origin });
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.#server.listening) return resolve();
      this.#server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }
}
