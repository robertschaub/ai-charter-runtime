// SPDX-License-Identifier: AGPL-3.0-only
/** Native HTTP host for the ADR-002 authorization-service boundary. */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { z, ZodError } from 'zod';

import {
  AuthorizationCore,
  AuthorizationError,
  bindMandate,
  type ContinueEscalationRevisionResult,
  type DisposeEscalationResult,
  type EffectOutcomeReportResult,
  type RuleProposalResult,
} from './authorizationCore.js';
import {
  AUTHORIZATION_ROUTES,
  AuthorizationHttpAdapter,
  type AuthorizationAdapterContext,
  type AuthorizationOperationResult,
} from './authorizationHttpAdapter.js';
import type { Keyring } from './keyring.js';
import {
  classToken,
  disposition,
  effectIntent,
  frozenProposal,
  gate,
  hexDigest,
  id,
  integer,
  timestamp,
  type Mandate,
} from './schemas/index.js';

const jsonObject = z.record(z.string(), z.unknown());
const proposalRequest = z
  .object({
    gate,
    proposal: frozenProposal,
    service: id,
    action_class: classToken,
    context: jsonObject.optional(),
  })
  .strict();
const commitVerifyRequest = z
  .object({
    ruling_id: id,
    intent: effectIntent,
    services_host_boot_id: id,
    services_ledger_id: id,
  })
  .strict();
const effectOutcomeRequest = z
  .object({
    world_id: z.string(),
    commitment_id: id,
    effect_id: id,
    idempotency_key: hexDigest,
    effect_request_digest: hexDigest,
    services_host_boot_id: id,
    services_ledger_id: id,
    outcome: z.enum(['success', 'failed']),
    recorded_at: timestamp,
    detail: z.string().optional(),
    delivery: z.enum(['executed', 'retry', 'reconciliation-probe']),
  })
  .strict();
const revokeRequest = z.object({ version: integer.min(1) }).strict();
const dispositionRequest = z.object({ disposition }).strict();
const revisionRequest = z
  .object({ proposal: frozenProposal, context: jsonObject.optional() })
  .strict();

class HttpInputError extends Error {
  constructor(readonly status: 400 | 413 | 415, readonly responseCode: string) {
    super(responseCode);
  }
}

async function readJson(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  const contentType = request.headers['content-type'];
  if (contentType === undefined || !contentType.toLowerCase().startsWith('application/json')) {
    throw new HttpInputError(415, 'json-required');
  }
  const declared = request.headers['content-length'];
  if (declared !== undefined) {
    const bytes = Number(declared);
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new HttpInputError(400, 'invalid-content-length');
    if (bytes > maxBytes) throw new HttpInputError(413, 'body-too-large');
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > maxBytes) throw new HttpInputError(413, 'body-too-large');
    chunks.push(bytes);
  }
  if (length === 0) throw new HttpInputError(400, 'empty-json-body');
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new HttpInputError(400, 'malformed-json');
  }
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(JSON.stringify(body), 'utf8');
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': bytes.length,
    'cache-control': 'no-store',
    'content-security-policy': "frame-ancestors 'none'",
  });
  response.end(bytes);
}

type Handler = (
  request: IncomingMessage,
  context: AuthorizationAdapterContext,
) => Promise<AuthorizationOperationResult<unknown>>;

export interface AuthorizationHttpServerOptions {
  readonly authorization: AuthorizationCore;
  readonly adapter: AuthorizationHttpAdapter;
  readonly keyring: Keyring;
  readonly host: string;
  readonly port: number;
  readonly maxBodyBytes?: number;
}

export interface ListeningAddress {
  readonly host: string;
  readonly port: number;
  readonly origin: string;
}

/**
 * The handler table is closed over route ids. The caller cannot pair a permitted path
 * with an arbitrary core operation: route matching and operation selection happen in
 * one authorization-owned callback.
 */
export class AuthorizationHttpServer {
  readonly #server: Server;
  readonly #host: string;
  readonly #port: number;
  readonly #handlers: Readonly<Record<string, Handler>>;

  constructor(options: AuthorizationHttpServerOptions) {
    const maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
    if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
      throw new RangeError('maxBodyBytes must be a positive safe integer');
    }
    if (!Number.isSafeInteger(options.port) || options.port < 0 || options.port > 65_535) {
      throw new RangeError('port must be an integer from 0 through 65535');
    }
    this.#host = options.host;
    this.#port = options.port;

    const body = (request: IncomingMessage) => readJson(request, maxBodyBytes);
    const requireActor = (context: AuthorizationAdapterContext) => {
      if (context.actor === null) throw new AuthorizationError('unauthorized-actor', 'authenticated actor required');
      return context.actor;
    };
    const handlers: Record<string, Handler> = {
      health: async () => ({ status: 200, body: { status: 'ready', service: 'authorization' } }),
      'proposal.submit': async (request, context) => {
        const parsed = proposalRequest.parse(await body(request));
        const result: RuleProposalResult = await options.authorization.ruleProposal({
          gate: parsed.gate,
          proposal: parsed.proposal,
          service: parsed.service,
          actionClass: parsed.action_class,
          actor: requireActor(context),
          ...(parsed.context === undefined ? {} : { context: parsed.context }),
        });
        return { status: 200, body: result };
      },
      'commit.verify': async (request, context) => {
        const parsed = commitVerifyRequest.parse(await body(request));
        const result = await options.authorization.commitVerify({
          rulingId: parsed.ruling_id,
          intent: parsed.intent,
          servicesHostBootId: parsed.services_host_boot_id,
          servicesLedgerId: parsed.services_ledger_id,
          actor: requireActor(context),
        });
        return { status: 200, body: result };
      },
      'effect.outcome': async (request, context) => {
        const parsed = effectOutcomeRequest.parse(await body(request));
        if (context.worldId !== parsed.world_id || context.params['id'] !== parsed.effect_id) {
          return { status: 422, body: { error: 'binding-mismatch' } };
        }
        const result: EffectOutcomeReportResult = await options.authorization.reportEffectOutcome({
          worldId: parsed.world_id,
          commitmentId: parsed.commitment_id,
          effectId: parsed.effect_id,
          idempotencyKey: parsed.idempotency_key,
          effectRequestDigest: parsed.effect_request_digest,
          servicesHostBootId: parsed.services_host_boot_id,
          servicesLedgerId: parsed.services_ledger_id,
          outcome: parsed.outcome,
          recordedAt: parsed.recorded_at,
          ...(parsed.detail === undefined ? {} : { detail: parsed.detail }),
          delivery: parsed.delivery,
          actor: requireActor(context),
        });
        return { status: 200, body: result };
      },
      'mandate.grant': async (request, context) => {
        const raw = jsonObject.parse(await body(request));
        if (Object.hasOwn(raw, 'binding')) return { status: 422, body: { error: 'binding-server-owned' } };
        const bound = bindMandate(options.keyring, raw as unknown as Omit<Mandate, 'binding'>);
        await options.authorization.grantMandate(bound, requireActor(context));
        return { status: 201, body: { mandate_id: bound.mandate_id, version: bound.version } };
      },
      'mandate.amend': async (request, context) => {
        const raw = jsonObject.parse(await body(request));
        if (Object.hasOwn(raw, 'binding')) return { status: 422, body: { error: 'binding-server-owned' } };
        const bound = bindMandate(options.keyring, raw as unknown as Omit<Mandate, 'binding'>);
        if (context.params['id'] !== bound.mandate_id) return { status: 422, body: { error: 'binding-mismatch' } };
        await options.authorization.amendMandate(bound, requireActor(context));
        return { status: 200, body: { mandate_id: bound.mandate_id, version: bound.version } };
      },
      'mandate.revoke': async (request, context) => {
        const parsed = revokeRequest.parse(await body(request));
        const mandateId = context.params['id'];
        if (mandateId === undefined) return { status: 422, body: { error: 'binding-mismatch' } };
        await options.authorization.revokeMandate(mandateId, parsed.version, requireActor(context));
        return { status: 200, body: { mandate_id: mandateId, version: parsed.version, state: 'revoked' } };
      },
      'escalation.dispose': async (request, context) => {
        const parsed = dispositionRequest.parse(await body(request));
        const escalationId = context.params['id'];
        if (escalationId === undefined) return { status: 422, body: { error: 'binding-mismatch' } };
        const result: DisposeEscalationResult = await options.authorization.disposeEscalation({
          escalationId,
          disposition: parsed.disposition,
          actor: requireActor(context),
        });
        return { status: result.accepted ? 200 : 422, body: result };
      },
      'escalation.revise': async (request, context) => {
        const parsed = revisionRequest.parse(await body(request));
        const escalationId = context.params['id'];
        if (escalationId === undefined) return { status: 422, body: { error: 'binding-mismatch' } };
        const result: ContinueEscalationRevisionResult = await options.authorization.continueEscalationRevision({
          escalationId,
          proposal: parsed.proposal,
          actor: requireActor(context),
          ...(parsed.context === undefined ? {} : { context: parsed.context }),
        });
        return { status: result.accepted ? 200 : 422, body: result };
      },
    };
    const unsupported: Handler = async () => ({ status: 501, body: { error: 'not-implemented' } });
    this.#handlers = Object.fromEntries(
      AUTHORIZATION_ROUTES.map((route) => [route.id, handlers[route.id] ?? unsupported]),
    );

    this.#server = createServer((request, response) => {
      void this.#handle(request, response, options.adapter);
    });
  }

  async #handle(
    request: IncomingMessage,
    response: ServerResponse,
    adapter: AuthorizationHttpAdapter,
  ): Promise<void> {
    try {
      const url = new URL(request.url ?? '/', `http://${this.#host}`);
      const adapted = await adapter.dispatch(
        {
          method: request.method ?? 'GET',
          pathname: url.pathname,
          authorization: request.headers.authorization,
          origin: Array.isArray(request.headers.origin) ? request.headers.origin[0] : request.headers.origin,
          claimedRole: Array.isArray(request.headers['x-on-behalf-of-role'])
            ? request.headers['x-on-behalf-of-role'][0]
            : request.headers['x-on-behalf-of-role'],
          sessionId: Array.isArray(request.headers['x-session-id'])
            ? request.headers['x-session-id'][0]
            : request.headers['x-session-id'],
        },
        async (context) => {
          try {
            const handler = this.#handlers[context.routeId];
            if (handler === undefined) return { status: 500, body: { error: 'route-handler-missing' } };
            return await handler(request, context);
          } catch (error) {
            if (error instanceof HttpInputError) return { status: error.status, body: { error: error.responseCode } };
            if (error instanceof ZodError) return { status: 422, body: { error: 'invalid-request' } };
            if (error instanceof AuthorizationError) return { status: 422, body: { error: error.code } };
            throw error;
          }
        },
      );
      sendJson(response, adapted.status, adapted.body);
    } catch {
      if (!response.headersSent) sendJson(response, 500, { error: 'internal-error' });
      else response.destroy();
    }
  }

  listen(): Promise<ListeningAddress> {
    return new Promise((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      this.#server.once('error', onError);
      this.#server.listen(this.#port, this.#host, () => {
        this.#server.off('error', onError);
        const address = this.#server.address();
        if (address === null || typeof address === 'string') {
          reject(new Error('authorization listener did not expose a TCP address'));
          return;
        }
        resolve({ host: this.#host, port: address.port, origin: `http://${this.#host}:${address.port}` });
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.#server.listening) {
        resolve();
        return;
      }
      this.#server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }
}
