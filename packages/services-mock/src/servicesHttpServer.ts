// SPDX-License-Identifier: MIT
/** Native HTTP host for the mock executing-services process. */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { effectIntent, hexDigest, id, timingSafeEqualUtf8, worldId } from 'gate-core';
import { z, ZodError } from 'zod';

import type { EffectLedger } from './effectLedger.js';
import type {
  ServicesAccessDenial,
  ServicesDataAccessRoute,
  ServicesAuthorizationHttpClient,
} from './authorizationHttpClient.js';
import type { MockServicesHost } from './servicesHost.js';
import { resolveSyntheticRegistryEvidence } from './registryEvidence.js';

const executeRequest = z.object({ ruling_id: id, intent: effectIntent }).strict();
const nativeExecuteRequest = z.object({}).strict();

async function readJson(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  if (!request.headers['content-type']?.toLowerCase().startsWith('application/json')) {
    throw new Error('json-required');
  }
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
  });
  response.end(bytes);
}

export interface ServicesHttpServerOptions {
  readonly services: MockServicesHost;
  readonly ledger: EffectLedger;
  readonly worldId: string;
  readonly orchestratorToken: string;
  readonly authorizationToken: string;
  readonly accessRecorder: Pick<ServicesAuthorizationHttpClient, 'recordAccessDenial'>;
  readonly host: string;
  readonly port: number;
  readonly maxBodyBytes?: number;
  readonly unauthenticatedDetailLimit?: number;
  readonly unauthenticatedWindowMs?: number;
  readonly nowMilliseconds?: () => number;
}

export interface ServicesListeningAddress {
  readonly host: string;
  readonly port: number;
  readonly origin: string;
}

export class ServicesHttpServer {
  readonly #server: Server;
  readonly #host: string;
  readonly #port: number;
  readonly #worldId: string;
  readonly #accessRecorder: Pick<ServicesAuthorizationHttpClient, 'recordAccessDenial'>;
  readonly #unauthenticatedDetailLimit: number;
  readonly #unauthenticatedWindowMs: number;
  readonly #nowMilliseconds: () => number;
  #unauthenticatedWindowStart: number;
  #unauthenticatedDetailedCount = 0;
  #unauthenticatedSuppressionRecorded = false;
  #unauthenticatedSuppressedCount = 0;

  constructor(options: ServicesHttpServerOptions) {
    const configuredWorld = worldId.parse(options.worldId);
    const maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
    this.#worldId = configuredWorld;
    this.#accessRecorder = options.accessRecorder;
    this.#unauthenticatedDetailLimit = options.unauthenticatedDetailLimit ?? 8;
    this.#unauthenticatedWindowMs = options.unauthenticatedWindowMs ?? 1_000;
    this.#nowMilliseconds = options.nowMilliseconds ?? Date.now;
    if (!Number.isSafeInteger(this.#unauthenticatedDetailLimit) || this.#unauthenticatedDetailLimit < 1) {
      throw new RangeError('unauthenticatedDetailLimit must be a positive safe integer');
    }
    if (!Number.isSafeInteger(this.#unauthenticatedWindowMs) || this.#unauthenticatedWindowMs < 1) {
      throw new RangeError('unauthenticatedWindowMs must be a positive safe integer');
    }
    this.#unauthenticatedWindowStart = this.#nowMilliseconds();
    if (!Number.isSafeInteger(this.#unauthenticatedWindowStart)) {
      throw new RangeError('nowMilliseconds must return a safe integer');
    }
    if (!/^[0-9a-fA-F]{64,}$/.test(options.orchestratorToken)) throw new Error('invalid orchestrator credential');
    if (!/^[0-9a-fA-F]{64,}$/.test(options.authorizationToken)) throw new Error('invalid authorization credential');
    if (timingSafeEqualUtf8(options.orchestratorToken, options.authorizationToken)) {
      throw new Error('services credentials must be distinct');
    }
    this.#host = options.host;
    this.#port = options.port;
    this.#server = createServer((request, response) => {
      void (async () => {
        try {
          const url = new URL(request.url ?? '/', `http://${options.host}`);
          if (request.method === 'GET' && url.pathname === '/healthz') {
            sendJson(response, 200, { status: 'ready', service: 'services' });
            return;
          }
          const execute = /^\/w\/([^/]+)\/services\/([^/]+)\/execute$/.exec(url.pathname);
          const nativeExecute = /^\/w\/([^/]+)\/execution-preparations\/([^/]+)\/execute$/.exec(url.pathname);
          const probe = /^\/w\/([^/]+)\/effects\/([0-9a-f]{64})$/.exec(url.pathname);
          const registryRead = /^\/w\/([^/]+)\/registry-records\/([^/]+)$/.exec(url.pathname);
          const presented = bearer(request.headers.authorization);
          const knownOrchestrator =
            presented !== null && timingSafeEqualUtf8(presented, options.orchestratorToken);
          const knownAuthorization =
            presented !== null && timingSafeEqualUtf8(presented, options.authorizationToken);
          if (execute !== null && request.method === 'POST') {
            if (!knownOrchestrator) {
              const denial = knownAuthorization
                ? await this.#recordForbidden('services.execute', 'proc:authz')
                : await this.#recordUnauthenticated('services.execute');
              sendJson(response, denial.http_status, {
                error: denial.outcome === 'rate-limited' ? 'rate-limited' : denial.outcome,
              });
              return;
            }
            if (request.headers.origin !== undefined) {
              const denial = await this.#recordForbidden('services.execute', 'proc:orchestrator');
              sendJson(response, denial.http_status, { error: denial.outcome });
              return;
            }
            const requestedWorld = worldId.safeParse(execute[1]);
            const service = id.safeParse(execute[2]);
            if (!requestedWorld.success || requestedWorld.data !== configuredWorld || !service.success) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            const parsed = executeRequest.parse(await readJson(request, maxBodyBytes));
            if (
              parsed.intent.world_id !== configuredWorld ||
              parsed.intent.service !== service.data ||
              parsed.intent.ruling_id !== parsed.ruling_id
            ) {
              sendJson(response, 422, { error: 'binding-mismatch' });
              return;
            }
            sendJson(response, 200, await options.services.execute(parsed.ruling_id, parsed.intent));
            return;
          }
          if (nativeExecute !== null && request.method === 'POST') {
            if (!knownOrchestrator) {
              const denial = knownAuthorization
                ? await this.#recordForbidden('services.native-execute', 'proc:authz')
                : await this.#recordUnauthenticated('services.native-execute');
              sendJson(response, denial.http_status, { error: denial.outcome === 'rate-limited' ? 'rate-limited' : denial.outcome });
              return;
            }
            if (request.headers.origin !== undefined) {
              const denial = await this.#recordForbidden('services.native-execute', 'proc:orchestrator');
              sendJson(response, denial.http_status, { error: denial.outcome });
              return;
            }
            const requestedWorld = worldId.safeParse(nativeExecute[1]);
            const preparation = id.safeParse(nativeExecute[2]);
            if (!requestedWorld.success || requestedWorld.data !== configuredWorld || !preparation.success) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            nativeExecuteRequest.parse(await readJson(request, maxBodyBytes));
            sendJson(response, 200, await options.services.executePrepared(configuredWorld, preparation.data));
            return;
          }
          if (probe !== null && request.method === 'GET') {
            if (!knownAuthorization) {
              const denial = knownOrchestrator
                ? await this.#recordForbidden('services.effect-probe', 'proc:orchestrator')
                : await this.#recordUnauthenticated('services.effect-probe');
              sendJson(response, denial.http_status, {
                error: denial.outcome === 'rate-limited' ? 'rate-limited' : denial.outcome,
              });
              return;
            }
            if (request.headers.origin !== undefined) {
              const denial = await this.#recordForbidden('services.effect-probe', 'proc:authz');
              sendJson(response, denial.http_status, { error: denial.outcome });
              return;
            }
            const requestedWorld = worldId.safeParse(probe[1]);
            const key = hexDigest.safeParse(probe[2]);
            if (!requestedWorld.success || requestedWorld.data !== configuredWorld || !key.success) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            sendJson(response, 200, options.ledger.probe(key.data));
            return;
          }
          if (registryRead !== null && request.method === 'GET') {
            if (!knownAuthorization) {
              const denial = knownOrchestrator
                ? await this.#recordForbidden('services.registry-read', 'proc:orchestrator')
                : await this.#recordUnauthenticated('services.registry-read');
              sendJson(response, denial.http_status, {
                error: denial.outcome === 'rate-limited' ? 'rate-limited' : denial.outcome,
              });
              return;
            }
            if (request.headers.origin !== undefined) {
              const denial = await this.#recordForbidden('services.registry-read', 'proc:authz');
              sendJson(response, denial.http_status, { error: denial.outcome });
              return;
            }
            const requestedWorld = worldId.safeParse(registryRead[1]);
            let recordId: string;
            try {
              recordId = decodeURIComponent(registryRead[2] ?? '');
            } catch {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            if (!requestedWorld.success || requestedWorld.data !== configuredWorld || recordId.length > 256) {
              sendJson(response, 404, { error: 'not-found' });
              return;
            }
            const resolvedAt = new Date(this.#nowMilliseconds()).toISOString();
            const evidence = resolveSyntheticRegistryEvidence(recordId, resolvedAt);
            sendJson(response, evidence === null ? 404 : 200, evidence ?? { error: 'not-found' });
            return;
          }
          sendJson(response, 404, { error: 'not-found' });
        } catch (error) {
          if (error instanceof ZodError || error instanceof SyntaxError) sendJson(response, 422, { error: 'invalid-request' });
          else if (error instanceof Error && error.message === 'body-too-large') sendJson(response, 413, { error: 'body-too-large' });
          else if (!response.headersSent) sendJson(response, 500, { error: 'internal-error' });
          else response.destroy();
        }
      })();
    });
  }

  async #recordForbidden(
    route: ServicesDataAccessRoute,
    actor: 'proc:orchestrator' | 'proc:authz',
  ): Promise<Extract<ServicesAccessDenial, { outcome: 'forbidden' }>> {
    const denial = {
      route,
      authenticated_actor: actor,
      outcome: 'forbidden',
      http_status: 403,
    } as const;
    await this.#accessRecorder.recordAccessDenial(this.#worldId, denial);
    return denial;
  }

  async #recordUnauthenticated(
    route: ServicesDataAccessRoute,
  ): Promise<Extract<ServicesAccessDenial, { outcome: 'unauthenticated' | 'rate-limited' }>> {
    const now = this.#nowMilliseconds();
    if (!Number.isSafeInteger(now)) throw new RangeError('nowMilliseconds must return a safe integer');
    if (
      now < this.#unauthenticatedWindowStart ||
      now - this.#unauthenticatedWindowStart >= this.#unauthenticatedWindowMs
    ) {
      const suppressedCount = this.#unauthenticatedSuppressedCount;
      this.#unauthenticatedWindowStart = now;
      this.#unauthenticatedDetailedCount = 0;
      this.#unauthenticatedSuppressionRecorded = false;
      this.#unauthenticatedSuppressedCount = 0;
      if (suppressedCount > 0) {
        await this.#accessRecorder.recordAccessDenial(this.#worldId, {
          route: 'services.unauthenticated-ingress',
          authenticated_actor: null,
          outcome: 'rate-limited',
          http_status: 429,
          suppressed_count: suppressedCount,
          suppression_window_ms: this.#unauthenticatedWindowMs,
          suppression_final: true,
        });
      }
    }
    if (this.#unauthenticatedDetailedCount < this.#unauthenticatedDetailLimit) {
      this.#unauthenticatedDetailedCount += 1;
      const denial = {
        route,
        authenticated_actor: null,
        outcome: 'unauthenticated',
        http_status: 401,
      } as const;
      await this.#accessRecorder.recordAccessDenial(this.#worldId, denial);
      return denial;
    }
    this.#unauthenticatedSuppressedCount += 1;
    const denial = {
      route: 'services.unauthenticated-ingress',
      authenticated_actor: null,
      outcome: 'rate-limited',
      http_status: 429,
      suppressed_count: 1,
      suppression_window_ms: this.#unauthenticatedWindowMs,
      suppression_final: false,
    } as const;
    if (!this.#unauthenticatedSuppressionRecorded) {
      this.#unauthenticatedSuppressionRecorded = true;
      await this.#accessRecorder.recordAccessDenial(this.#worldId, denial);
    }
    return denial;
  }

  listen(): Promise<ServicesListeningAddress> {
    return new Promise((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      this.#server.once('error', onError);
      this.#server.listen(this.#port, this.#host, () => {
        this.#server.off('error', onError);
        const address = this.#server.address();
        if (address === null || typeof address === 'string') return reject(new Error('services listener has no TCP address'));
        resolve({ host: this.#host, port: address.port, origin: `http://${this.#host}:${address.port}` });
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
