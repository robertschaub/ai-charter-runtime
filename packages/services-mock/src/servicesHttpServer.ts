// SPDX-License-Identifier: MIT
/** Native HTTP host for the mock executing-services process. */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { effectIntent, hexDigest, id, timingSafeEqualUtf8, worldId } from 'gate-core';
import { z, ZodError } from 'zod';

import type { EffectLedger } from './effectLedger.js';
import type { MockServicesHost } from './servicesHost.js';

const executeRequest = z.object({ ruling_id: id, intent: effectIntent }).strict();

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
  readonly host: string;
  readonly port: number;
  readonly maxBodyBytes?: number;
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

  constructor(options: ServicesHttpServerOptions) {
    const configuredWorld = worldId.parse(options.worldId);
    const maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
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
          const probe = /^\/w\/([^/]+)\/effects\/([0-9a-f]{64})$/.exec(url.pathname);
          const presented = bearer(request.headers.authorization);
          const knownOrchestrator =
            presented !== null && timingSafeEqualUtf8(presented, options.orchestratorToken);
          const knownAuthorization =
            presented !== null && timingSafeEqualUtf8(presented, options.authorizationToken);
          if (execute !== null && request.method === 'POST') {
            if (!knownOrchestrator) {
              sendJson(response, knownAuthorization ? 403 : 401, { error: knownAuthorization ? 'forbidden' : 'unauthenticated' });
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
          if (probe !== null && request.method === 'GET') {
            if (!knownAuthorization) {
              sendJson(response, knownOrchestrator ? 403 : 401, { error: knownOrchestrator ? 'forbidden' : 'unauthenticated' });
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
