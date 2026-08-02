// SPDX-License-Identifier: MIT
/** Native HTTP host for the model-side orchestrator process. */
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import {
  classToken,
  effectIntent,
  frozenProposal,
  id,
  timingSafeEqualUtf8,
  worldId,
} from 'gate-core';
import { z, ZodError } from 'zod';

import {
  OrchestratorAuthorizationHttpClient,
  OrchestratorServicesHttpClient,
} from './runtimeHttpClients.js';

const executeRequest = z
  .object({ proposal: frozenProposal, service: id, action_class: classToken })
  .strict();

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
  });
  response.end(bytes);
}

export interface OrchestratorHttpServerOptions {
  readonly authorization: OrchestratorAuthorizationHttpClient;
  readonly services: OrchestratorServicesHttpClient;
  readonly worldId: string;
  readonly caseOfficerToken: string;
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

  constructor(options: OrchestratorHttpServerOptions) {
    const configuredWorld = worldId.parse(options.worldId);
    const maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
    if (!/^[0-9a-fA-F]{64,}$/.test(options.caseOfficerToken)) throw new Error('invalid case-console credential');
    this.#host = options.host;
    this.#port = options.port;
    this.#server = createServer((request, response) => {
      void (async () => {
        try {
          const url = new URL(request.url ?? '/', `http://${options.host}`);
          if (request.method === 'GET' && url.pathname === '/healthz') {
            sendJson(response, 200, { status: 'ready', service: 'orchestrator' });
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
