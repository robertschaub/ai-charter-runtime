// SPDX-License-Identifier: AGPL-3.0-only
/** Authorization-owned client for read-only services-ledger reconciliation probes. */
import { z } from 'zod';

import type { CommitmentProbe } from './authorizationCore.js';
import { classToken, effectIntent, hexDigest, id, timestamp, worldId } from './schemas/index.js';

const recordedProbe = z
  .object({
    state: z.literal('recorded'),
    boot_id: id,
    ledger_id: id,
    record: z
      .object({
        version: z.literal(1),
        world_id: worldId,
        services_host_boot_id: id,
        services_ledger_id: id,
        idempotency_key: hexDigest,
        effect_id: id,
        ruling_id: id,
        frozen_proposal_hash: hexDigest,
        effect_request_digest: hexDigest,
        service: id,
        action_class: classToken,
        intent: effectIntent,
        outcome: z.enum(['success', 'failed']),
        recorded_at: timestamp,
        detail: z.string().min(1).optional(),
      })
      .strict(),
  })
  .strict();
const absentProbe = z
  .object({ state: z.literal('absent'), boot_id: id, ledger_id: id })
  .strict();
const probeResponse = z.discriminatedUnion('state', [recordedProbe, absentProbe]);
const healthResponse = z
  .object({ status: z.literal('ready'), service: z.literal('services') })
  .strict();

async function responseJson(response: Response, maxBytes: number): Promise<unknown> {
  const declared = response.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) throw new Error('services response exceeded limit');
  const bytes = Buffer.from(await response.arrayBuffer());
  if (bytes.length > maxBytes) throw new Error('services response exceeded limit');
  try {
    return JSON.parse(bytes.toString('utf8')) as unknown;
  } catch {
    throw new Error('services response was not JSON');
  }
}

export interface ServicesProbeHttpClientOptions {
  readonly origin: string;
  readonly token: string;
  readonly worldId: string;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly fetchImplementation?: typeof fetch;
}

export class ServicesProbeHttpClient {
  readonly #origin: string;
  readonly #token: string;
  readonly #worldId: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetch: typeof fetch;

  constructor(options: ServicesProbeHttpClientOptions) {
    this.#origin = new URL(options.origin).origin;
    this.#token = options.token;
    this.#worldId = worldId.parse(options.worldId);
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    this.#maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024;
    this.#fetch = options.fetchImplementation ?? fetch;
  }

  async #get(path: string): Promise<unknown> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#origin), {
        headers: { authorization: `Bearer ${this.#token}` },
        redirect: 'error',
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch {
      throw new Error('services host unavailable');
    }
    const body = await responseJson(response, this.#maxResponseBytes);
    if (!response.ok) throw new Error(`services host rejected probe with HTTP ${response.status}`);
    return body;
  }

  async requireHealthy(): Promise<void> {
    healthResponse.parse(await this.#get('/healthz'));
  }

  async probe(idempotencyKeyInput: string): Promise<CommitmentProbe> {
    const key = hexDigest.parse(idempotencyKeyInput);
    const parsed = probeResponse.parse(await this.#get(`/w/${this.#worldId}/effects/${key}`));
    if (parsed.state === 'absent') return parsed;
    if (
      parsed.record.world_id !== this.#worldId ||
      parsed.record.idempotency_key !== key ||
      parsed.record.services_ledger_id !== parsed.ledger_id
    ) {
      throw new Error('services probe response did not match its request and ledger identity');
    }
    return {
      state: 'recorded',
      boot_id: parsed.boot_id,
      record: {
        world_id: parsed.record.world_id,
        services_host_boot_id: parsed.record.services_host_boot_id,
        services_ledger_id: parsed.record.services_ledger_id,
        effect_id: parsed.record.effect_id,
        idempotency_key: parsed.record.idempotency_key,
        effect_request_digest: parsed.record.effect_request_digest,
        outcome: parsed.record.outcome,
        recorded_at: parsed.record.recorded_at,
        ...(parsed.record.detail === undefined ? {} : { detail: parsed.record.detail }),
      },
    };
  }
}
