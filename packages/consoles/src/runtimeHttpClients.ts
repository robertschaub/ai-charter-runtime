// SPDX-License-Identifier: MIT
/** Narrow HTTP clients held by the orchestrator process. */
import {
  classToken,
  effectIntent,
  frozenProposal,
  gateRuling,
  id,
  type EffectIntent,
  type FrozenProposal,
  type RuleProposalResult,
} from 'gate-core';
import type { ServicesHostExecution } from 'services-mock';
import { z } from 'zod';

const ruleResult = z
  .object({
    ruling: gateRuling,
    escalationId: id.nullable(),
    recordEntryId: id,
    mandateNarrowed: z.boolean(),
  })
  .strict();

async function responseJson(response: Response, maxBytes: number): Promise<unknown> {
  const declared = response.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) throw new Error('runtime response exceeded limit');
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) throw new Error('runtime response exceeded limit');
  try {
    return JSON.parse(buffer.toString('utf8')) as unknown;
  } catch {
    throw new Error('runtime response was not JSON');
  }
}

function containsTokenField(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsTokenField);
  if (typeof value !== 'object' || value === null) return false;
  return Object.entries(value).some(([key, nested]) => key.toLowerCase().includes('token') || containsTokenField(nested));
}

interface ClientOptions {
  readonly origin: string;
  readonly token: string;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly fetchImplementation?: typeof fetch;
}

abstract class JsonHttpClient {
  readonly #origin: string;
  readonly #token: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetch: typeof fetch;

  constructor(options: ClientOptions) {
    this.#origin = new URL(options.origin).origin;
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    this.#maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024;
    this.#fetch = options.fetchImplementation ?? fetch;
  }

  protected async post(path: string, body: unknown): Promise<unknown> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#origin), {
        method: 'POST',
        headers: { authorization: `Bearer ${this.#token}`, 'content-type': 'application/json' },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch {
      throw new Error('runtime dependency unavailable');
    }
    const parsed = await responseJson(response, this.#maxResponseBytes);
    if (!response.ok) throw new Error(`runtime dependency rejected transport request with HTTP ${response.status}`);
    return parsed;
  }
}

export class OrchestratorAuthorizationHttpClient extends JsonHttpClient {
  async ruleCommit(input: {
    readonly proposal: FrozenProposal;
    readonly service: string;
    readonly actionClass: string;
  }): Promise<RuleProposalResult> {
    const proposal = frozenProposal.parse(input.proposal);
    const service = id.parse(input.service);
    const actionClass = classToken.parse(input.actionClass);
    return ruleResult.parse(
      await this.post(`/w/${proposal.world_id}/proposals`, {
        gate: 'commit',
        proposal,
        service,
        action_class: actionClass,
      }),
    ) as RuleProposalResult;
  }
}

export class OrchestratorServicesHttpClient extends JsonHttpClient {
  async execute(rulingIdInput: string, intentInput: EffectIntent): Promise<ServicesHostExecution> {
    const rulingId = id.parse(rulingIdInput);
    const intent = effectIntent.parse(intentInput);
    const result = await this.post(`/w/${intent.world_id}/services/${intent.service}/execute`, {
      ruling_id: rulingId,
      intent,
    });
    if (containsTokenField(result)) throw new Error('services response exposed a token field');
    return z.object({ ok: z.boolean() }).passthrough().parse(result) as ServicesHostExecution;
  }
}
