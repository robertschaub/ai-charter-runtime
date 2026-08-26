// SPDX-License-Identifier: MIT
/** Services-host client for the two authorization endpoints it alone may call. */
import {
  AUTHORITY_DEFECTS,
  commitToken,
  nativeCommitVerifyResult,
  id,
  worldId as worldIdSchema,
  type AuthorizationCore,
  type CommitVerifyInput,
  type CommitVerifyResult,
  type EffectOutcomeReportInput,
  type EffectOutcomeReportResult,
  type NativeCommitVerifyResult,
} from 'gate-core';
import { z } from 'zod';

import { ServicesAuthorizationHttpError } from './authorizationHttpError.js';
export { ServicesAuthorizationHttpError } from './authorizationHttpError.js';

const commitDefect = z.enum([
  ...AUTHORITY_DEFECTS,
  'not-allowed',
  'counter-invalid',
  'expired-ruling',
  'system-use-unavailable',
  'native-proposal-requires-preparation',
  'unauthorized-caller',
]);
const commitResult = z.discriminatedUnion('ok', [
  z.object({ ok: z.literal(false), defect: commitDefect }).strict(),
  z.object({ ok: z.literal(true), token: commitToken, commitmentId: id, recordEntryId: id }).strict(),
]);
const outcomeResult = z.discriminatedUnion('accepted', [
  z
    .object({
      accepted: z.literal(true),
      status: z.enum(['recorded', 'already-recorded', 'retry-recorded']),
      recordEntryId: id.nullable(),
    })
    .strict(),
  z
    .object({
      accepted: z.literal(false),
      defect: z.enum([
        'unauthorized-reporter',
        'missing-commitment',
        'binding-mismatch',
        'conflicting-outcome',
        'terminal-commitment',
      ]),
    })
    .strict(),
]);
const accessReportResult = z.object({ entry_id: id }).strict();

export type ServicesDataAccessRoute =
  | 'services.execute'
  | 'services.native-execute'
  | 'services.effect-probe'
  | 'services.registry-read';
export type ServicesAccessRoute = ServicesDataAccessRoute | 'services.unauthenticated-ingress';

export type ServicesAccessDenial =
  | {
      readonly route: ServicesDataAccessRoute;
      readonly authenticated_actor: null;
      readonly outcome: 'unauthenticated';
      readonly http_status: 401;
    }
  | {
      readonly route: ServicesDataAccessRoute;
      readonly authenticated_actor: 'proc:orchestrator' | 'proc:authz';
      readonly outcome: 'forbidden';
      readonly http_status: 403;
    }
  | {
      readonly route: 'services.unauthenticated-ingress';
      readonly authenticated_actor: null;
      readonly outcome: 'rate-limited';
      readonly http_status: 429;
      readonly suppressed_count: number;
      readonly suppression_window_ms: number;
      readonly suppression_final: boolean;
    };

async function responseJson(response: Response, maxBytes: number): Promise<unknown> {
  const declared = response.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) throw new Error('authorization response exceeded limit');
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) throw new Error('authorization response exceeded limit');
  try {
    return JSON.parse(buffer.toString('utf8')) as unknown;
  } catch {
    throw new Error('authorization response was not JSON');
  }
}

export interface ServicesAuthorizationHttpClientOptions {
  readonly origin: string;
  readonly token: string;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly fetchImplementation?: typeof fetch;
}

export class ServicesAuthorizationHttpClient
  implements Pick<AuthorizationCore, 'commitVerify' | 'reportEffectOutcome'>
{
  readonly #origin: string;
  readonly #token: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetch: typeof fetch;

  constructor(options: ServicesAuthorizationHttpClientOptions) {
    this.#origin = new URL(options.origin).origin;
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    this.#maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024;
    this.#fetch = options.fetchImplementation ?? fetch;
  }

  async #post(path: string, body: unknown): Promise<unknown> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#origin), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.#token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch {
      throw new Error('authorization service unavailable');
    }
    const parsed = await responseJson(response, this.#maxResponseBytes);
    if (!response.ok) {
      const code = typeof parsed === 'object' && parsed !== null &&
        'error' in parsed && typeof parsed.error === 'string' ? parsed.error : null;
      throw new ServicesAuthorizationHttpError(response.status, code);
    }
    return parsed;
  }

  async commitVerify(input: CommitVerifyInput): Promise<CommitVerifyResult> {
    return commitResult.parse(
      await this.#post(`/w/${input.intent.world_id}/commit-verify`, {
        ruling_id: input.rulingId,
        intent: input.intent,
        services_host_boot_id: input.servicesHostBootId,
        services_ledger_id: input.servicesLedgerId,
      }),
    ) as CommitVerifyResult;
  }

  async commitVerifyPreparation(
    worldId: string,
    preparationId: string,
    servicesHostBootId: string,
    servicesLedgerId: string,
  ): Promise<NativeCommitVerifyResult> {
    const world = worldIdSchema.parse(worldId);
    const preparation = id.parse(preparationId);
    return nativeCommitVerifyResult.parse(
      await this.#post(`/w/${world}/execution-preparations/${preparation}/commit-verify`, {
        services_host_boot_id: id.parse(servicesHostBootId),
        services_ledger_id: id.parse(servicesLedgerId),
      }),
    );
  }

  async reportEffectOutcome(input: EffectOutcomeReportInput): Promise<EffectOutcomeReportResult> {
    return outcomeResult.parse(
      await this.#post(`/w/${input.worldId}/effects/${input.effectId}/outcome`, {
        world_id: input.worldId,
        commitment_id: input.commitmentId,
        effect_id: input.effectId,
        idempotency_key: input.idempotencyKey,
        effect_request_digest: input.effectRequestDigest,
        services_host_boot_id: input.servicesHostBootId,
        services_ledger_id: input.servicesLedgerId,
        outcome: input.outcome,
        recorded_at: input.recordedAt,
        ...(input.detail === undefined ? {} : { detail: input.detail }),
        delivery: input.delivery,
      }),
    ) as EffectOutcomeReportResult;
  }

  async recordAccessDenial(worldId: string, denial: ServicesAccessDenial): Promise<string> {
    const world = worldIdSchema.parse(worldId);
    const parsed = accessReportResult.parse(await this.#post(`/w/${world}/access-events`, denial));
    return parsed.entry_id;
  }
}
