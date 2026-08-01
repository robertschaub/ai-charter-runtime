// SPDX-License-Identifier: MIT
/** Mock services process facade: obtain commit-verify itself, execute, then report outcome. */
import type {
  AuthorizationCore,
  CommitDefect,
  CommitVerifyResult,
  EffectIntent,
  EffectOutcomeReportResult,
} from 'gate-core';

import { EffectLedger, type ProposedEffectOutcome, type ServiceEffectRecord } from './effectLedger.js';

const SERVICES_HOST = { credential: 'proc:services_host', claimed_role: null } as const;

export type ServicesHostExecution =
  | { readonly ok: false; readonly stage: 'commit-verify'; readonly defect: CommitDefect }
  | {
      readonly ok: false;
      readonly stage: 'token-verification';
      readonly defect: 'malformed' | 'invalid-mac' | 'expired' | 'binding-mismatch';
    }
  | { readonly ok: false; readonly stage: 'outcome-report'; readonly report: EffectOutcomeReportResult }
  | {
      readonly ok: true;
      readonly commitmentId: string;
      readonly delivery: 'executed' | 'retry';
      readonly effect: ServiceEffectRecord;
      readonly report: EffectOutcomeReportResult;
    };

export type MockServiceHandler = (intent: EffectIntent) => ProposedEffectOutcome;

const DEFAULT_HANDLERS: Readonly<Record<string, MockServiceHandler>> = {
  'filing:grant-filing': () => ({
    outcome: 'success',
    detail: 'Synthetic filing accepted by the local mock service.',
  }),
  'registry:registry-read': () => ({
    outcome: 'success',
    detail: 'Synthetic registry record retrieved by the local mock service.',
  }),
  'notification:notification': () => ({
    outcome: 'success',
    detail: 'Synthetic notification accepted by the local mock service.',
  }),
};

export class MockServicesHost {
  readonly #handlers: Readonly<Record<string, MockServiceHandler>>;
  readonly #commitments = new Map<string, Extract<CommitVerifyResult, { ok: true }>>();
  readonly #commitInFlight = new Map<string, Promise<CommitVerifyResult>>();

  constructor(
    readonly ledger: EffectLedger,
    readonly authorization: Pick<AuthorizationCore, 'commitVerify' | 'reportEffectOutcome'>,
    handlers: Readonly<Record<string, MockServiceHandler>> = DEFAULT_HANDLERS,
  ) {
    this.#handlers = handlers;
  }

  async execute(rulingId: string, intent: EffectIntent): Promise<ServicesHostExecution> {
    const committed = await this.#obtainCommitment(rulingId, intent);
    if (!committed.ok) return { ok: false, stage: 'commit-verify', defect: committed.defect };
    const handler = this.#handlers[`${intent.service}:${intent.action_class}`] ?? (() => ({
      outcome: 'failed' as const,
      detail: 'The mock services host has no implementation for this service action.',
    }));
    const executed = this.ledger.execute(committed.token, intent, handler);
    if (!executed.accepted) {
      return { ok: false, stage: 'token-verification', defect: executed.reason };
    }
    const report = await this.authorization.reportEffectOutcome({
      worldId: executed.record.world_id,
      commitmentId: committed.commitmentId,
      effectId: executed.record.effect_id,
      idempotencyKey: executed.record.idempotency_key,
      effectRequestDigest: executed.record.effect_request_digest,
      servicesHostBootId: executed.record.services_host_boot_id,
      outcome: executed.record.outcome,
      recordedAt: executed.record.recorded_at,
      ...(executed.record.detail === undefined ? {} : { detail: executed.record.detail }),
      delivery: executed.delivery,
      actor: SERVICES_HOST,
    });
    if (!report.accepted) return { ok: false, stage: 'outcome-report', report };
    return {
      ok: true,
      commitmentId: committed.commitmentId,
      delivery: executed.delivery,
      effect: executed.record,
      report,
    };
  }

  async #obtainCommitment(rulingId: string, intent: EffectIntent): Promise<CommitVerifyResult> {
    const cacheKey = `${intent.world_id}\u0000${rulingId}`;
    const cached = this.#commitments.get(cacheKey);
    if (cached !== undefined) return cached;
    const pending = this.#commitInFlight.get(cacheKey);
    if (pending !== undefined) return pending;
    const request = this.authorization.commitVerify({
      rulingId,
      intent,
      servicesHostBootId: this.ledger.bootId,
      actor: SERVICES_HOST,
    });
    this.#commitInFlight.set(cacheKey, request);
    try {
      const result = await request;
      if (result.ok) this.#commitments.set(cacheKey, result);
      return result;
    } finally {
      this.#commitInFlight.delete(cacheKey);
    }
  }
}
