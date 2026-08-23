// SPDX-License-Identifier: MIT
/** Mock services process facade: obtain commit-verify itself, execute, then report outcome. */
import type {
  AuthorizationCore,
  CommitDefect,
  CommitVerifyResult,
  EffectIntent,
  EffectOutcomeReportResult,
  NativeCommitVerifyResult,
  NativeServicesExecutionResult,
} from 'gate-core';
import { nativeServicesExecutionResult } from 'gate-core';

import { EffectLedger, type ProposedEffectOutcome, type ServiceEffectRecord } from './effectLedger.js';
import { ServicesAuthorizationHttpError } from './authorizationHttpClient.js';

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

type ServicesAuthorization = Pick<AuthorizationCore, 'commitVerify' | 'reportEffectOutcome'> & {
  commitVerifyPreparation?(
    worldId: string,
    preparationId: string,
    servicesHostBootId: string,
    servicesLedgerId: string,
  ): Promise<NativeCommitVerifyResult>;
};

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
  readonly #nativeInFlight = new Map<string, Promise<NativeServicesExecutionResult>>();

  constructor(
    readonly ledger: EffectLedger,
    readonly authorization: ServicesAuthorization,
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
      servicesLedgerId: executed.record.services_ledger_id,
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

  async executePrepared(worldId: string, preparationId: string): Promise<NativeServicesExecutionResult> {
    const pending = this.#nativeInFlight.get(preparationId);
    if (pending !== undefined) return pending;
    const operation = this.#executePrepared(worldId, preparationId);
    this.#nativeInFlight.set(preparationId, operation);
    try {
      return await operation;
    } finally {
      this.#nativeInFlight.delete(preparationId);
    }
  }

  async #executePrepared(worldId: string, preparationId: string): Promise<NativeServicesExecutionResult> {
    const consume = this.authorization.commitVerifyPreparation;
    if (consume === undefined) {
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'preparation-unavailable', effect_outcome: null, recorded_at: null });
    }
    let committed: NativeCommitVerifyResult;
    try {
      committed = await consume.call(
        this.authorization,
        worldId,
        preparationId,
        this.ledger.bootId,
        this.ledger.ledgerId,
      );
    } catch (error) {
      if (error instanceof ServicesAuthorizationHttpError &&
        ['not-found', 'conflict', 'currentness', 'unavailable'].includes(error.code ?? '')) {
        return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'preparation-unavailable', effect_outcome: null, recorded_at: null });
      }
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'indeterminate', effect_outcome: 'unknown-reconciliation-required', recorded_at: null });
    }
    if (committed.execution_preparation_id !== preparationId) {
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'indeterminate', effect_outcome: 'unknown-reconciliation-required', recorded_at: null });
    }
    if (committed.state === 'commit-denied') {
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'commit-denied', effect_outcome: null, recorded_at: null });
    }
    if (committed.state === 'commit-escalated') {
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'commit-escalated', effect_outcome: null, recorded_at: null });
    }
    if (committed.state === 'already-consumed') {
      if (committed.effect_outcome !== null) {
        const state = committed.effect_outcome === 'success' || committed.effect_outcome === 'failed'
          ? 'effect-recorded'
          : committed.effect_outcome === 'no-effect'
            ? 'no-effect'
            : 'indeterminate';
        return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state, effect_outcome: committed.effect_outcome, recorded_at: committed.recorded_at });
      }
      const existing = this.ledger.probe(committed.idempotency_key);
      if (existing.state === 'absent') {
        return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'indeterminate', effect_outcome: 'unknown-reconciliation-required', recorded_at: null });
      }
      const record = existing.record;
      const report = await this.authorization.reportEffectOutcome({
        worldId: record.world_id,
        commitmentId: committed.commitment_id,
        effectId: record.effect_id,
        idempotencyKey: record.idempotency_key,
        effectRequestDigest: record.effect_request_digest,
        servicesHostBootId: record.services_host_boot_id,
        servicesLedgerId: record.services_ledger_id,
        outcome: record.outcome,
        recordedAt: record.recorded_at,
        ...(record.detail === undefined ? {} : { detail: record.detail }),
        delivery: 'retry',
        actor: SERVICES_HOST,
      });
      if (!report.accepted) {
        return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'indeterminate', effect_outcome: 'unknown-reconciliation-required', recorded_at: record.recorded_at });
      }
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'effect-recorded', effect_outcome: record.outcome, recorded_at: record.recorded_at });
    }
    const handler = this.#handlers[`${committed.intent.service}:${committed.intent.action_class}`] ?? (() => ({
      outcome: 'failed' as const,
      detail: 'The mock services host has no implementation for this service action.',
    }));
    const executed = this.ledger.execute(committed.token, committed.intent, handler);
    if (!executed.accepted) {
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'indeterminate', effect_outcome: 'unknown-reconciliation-required', recorded_at: null });
    }
    const report = await this.authorization.reportEffectOutcome({
      worldId: executed.record.world_id,
      commitmentId: committed.commitment_id,
      effectId: executed.record.effect_id,
      idempotencyKey: executed.record.idempotency_key,
      effectRequestDigest: executed.record.effect_request_digest,
      servicesHostBootId: executed.record.services_host_boot_id,
      servicesLedgerId: executed.record.services_ledger_id,
      outcome: executed.record.outcome,
      recordedAt: executed.record.recorded_at,
      ...(executed.record.detail === undefined ? {} : { detail: executed.record.detail }),
      delivery: executed.delivery,
      actor: SERVICES_HOST,
    });
    if (!report.accepted) {
      return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'indeterminate', effect_outcome: 'unknown-reconciliation-required', recorded_at: executed.record.recorded_at });
    }
    return nativeServicesExecutionResult.parse({ execution_preparation_id: preparationId, state: 'effect-recorded', effect_outcome: executed.record.outcome, recorded_at: executed.record.recorded_at });
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
      servicesLedgerId: this.ledger.ledgerId,
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
