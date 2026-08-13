// SPDX-License-Identifier: AGPL-3.0-only
/** M6.1 authorization-owned live-screening call lifecycle. */
import { randomUUID } from 'node:crypto';

import { z } from 'zod';

import { conversationProjection } from './authorizationProjection.js';
import type { ScreeningResolution } from './authorizationCore.js';
import { canonicalize } from './canonicalize.js';
import {
  ConversationProjectionService,
  ConversationProjectionServiceError,
  type LiveScreeningProjectionResolution,
} from './conversationProjectionService.js';
import { evaluatePolicy } from './evaluator.js';
import { digestFor, verifyDigest } from './hash.js';
import type { LoadedPolicy } from './policyLoader.js';
import {
  SCREENING_MAX_OUTPUT_TOKENS,
  SCREENING_RESPONSE_SCHEMA_ID,
  cardSlug,
  gate,
  id,
  integer,
  modelId,
  screeningCallAdmittedRecord,
  screeningCallFailedRecord,
  screeningCallFailureRequest,
  screeningCallOpenRecord,
  screeningCallOutputRequest,
  screeningCallTerminalProjection,
  screeningProviderResponse,
  timestamp,
  type EvidenceRef,
  type FrozenProposal,
  type Gate,
  type Mandate,
  type ScreeningCallFailureRequest,
  type ScreeningCallOpenRecord,
  type ScreeningCallOutputRequest,
  type ScreeningCallRecord,
  type ScreeningCallTerminalProjection,
  type WalOp,
} from './schemas/index.js';
import { compareServedId } from './servedModel.js';
import { mandateVersionKey, type WorldState } from './state.js';
import { assertNoDuplicateJsonKeys } from './strictJson.js';
import type { TransactionActor, WalStore } from './walStore.js';

export const SCREENING_PROVIDER_JSON_SCHEMA = Object.freeze({
  type: 'array',
  maxItems: 16,
  items: {
    type: 'object',
    additionalProperties: false,
    required: ['signal', 'suspect_item_id', 'confidence_pct', 'rationale'],
    properties: {
      signal: {
        type: 'string',
        enum: ['injection_suspicion', 'evidence_conflict', 'unconfirmed_inference_as_fact', 'scope_drift'],
      },
      suspect_item_id: { oneOf: [{ type: 'string', pattern: '^[a-z0-9][a-z0-9_.:-]*$' }, { type: 'null' }] },
      confidence_pct: { type: 'integer', minimum: 0, maximum: 100 },
      rationale: { type: 'string', minLength: 1, maxLength: 1024 },
    },
  },
} as const);
export const SCREENING_RESPONSE_SCHEMA_DIGEST = digestFor(
  'screening-response-schema',
  SCREENING_PROVIDER_JSON_SCHEMA,
);
export const SCREENING_RESPONSE_FORMAT = Object.freeze({
  type: 'json_schema',
  json_schema: {
    name: 'screening_signals',
    strict: true,
    schema: SCREENING_PROVIDER_JSON_SCHEMA,
  },
} as const);
export const SCREENING_SYSTEM_INSTRUCTION = [
  'Inspect only the supplied authorization projection for the named precommit gate.',
  'Return only the strict screening-signals@1 JSON array.',
  'Do not authorize, select a disposition, infer hidden context, or refer to items outside the projection.',
].join(' ');

export const screeningCallStart = z
  .object({
    kind: z.literal('screening_required'),
    call_id: id,
    proposal_id: id,
    proposal_run_id: id,
    gate: gate.refine((value) => value === 'submit' || value === 'verify'),
    card_id: cardSlug,
    card_version: integer.min(1),
    requested_id: modelId,
    expires_at: timestamp,
    max_output_tokens: z.literal(SCREENING_MAX_OUTPUT_TOKENS),
    tools_allowed: z.literal(false),
    response_schema_id: z.literal(SCREENING_RESPONSE_SCHEMA_ID),
    response_schema_digest: z.literal(SCREENING_RESPONSE_SCHEMA_DIGEST),
    projection: conversationProjection.refine((value) => value.role === 'screening' && value.items.length > 0),
  })
  .strict();
export type ScreeningCallStart = z.infer<typeof screeningCallStart>;

export class ScreeningCallError extends Error {
  constructor(
    readonly code: 'forbidden' | 'not-found' | 'invalid-scope' | 'unavailable',
    message: string,
  ) {
    super(message);
    this.name = 'ScreeningCallError';
  }
}

export interface ScreeningCallServiceOptions {
  readonly store: WalStore;
  readonly projections: ConversationProjectionService;
  readonly policy: LoadedPolicy;
  readonly authorizationBootId: string;
  readonly callTtlMs?: number;
  readonly nextCallId?: () => string;
  readonly now?: () => string;
}

export interface ScreeningCallEnsureInput {
  readonly proposal: FrozenProposal;
  readonly gate: 'submit' | 'verify';
  readonly caseId: string;
  readonly proposalRunId: string;
  readonly actor: TransactionActor;
  readonly assertCurrent: (state: WorldState, at: string) => void;
}

export interface ScreeningValidation {
  readonly valid: boolean;
  readonly ops: readonly WalOp[];
}

function terminalProjection(call: Exclude<ScreeningCallRecord, ScreeningCallOpenRecord>): ScreeningCallTerminalProjection {
  return screeningCallTerminalProjection.parse({
    kind: 'screening_call_terminal',
    call_id: call.call_id,
    proposal_id: call.proposal_id,
    proposal_run_id: call.proposal_run_id,
    gate: call.gate,
    state: 'terminal',
    outcome: call.outcome,
    provider_disclosure: call.provider_disclosure,
    served_id: call.served_id,
    output_digest: call.output_digest,
    failure_reason: call.failure_reason,
    completed_at: call.completed_at,
  });
}

function skipped(provider: string | null, ids: readonly string[]): EvidenceRef {
  return {
    kind: 'screening_skipped',
    provider: provider === null ? null : cardSlug.parse(provider),
    role: 'screening',
    reason: 'resolver-error',
    suspect_item_ids: [...new Set(ids)].sort(),
  };
}

function callMatchesBinding(
  call: ScreeningCallRecord,
  proposal: FrozenProposal,
  gateName: 'submit' | 'verify',
  caseId: string,
): boolean {
  return call.proposal_id === proposal.proposal_id &&
    call.proposal_hash === proposal.proposal_hash &&
    call.gate === gateName &&
    call.case_id === caseId;
}

export class ScreeningCallService {
  readonly #store: WalStore;
  readonly #projections: ConversationProjectionService;
  readonly #policy: LoadedPolicy;
  readonly #authorizationBootId: string;
  readonly #callTtlMs: number;
  readonly #nextCallId: () => string;
  readonly #now: () => string;

  constructor(options: ScreeningCallServiceOptions) {
    this.#store = options.store;
    this.#projections = options.projections;
    this.#policy = options.policy;
    this.#authorizationBootId = id.parse(options.authorizationBootId);
    this.#callTtlMs = integer.min(1).max(300_000).parse(options.callTtlMs ?? 60_000);
    this.#nextCallId = options.nextCallId ?? (() => `scr_${randomUUID()}`);
    this.#now = options.now ?? (() => new Date().toISOString());
  }

  #requireOrchestrator(actor: TransactionActor): void {
    if (actor.credential !== 'proc:orchestrator') {
      throw new ScreeningCallError('forbidden', 'only the orchestrator process may advance screening calls');
    }
  }

  #mandate(state: WorldState, proposal: FrozenProposal): Mandate | undefined {
    return state.mandates.get(mandateVersionKey(proposal.mandate_ref.mandate_id, proposal.mandate_ref.version));
  }

  #required(state: WorldState, proposal: FrozenProposal, gateName: 'submit' | 'verify', at: string): boolean {
    const mandateValue = this.#mandate(state, proposal);
    if (mandateValue === undefined) return false;
    const evaluated = evaluatePolicy(this.#policy.policy, {
      gate: gateName,
      proposal,
      mandate: mandateValue,
      context: {},
      counters: {},
      signals: [],
      screeningPerformed: true,
      patternEvents: state.patternEvents,
      now: at,
      authorityDefects: [],
    });
    return evaluated.matchedRuleId !== null &&
      this.#policy.policy.rules.some(
        (rule) => rule.id === evaluated.matchedRuleId && rule.verdict === 'allow' && rule.screening_required === true,
      );
  }

  #resolution(
    proposal: FrozenProposal,
    caseId: string,
    state: WorldState,
    at: string,
  ): LiveScreeningProjectionResolution {
    return this.#projections.liveScreeningProjection(proposal, caseId, state, at);
  }

  #isCurrent(
    call: ScreeningCallRecord,
    proposal: FrozenProposal,
    caseId: string,
    state: WorldState,
    at: string,
  ): boolean {
    if (
      call.authorization_boot_id !== this.#authorizationBootId ||
      at >= call.expires_at ||
      state.policy?.policy_version !== call.policy_version ||
      state.policy.policy_content_digest !== call.policy_content_digest ||
      state.policy.evaluator_build_id !== call.evaluator_build_id
    ) return false;
    try {
      const resolved = this.#resolution(proposal, caseId, state, at);
      return resolved.approval.card_id === call.card_id &&
        resolved.approval.card_version === call.card_version &&
        resolved.approval.card_digest === call.card_digest &&
        resolved.approval.requested_id === call.requested_id &&
        resolved.inspection.keyId === call.card_key_id &&
        canonicalize(resolved.systemUseDecision) === canonicalize(call.system_use_decision) &&
        verifyDigest(call.projection_digest, digestFor('screening-projection', resolved.projection)) &&
        canonicalize(resolved.projection.items.map((item) => item.id)) === canonicalize(call.projection_item_ids);
    } catch {
      return false;
    }
  }

  #find(state: WorldState, proposal: FrozenProposal, gateName: 'submit' | 'verify'): ScreeningCallRecord | undefined {
    return [...state.screeningCalls.values()].find(
      (call) => call.proposal_hash === proposal.proposal_hash &&
        call.gate === gateName &&
        call.screening_role === 'screening' &&
        call.policy_version === this.#policy.policy.policy_version,
    );
  }

  #start(call: ScreeningCallOpenRecord, resolution: LiveScreeningProjectionResolution): ScreeningCallStart {
    return screeningCallStart.parse({
      kind: 'screening_required',
      call_id: call.call_id,
      proposal_id: call.proposal_id,
      proposal_run_id: call.proposal_run_id,
      gate: call.gate,
      card_id: call.card_id,
      card_version: call.card_version,
      requested_id: call.requested_id,
      expires_at: call.expires_at,
      max_output_tokens: call.max_output_tokens,
      tools_allowed: call.tools_allowed,
      response_schema_id: call.response_schema_id,
      response_schema_digest: call.response_schema_digest,
      projection: resolution.projection,
    });
  }

  async ensure(input: ScreeningCallEnsureInput): Promise<ScreeningCallStart | null> {
    this.#requireOrchestrator(input.actor);
    const proposal = input.proposal;
    const gateName = z.enum(['submit', 'verify']).parse(input.gate);
    const caseId = id.parse(input.caseId);
    const proposalRunId = id.parse(input.proposalRunId);
    const callId = id.parse(this.#nextCallId());
    const completed = await this.#store.transactWithState<ScreeningCallStart | null>(
      'screening_call_ensure',
      input.actor,
      (state, at) => {
        input.assertCurrent(state, at);
        if (!this.#required(state, proposal, gateName, at)) return { ops: [], result: null };
        const existing = this.#find(state, proposal, gateName);
        if (existing !== undefined) {
          if (existing.state === 'terminal') return { ops: [], result: null };
          if (at >= existing.expires_at || !this.#isCurrent(existing, proposal, caseId, state, at)) {
            return {
              ops: [{
                op: 'screening_call.fail',
                call_id: existing.call_id,
                provider_disclosure: 'possible',
                served_id: null,
                model_resolution: null,
                output_digest: null,
                failure_reason: at >= existing.expires_at ? 'provider-timeout' : 'authorization-invalidated',
                completed_at: at,
              }],
              result: null,
            };
          }
          return { ops: [], result: this.#start(existing, this.#resolution(proposal, caseId, state, at)) };
        }
        let resolved: LiveScreeningProjectionResolution;
        try {
          resolved = this.#resolution(proposal, caseId, state, at);
        } catch (error) {
          if (error instanceof ConversationProjectionServiceError) return { ops: [], result: null };
          throw error;
        }
        const projectionItemIds = resolved.projection.items.map((item) => item.id);
        const call = screeningCallOpenRecord.parse({
          kind: 'screening_call_lifecycle',
          world_id: proposal.world_id,
          call_id: callId,
          authorization_boot_id: this.#authorizationBootId,
          case_id: caseId,
          proposal_id: proposal.proposal_id,
          proposal_run_id: proposalRunId,
          proposal_hash: proposal.proposal_hash,
          gate: gateName,
          screening_role: 'screening',
          policy_version: this.#policy.policy.policy_version,
          policy_content_digest: this.#policy.policyContentDigest,
          evaluator_build_id: this.#policy.evaluatorBuildId,
          mandate_id: proposal.mandate_ref.mandate_id,
          mandate_version: proposal.mandate_ref.version,
          card_id: resolved.approval.card_id,
          card_version: resolved.approval.card_version,
          card_digest: resolved.approval.card_digest,
          card_key_id: resolved.inspection.keyId,
          requested_id: resolved.approval.requested_id,
          projection_digest: digestFor('screening-projection', resolved.projection),
          projection_item_count: projectionItemIds.length,
          projection_item_ids: projectionItemIds,
          system_use_decision: resolved.systemUseDecision,
          response_schema_id: SCREENING_RESPONSE_SCHEMA_ID,
          response_schema_digest: SCREENING_RESPONSE_SCHEMA_DIGEST,
          max_output_tokens: SCREENING_MAX_OUTPUT_TOKENS,
          tools_allowed: false,
          opened_at: at,
          expires_at: timestamp.parse(new Date(Date.parse(at) + this.#callTtlMs).toISOString()),
          state: 'open',
          outcome: 'indeterminate',
          provider_disclosure: 'possible',
          completed_at: null,
          served_id: null,
          model_resolution: null,
          output_digest: null,
          failure_reason: null,
          signals: [],
        });
        if (projectionItemIds.length === 0) {
          return {
            ops: [
              { op: 'screening_call.open', call },
              {
                op: 'screening_call.fail',
                call_id: call.call_id,
                provider_disclosure: 'possible',
                served_id: null,
                model_resolution: null,
                output_digest: null,
                failure_reason: 'authorization-invalidated',
                completed_at: at,
              },
            ],
            result: null,
          };
        }
        return { ops: [{ op: 'screening_call.open', call }], result: this.#start(call, resolved) };
      },
    );
    return completed.result;
  }

  startFor(
    proposal: FrozenProposal,
    gateInput: 'submit' | 'verify',
    caseIdInput: string,
  ): ScreeningCallStart | null {
    const caseId = id.parse(caseIdInput);
    const state = this.#store.snapshot();
    const call = this.#find(state, proposal, gateInput);
    if (
      call === undefined ||
      call.state !== 'open' ||
      !callMatchesBinding(call, proposal, gateInput, caseId)
    ) return null;
    const at = timestamp.parse(this.#now());
    if (at >= call.expires_at || !this.#isCurrent(call, proposal, caseId, state, at)) return null;
    try {
      return this.#start(call, this.#resolution(proposal, caseId, state, at));
    } catch {
      return null;
    }
  }

  resolve(proposal: FrozenProposal, gateInput: Gate, caseIdInput?: string): ScreeningResolution {
    if (gateInput !== 'submit' && gateInput !== 'verify') {
      return { performed: true, signals: [], evidenceRefs: [] };
    }
    const caseId = caseIdInput ?? '';
    const state = this.#store.snapshot();
    const call = this.#find(state, proposal, gateInput);
    if (call === undefined || !callMatchesBinding(call, proposal, gateInput, caseId)) {
      return { performed: false, signals: [], evidenceRefs: [skipped(null, [])] };
    }
    if (call.state !== 'terminal' || call.outcome !== 'admitted') {
      return { performed: false, signals: [], evidenceRefs: [skipped(call.card_id, call.projection_item_ids)] };
    }
    try {
      const resolved = this.#resolution(proposal, caseId, state, timestamp.parse(this.#now()));
      return { performed: true, signals: call.signals, evidenceRefs: [resolved.evidenceRef] };
    } catch {
      return { performed: false, signals: [], evidenceRefs: [skipped(call.card_id, call.projection_item_ids)] };
    }
  }

  validate(
    resolution: ScreeningResolution,
    proposal: FrozenProposal,
    gateInput: Gate,
    caseIdInput: string | undefined,
    state: WorldState,
    at: string,
  ): ScreeningValidation {
    if (gateInput !== 'submit' && gateInput !== 'verify') return { valid: true, ops: [] };
    const caseId = caseIdInput ?? '';
    const call = this.#find(state, proposal, gateInput);
    if (
      call === undefined ||
      !callMatchesBinding(call, proposal, gateInput, caseId) ||
      call.state !== 'terminal' ||
      call.outcome !== 'admitted'
    ) {
      return { valid: canonicalize(resolution) === canonicalize({ performed: false, signals: [], evidenceRefs: [skipped(call?.card_id ?? null, call?.projection_item_ids ?? [])] }), ops: [] };
    }
    if (!this.#isCurrent(call, proposal, caseId, state, at)) {
      return {
        valid: false,
        ops: [{
          op: 'screening_call.invalidate',
          call_id: call.call_id,
          failure_reason: 'authorization-invalidated',
          completed_at: at,
        }],
      };
    }
    const resolved = this.#resolution(proposal, caseId, state, at);
    const expected: ScreeningResolution = { performed: true, signals: call.signals, evidenceRefs: [resolved.evidenceRef] };
    return { valid: canonicalize(resolution) === canonicalize(expected), ops: [] };
  }

  async admit(
    callIdInput: string,
    requestInput: ScreeningCallOutputRequest,
    actor: TransactionActor,
  ): Promise<ScreeningCallTerminalProjection> {
    this.#requireOrchestrator(actor);
    const callId = id.parse(callIdInput);
    const request = screeningCallOutputRequest.parse(requestInput);
    const outputDigest = digestFor('screening-output', { call_id: callId, content: request.content });
    const completed = await this.#store.transactWithState<ScreeningCallTerminalProjection>(
      'screening_call_admit',
      actor,
      (state, at) => {
        const current = state.screeningCalls.get(callId);
        if (current === undefined) throw new ScreeningCallError('not-found', 'screening call does not exist');
        if (current.state === 'terminal') {
          if (current.served_id === request.served_id && current.output_digest === outputDigest) {
            return { ops: [], result: terminalProjection(current) };
          }
          throw new ScreeningCallError('invalid-scope', 'screening call already has different terminal evidence');
        }
        const proposal = state.proposals.get(current.proposal_id);
        if (proposal === undefined) throw new ScreeningCallError('unavailable', 'screening proposal is unavailable');
        let resolved: LiveScreeningProjectionResolution | null = null;
        let currentnessFailure: 'authorization-invalidated' | 'system-use-invalidated' = 'authorization-invalidated';
        try {
          resolved = this.#resolution(proposal, current.case_id, state, at);
        } catch (error) {
          if (error instanceof ConversationProjectionServiceError && error.code === 'system-use-unavailable') {
            currentnessFailure = 'system-use-invalidated';
          }
          resolved = null;
        }
        const inspection = resolved?.inspection;
        const modelResolution = inspection === undefined
          ? 'mismatch' as const
          : compareServedId(current.requested_id, inspection.card.model.resolution.policy, request.served_id);
        const fail = (failureReason: 'provider-timeout' | 'malformed-response' | 'authorization-invalidated' | 'system-use-invalidated') => {
          const failed = screeningCallFailedRecord.parse({
            ...current,
            state: 'terminal',
            outcome: 'failed',
            provider_disclosure: 'confirmed',
            completed_at: at,
            served_id: request.served_id,
            model_resolution: modelResolution,
            output_digest: outputDigest,
            failure_reason: failureReason,
            signals: [],
          });
          return {
            ops: [{
              op: 'screening_call.fail' as const,
              call_id: callId,
              provider_disclosure: 'confirmed' as const,
              served_id: request.served_id,
              model_resolution: modelResolution,
              output_digest: outputDigest,
              failure_reason: failureReason,
              completed_at: at,
            }],
            result: terminalProjection(failed),
          };
        };
        if (at >= current.expires_at) return fail('provider-timeout');
        if (resolved === null || !this.#isCurrent(current, proposal, current.case_id, state, at)) {
          return fail(currentnessFailure);
        }
        if (modelResolution === 'mismatch') return fail('authorization-invalidated');
        let parsed: z.infer<typeof screeningProviderResponse>;
        try {
          assertNoDuplicateJsonKeys(request.content);
          parsed = screeningProviderResponse.parse(JSON.parse(request.content) as unknown);
        } catch {
          return fail('malformed-response');
        }
        const allowedIds = new Set(current.projection_item_ids);
        if (parsed.some((signal) => signal.suspect_item_id !== null && !allowedIds.has(signal.suspect_item_id))) {
          return fail('malformed-response');
        }
        const signals = parsed.map((signal) => ({
          kind: 'screening_signal' as const,
          signal: signal.signal,
          suspect_item_id: signal.suspect_item_id,
          confidence_pct: signal.confidence_pct,
          rationale: signal.rationale,
          model_id: current.requested_id,
          model_version_reported: request.served_id,
        }));
        const admitted = screeningCallAdmittedRecord.parse({
          ...current,
          state: 'terminal',
          outcome: 'admitted',
          provider_disclosure: 'confirmed',
          completed_at: at,
          served_id: request.served_id,
          model_resolution: modelResolution,
          output_digest: outputDigest,
          failure_reason: null,
          signals,
        });
        return {
          ops: [{
            op: 'screening_call.complete',
            call_id: callId,
            served_id: request.served_id,
            model_resolution: modelResolution,
            output_digest: outputDigest,
            signals,
            completed_at: at,
          }],
          result: terminalProjection(admitted),
        };
      },
    );
    return completed.result;
  }

  async fail(
    callIdInput: string,
    requestInput: ScreeningCallFailureRequest,
    actor: TransactionActor,
  ): Promise<ScreeningCallTerminalProjection> {
    this.#requireOrchestrator(actor);
    const callId = id.parse(callIdInput);
    const request = screeningCallFailureRequest.parse(requestInput);
    const completed = await this.#store.transactWithState<ScreeningCallTerminalProjection>(
      'screening_call_fail',
      actor,
      (state, at) => {
        const current = state.screeningCalls.get(callId);
        if (current === undefined) throw new ScreeningCallError('not-found', 'screening call does not exist');
        if (current.state === 'terminal') {
          if (
            current.outcome === 'failed' &&
            current.failure_reason === request.failure_reason &&
            current.provider_disclosure === request.provider_disclosure &&
            current.served_id === request.served_id &&
            current.output_digest === null
          ) return { ops: [], result: terminalProjection(current) };
          throw new ScreeningCallError('invalid-scope', 'screening call already has different terminal evidence');
        }
        const failed = screeningCallFailedRecord.parse({
          ...current,
          state: 'terminal',
          outcome: 'failed',
          provider_disclosure: request.provider_disclosure,
          completed_at: at,
          served_id: request.served_id,
          model_resolution: null,
          output_digest: null,
          failure_reason: request.failure_reason,
          signals: [],
        });
        return {
          ops: [{
            op: 'screening_call.fail',
            call_id: callId,
            provider_disclosure: request.provider_disclosure,
            served_id: request.served_id,
            model_resolution: null,
            output_digest: null,
            failure_reason: request.failure_reason,
            completed_at: at,
          }],
          result: terminalProjection(failed),
        };
      },
    );
    return completed.result;
  }
}
