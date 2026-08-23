// SPDX-License-Identifier: AGPL-3.0-only
/** M6.2 authorization-owned native execution preparation and atomic Commit continuation. */
import { randomBytes } from 'node:crypto';

import { canonicalize } from './canonicalize.js';
import { AuthorizationCore, type NativeCommitVerifyBuildResult } from './authorizationCore.js';
import { digestFor, verifyDigest } from './hash.js';
import { ProposalIntakeError, ProposalIntakeService } from './proposalIntake.js';
import {
  executionPreparationProjection,
  executionPreparationRecord,
  executionProcessProjection,
  nativeCommitVerifyResult,
  type ExecutionPreparationProjection,
  type ExecutionPreparationRecord,
  type ExecutionProcessProjection,
  type NativeCommitVerifyResult,
  type WalOp,
  id,
  timestamp,
} from './schemas/index.js';
import type { WorldState } from './state.js';
import { WalStore, type TransactionActor } from './walStore.js';

const PRECOMMIT_GATES = ['authorize', 'submit', 'verify'] as const;

export class ExecutionPreparationError extends Error {
  constructor(
    readonly code: 'forbidden' | 'not-found' | 'conflict' | 'currentness' | 'unavailable',
    message: string,
  ) {
    super(message);
    this.name = 'ExecutionPreparationError';
  }
}

export interface ExecutionPreparationServiceOptions {
  readonly store: WalStore;
  readonly authorization: AuthorizationCore;
  readonly proposalIntakes: ProposalIntakeService;
  readonly authorizationBootId: string;
  readonly authorizedAgentId: string;
  readonly ttlMs?: number;
  readonly nextId?: () => string;
  readonly now?: () => string;
}

function commitRulingProjection(ruling: WorldState['rulings'] extends Map<string, infer R> ? R : never) {
  return {
    gate: ruling.gate,
    ruling_id: ruling.ruling_id,
    verdict: ruling.verdict,
    ux_class: ruling.ux_class,
    reason: ruling.reason,
    status: ruling.status,
    validity_window: ruling.binding.validity_window,
  };
}

function precommitRulings(state: WorldState, preparation: Pick<ExecutionPreparationRecord, 'frozen_proposal_hash' | 'service' | 'action_class'>) {
  return PRECOMMIT_GATES.map((gateName) =>
    [...state.rulings.values()].filter((ruling) =>
      ruling.gate === gateName &&
      ruling.binding.frozen_proposal_hash === preparation.frozen_proposal_hash &&
      ruling.binding.service === preparation.service &&
      ruling.binding.action_class === preparation.action_class &&
      ruling.status === 'issued' &&
      ruling.verdict === 'allow'),
  );
}

export function executionProjectionForProposal(
  state: WorldState,
  proposalId: string,
  at: string,
  proposalCurrent: boolean,
): ExecutionProcessProjection {
  const proposal = state.proposals.get(proposalId);
  const origin = state.proposalOrigins.get(proposalId);
  const preparation = [...state.executionPreparations.values()]
    .filter((candidate) => candidate.proposal_id === proposalId)
    .sort((left, right) => right.issued_at.localeCompare(left.issued_at))[0];
  if (preparation === undefined) {
    const eligible = proposalCurrent && proposal !== undefined && origin !== undefined &&
      precommitRulings(state, {
        frozen_proposal_hash: proposal.proposal_hash,
        service: origin.service,
        action_class: origin.action_class,
      }).every((matches) => matches.length === 1 && at < matches[0]!.binding.validity_window.not_after);
    return executionProcessProjection.parse({
      state: eligible ? 'available' : 'unavailable',
      execution_preparation_id: null,
      expires_at: null,
      commit_ruling: null,
      escalation_id: null,
      commitment_id: null,
      effect_id: null,
      idempotency_key: null,
      effect_outcome: null,
      recorded_at: null,
    });
  }
  const ruling = preparation.commit_ruling_id === null ? undefined : state.rulings.get(preparation.commit_ruling_id);
  const commitment = preparation.commitment_id === null ? undefined : state.commitments.get(preparation.commitment_id);
  const issuedCurrent = proposalCurrent && preparation.state === 'issued' && at < preparation.expires_at &&
    precommitRulings(state, preparation).every((matches) =>
      matches.length === 1 && at < matches[0]!.binding.validity_window.not_after);
  const stateName = issuedCurrent
    ? 'prepared'
    : preparation.state !== 'consumed' || ruling === undefined
      ? 'unavailable'
      : ruling.verdict === 'deny'
        ? 'commit-denied'
        : ruling.verdict === 'escalate'
          ? 'commit-escalated'
          : commitment?.outcome === 'no-effect'
            ? 'no-effect'
            : commitment?.outcome === 'unknown-reconciliation-required'
              ? 'indeterminate'
              : preparation.effect_outcome === 'success' || preparation.effect_outcome === 'failed'
                ? 'effect-recorded'
                : 'committed';
  return executionProcessProjection.parse({
    state: stateName,
    execution_preparation_id: preparation.execution_preparation_id,
    expires_at: preparation.state === 'issued' ? preparation.expires_at : null,
    commit_ruling: ruling === undefined ? null : commitRulingProjection(ruling),
    escalation_id: preparation.escalation_id,
    commitment_id: preparation.commitment_id,
    effect_id: commitment?.effect_id ?? null,
    idempotency_key: commitment?.idempotency_key ?? null,
    effect_outcome: preparation.effect_outcome,
    recorded_at: preparation.effect_recorded_at,
  });
}

export class ExecutionPreparationService {
  readonly #store: WalStore;
  readonly #authorization: AuthorizationCore;
  readonly #proposalIntakes: ProposalIntakeService;
  readonly #authorizationBootId: string;
  readonly #authorizedAgentId: string;
  readonly #ttlMs: number;
  readonly #nextId: () => string;
  readonly #now: () => string;
  readonly #commitInFlight = new Map<string, Promise<NativeCommitVerifyResult>>();

  constructor(options: ExecutionPreparationServiceOptions) {
    this.#store = options.store;
    this.#authorization = options.authorization;
    this.#proposalIntakes = options.proposalIntakes;
    this.#authorizationBootId = id.parse(options.authorizationBootId);
    this.#authorizedAgentId = id.parse(options.authorizedAgentId);
    this.#ttlMs = options.ttlMs ?? 120_000;
    if (!Number.isSafeInteger(this.#ttlMs) || this.#ttlMs < 1 || this.#ttlMs > 120_000) {
      throw new RangeError('execution preparation ttl must be from 1 through 120000 milliseconds');
    }
    this.#nextId = options.nextId ?? (() => `xpr_${randomBytes(16).toString('hex')}`);
    this.#now = options.now ?? (() => new Date().toISOString());
  }

  #require(actor: TransactionActor, credential: 'proc:orchestrator' | 'proc:services_host'): void {
    if (actor.credential !== credential) throw new ExecutionPreparationError('forbidden', `only ${credential} may use this operation`);
  }

  #resolveRun(state: WorldState, caseId: string, runId: string) {
    const intakeId = state.proposalIntakeByRun.get(runId);
    const intake = intakeId === undefined ? undefined : state.proposalIntakes.get(intakeId);
    const proposal = intake?.proposal_id === null || intake?.proposal_id === undefined ? undefined : state.proposals.get(intake.proposal_id);
    const origin = proposal === undefined ? undefined : state.proposalOrigins.get(proposal.proposal_id);
    if (intake?.case_id !== caseId || intake.state !== 'consumed' || proposal === undefined || origin === undefined) {
      throw new ExecutionPreparationError('not-found', 'native proposal run does not exist for this case');
    }
    return { intake, proposal, origin };
  }

  #assertCurrent(state: WorldState, at: string, preparation: ExecutionPreparationRecord): void {
    if (preparation.state !== 'issued' || preparation.authorization_boot_id !== this.#authorizationBootId || at >= preparation.expires_at) {
      throw new ExecutionPreparationError('unavailable', 'execution preparation is no longer issued');
    }
    try {
      this.#proposalIntakes.assertProposalCurrent(state, at, preparation.proposal_id);
    } catch (error) {
      if (error instanceof ProposalIntakeError) throw new ExecutionPreparationError('currentness', 'native proposal is no longer current');
      throw error;
    }
    const { proposal, origin } = this.#resolveRun(state, preparation.case_id, preparation.proposal_run_id);
    const receipt = state.caseSessionProvenance.get(preparation.session_id);
    const basis = {
      world_id: state.worldId,
      frozen_proposal_hash: proposal.proposal_hash,
      service: origin.service,
      action_class: origin.action_class,
      target: proposal.target,
      exact_parameters: proposal.exact_parameters,
      data_to_be_disclosed: proposal.data_to_be_disclosed,
    };
    const gateMatches = precommitRulings(state, preparation);
    const newerRevision = [...state.proposals.values()].some((candidate) =>
      candidate.action_id === proposal.action_id && candidate.revision > proposal.revision);
    const commitConflict = [...state.rulings.values()].some((ruling) =>
      ruling.gate === 'commit' && ruling.binding.frozen_proposal_hash === proposal.proposal_hash);
    if (
      origin.session_id !== preparation.session_id || receipt?.state !== 'active' || receipt.case_id !== preparation.case_id ||
      receipt.authorization_boot_id !== this.#authorizationBootId || at >= receipt.expires_at || newerRevision || commitConflict ||
      gateMatches.some((matches) => matches.length !== 1 || at >= matches[0]!.binding.validity_window.not_after) ||
      gateMatches[0]![0]!.ruling_id !== preparation.authorize_ruling_id ||
      gateMatches[1]![0]!.ruling_id !== preparation.submit_ruling_id ||
      gateMatches[2]![0]!.ruling_id !== preparation.verify_ruling_id ||
      canonicalize(basis) !== canonicalize(preparation.effect_intent_basis) ||
      !verifyDigest(preparation.effect_intent_basis_digest, digestFor('execution-effect-intent-basis', basis))
    ) throw new ExecutionPreparationError('currentness', 'execution preparation binding is no longer current');
  }

  async issue(
    caseIdInput: string,
    runIdInput: string,
    sessionIdInput: string,
    actor: TransactionActor,
  ): Promise<ExecutionPreparationProjection> {
    this.#require(actor, 'proc:orchestrator');
    const caseId = id.parse(caseIdInput);
    const runId = id.parse(runIdInput);
    const sessionId = id.parse(sessionIdInput);
    const completed = await this.#store.transactWithState<ExecutionPreparationProjection>(
      'execution_preparation_issue',
      actor,
      (state, at) => {
        const { proposal, origin } = this.#resolveRun(state, caseId, runId);
        const proposalPreparations = [...state.executionPreparations.values()].filter((candidate) =>
          candidate.proposal_id === proposal.proposal_id);
        const issued = proposalPreparations.find((candidate) =>
          candidate.state === 'issued' && at < candidate.expires_at &&
          candidate.authorization_boot_id === this.#authorizationBootId);
        if (issued !== undefined) {
          if (issued.session_id !== sessionId) throw new ExecutionPreparationError('conflict', 'another session owns the live execution preparation');
          this.#assertCurrent(state, at, issued);
          return { ops: [], result: executionPreparationProjection.parse({ kind: 'execution_preparation', execution_preparation_id: issued.execution_preparation_id, proposal_run_id: issued.proposal_run_id, state: 'issued', issued_at: issued.issued_at, expires_at: issued.expires_at }) };
        }
        try {
          this.#proposalIntakes.assertProposalCurrent(state, at, proposal.proposal_id);
        } catch (error) {
          if (error instanceof ProposalIntakeError) throw new ExecutionPreparationError('currentness', 'native proposal is no longer current');
          throw error;
        }
        if (origin.session_id !== sessionId) throw new ExecutionPreparationError('conflict', 'session does not own the native proposal run');
        const matches = precommitRulings(state, { frozen_proposal_hash: proposal.proposal_hash, service: origin.service, action_class: origin.action_class });
        if (matches.some((gateRulings) => gateRulings.length !== 1 || at >= gateRulings[0]!.binding.validity_window.not_after)) {
          throw new ExecutionPreparationError('currentness', 'three current precommit allows are required');
        }
        if ([...state.rulings.values()].some((ruling) => ruling.gate === 'commit' && ruling.binding.frozen_proposal_hash === proposal.proposal_hash)) {
          throw new ExecutionPreparationError('conflict', 'native proposal already has Commit state');
        }
        if ([...state.proposals.values()].some((candidate) => candidate.action_id === proposal.action_id && candidate.revision > proposal.revision)) {
          throw new ExecutionPreparationError('conflict', 'native proposal already has a successor revision');
        }
        const receipt = state.caseSessionProvenance.get(sessionId);
        if (receipt?.state !== 'active' || receipt.case_id !== caseId || receipt.authorization_boot_id !== this.#authorizationBootId || at >= receipt.expires_at) {
          throw new ExecutionPreparationError('currentness', 'case session is no longer current');
        }
        const basis = {
          world_id: state.worldId,
          frozen_proposal_hash: proposal.proposal_hash,
          service: origin.service,
          action_class: origin.action_class,
          target: proposal.target,
          exact_parameters: proposal.exact_parameters,
          data_to_be_disclosed: proposal.data_to_be_disclosed,
        };
        const expiresAt = timestamp.parse(new Date(Math.min(Date.parse(at) + this.#ttlMs, Date.parse(receipt.expires_at), ...matches.map((gateRulings) => Date.parse(gateRulings[0]!.binding.validity_window.not_after)))).toISOString());
        const preparation = executionPreparationRecord.parse({
          world_id: state.worldId,
          execution_preparation_id: id.parse(this.#nextId()),
          authorization_boot_id: this.#authorizationBootId,
          case_id: caseId,
          session_id: sessionId,
          proposal_run_id: runId,
          proposal_id: proposal.proposal_id,
          frozen_proposal_hash: proposal.proposal_hash,
          action_id: proposal.action_id,
          revision: proposal.revision,
          conversation_version: origin.conversation_version,
          selection_id: origin.selection_id,
          requested_id: origin.requested_id,
          served_id: origin.served_id,
          card_id: origin.card_id,
          card_version: origin.card_version,
          card_digest: origin.card_digest,
          verifying_key_id: origin.verifying_key_id,
          mandate_id: origin.mandate_id,
          mandate_version: origin.mandate_version,
          policy_version: origin.policy_version,
          policy_content_digest: origin.policy_content_digest,
          evaluator_build_id: origin.evaluator_build_id,
          system_use_decision: origin.system_use_decision,
          authorize_ruling_id: matches[0]![0]!.ruling_id,
          submit_ruling_id: matches[1]![0]!.ruling_id,
          verify_ruling_id: matches[2]![0]!.ruling_id,
          service: origin.service,
          action_class: origin.action_class,
          effect_intent_basis: basis,
          effect_intent_basis_digest: digestFor('execution-effect-intent-basis', basis),
          issued_at: at,
          expires_at: expiresAt,
          state: 'issued',
          state_changed_at: at,
          commit_ruling_id: null,
          escalation_id: null,
          commitment_id: null,
          effect_outcome: null,
          effect_recorded_at: null,
          invalidation_reason: null,
        });
        const expiryOps: WalOp[] = proposalPreparations
          .filter((candidate) => candidate.state === 'issued')
          .map((candidate) => ({
            op: 'execution_preparation.expire',
            execution_preparation_id: candidate.execution_preparation_id,
            authorization_boot_id: this.#authorizationBootId,
            changed_at: at,
          }));
        return {
          ops: [...expiryOps, { op: 'execution_preparation.issue', preparation }],
          result: executionPreparationProjection.parse({ kind: 'execution_preparation', execution_preparation_id: preparation.execution_preparation_id, proposal_run_id: runId, state: 'issued', issued_at: at, expires_at: expiresAt }),
        };
      },
    );
    return completed.result;
  }

  async commitVerify(
    preparationIdInput: string,
    servicesHostBootId: string,
    servicesLedgerId: string,
    actor: TransactionActor,
  ): Promise<NativeCommitVerifyResult> {
    this.#require(actor, 'proc:services_host');
    const preparationId = id.parse(preparationIdInput);
    const joined = this.#commitInFlight.get(preparationId);
    if (joined !== undefined) return joined;
    const pending = this.#commitVerifyOnce(
      preparationId,
      id.parse(servicesHostBootId),
      id.parse(servicesLedgerId),
      actor,
    ).finally(() => {
      this.#commitInFlight.delete(preparationId);
    });
    this.#commitInFlight.set(preparationId, pending);
    return pending;
  }

  async #commitVerifyOnce(
    preparationId: string,
    servicesHostBootId: string,
    servicesLedgerId: string,
    actor: TransactionActor,
  ): Promise<NativeCommitVerifyResult> {
    const initial = this.#store.snapshot().executionPreparations.get(preparationId);
    if (initial === undefined) throw new ExecutionPreparationError('not-found', 'execution preparation does not exist');
    if (initial.state === 'consumed') {
      const ruling = initial.commit_ruling_id === null
        ? undefined
        : this.#store.snapshot().rulings.get(initial.commit_ruling_id);
      if (ruling === undefined) throw new ExecutionPreparationError('currentness', 'consumed preparation lost its Commit ruling');
      if (ruling.verdict === 'deny') {
        return nativeCommitVerifyResult.parse({
          execution_preparation_id: preparationId,
          state: 'commit-denied',
          ruling: commitRulingProjection(ruling),
          escalation_id: null,
        });
      }
      if (ruling.verdict === 'escalate') {
        if (initial.escalation_id === null) throw new ExecutionPreparationError('currentness', 'consumed preparation lost its escalation');
        return nativeCommitVerifyResult.parse({
          execution_preparation_id: preparationId,
          state: 'commit-escalated',
          ruling: commitRulingProjection(ruling),
          escalation_id: initial.escalation_id,
        });
      }
      const commitment = initial.commitment_id === null
        ? undefined
        : this.#store.snapshot().commitments.get(initial.commitment_id);
      if (commitment === undefined) throw new ExecutionPreparationError('currentness', 'consumed preparation lost its commitment');
      return nativeCommitVerifyResult.parse({
        execution_preparation_id: preparationId,
        state: 'already-consumed',
        commitment_id: commitment.commitment_id,
        idempotency_key: commitment.idempotency_key,
        effect_outcome: initial.effect_outcome,
        recorded_at: initial.effect_recorded_at,
      });
    }
    const proposal = this.#store.snapshot().proposals.get(initial.proposal_id);
    if (proposal === undefined) throw new ExecutionPreparationError('currentness', 'execution preparation lost its proposal');
    const built = await this.#authorization.nativeCommitVerify(
      {
        proposal,
        service: initial.service,
        actionClass: initial.action_class,
        caseId: initial.case_id,
        authorizedAgentId: this.#authorizedAgentId,
        servicesHostBootId,
        servicesLedgerId,
        actor,
      },
      (state, at) => {
        const current = state.executionPreparations.get(preparationId);
        if (current === undefined) throw new ExecutionPreparationError('not-found', 'execution preparation does not exist');
        this.#assertCurrent(state, at, current);
      },
      (_state, at, result): readonly WalOp[] => [{
        op: 'execution_preparation.consume',
        execution_preparation_id: preparationId,
        commit_ruling_id: result.ruling.ruling.ruling_id,
        escalation_id: result.ruling.escalationId,
        commitment_id: result.commitment?.commitmentId ?? null,
        changed_at: at,
      }],
    );
    return this.#nativeResult(preparationId, built);
  }

  #nativeResult(preparationId: string, built: NativeCommitVerifyBuildResult): NativeCommitVerifyResult {
    const ruling = commitRulingProjection(built.ruling.ruling);
    if (built.ruling.ruling.verdict === 'deny') return nativeCommitVerifyResult.parse({ execution_preparation_id: preparationId, state: 'commit-denied', ruling, escalation_id: null });
    if (built.ruling.ruling.verdict === 'escalate') return nativeCommitVerifyResult.parse({ execution_preparation_id: preparationId, state: 'commit-escalated', ruling, escalation_id: built.ruling.escalationId });
    if (built.commitment === null) throw new Error('native Commit allow lost its commitment');
    return nativeCommitVerifyResult.parse({
      execution_preparation_id: preparationId,
      state: 'committed',
      ruling,
      escalation_id: null,
      intent: {
        ...this.#store.snapshot().executionPreparations.get(preparationId)!.effect_intent_basis,
        ruling_id: built.ruling.ruling.ruling_id,
      },
      token: built.commitment.token,
      commitment_id: built.commitment.commitmentId,
      record_entry_id: built.commitment.recordEntryId,
    });
  }

  statusByRun(caseIdInput: string, runIdInput: string, actor: TransactionActor): ExecutionProcessProjection {
    this.#require(actor, 'proc:orchestrator');
    const state = this.#store.snapshot();
    const { proposal } = this.#resolveRun(state, id.parse(caseIdInput), id.parse(runIdInput));
    const at = timestamp.parse(this.#now());
    let proposalCurrent = true;
    try {
      this.#proposalIntakes.assertProposalCurrent(state, at, proposal.proposal_id);
    } catch (error) {
      if (!(error instanceof ProposalIntakeError)) throw error;
      proposalCurrent = false;
    }
    return executionProjectionForProposal(state, proposal.proposal_id, at, proposalCurrent);
  }

  async expire(actor: TransactionActor = { credential: 'proc:authz', claimed_role: null }): Promise<number> {
    const completed = await this.#store.transactWithState<number>('execution_preparation_expire', actor, (state, at) => {
      const ops = [...state.executionPreparations.values()]
        .filter((preparation) => preparation.state === 'issued' && (preparation.expires_at <= at || preparation.authorization_boot_id !== this.#authorizationBootId))
        .map((preparation) => ({ op: 'execution_preparation.expire' as const, execution_preparation_id: preparation.execution_preparation_id, authorization_boot_id: this.#authorizationBootId, changed_at: at }));
      return { ops, result: ops.length };
    });
    return completed.result;
  }
}
