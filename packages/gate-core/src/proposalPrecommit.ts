// SPDX-License-Identifier: AGPL-3.0-only
/** M5.11 authorization-owned fixed Authorize -> Submit -> Verify sequence. */
import { z } from 'zod';

import { AuthorizationCore } from './authorizationCore.js';
import { proposalRevisionPreparationInvalidationOps } from './conversationInvalidation.js';
import { ProposalIntakeError, ProposalIntakeService } from './proposalIntake.js';
import { ScreeningCallService, screeningCallStart } from './screeningCall.js';
import {
  classToken,
  gate,
  id,
  integer,
  jsonScalarOrList,
  modelId,
  rulingStatus,
  timestamp,
  uxClass,
  validityWindow,
  verdict,
  proposalRevisionContinuationProjection,
  type GateRuling,
} from './schemas/index.js';
import { WalStore, type TransactionActor } from './walStore.js';

const PRECOMMIT_GATES = ['authorize', 'submit', 'verify'] as const;
const boundedExactParameters = z.record(z.string(), jsonScalarOrList).refine(
  (parameters) =>
    Object.keys(parameters).length <= 64 &&
    Object.values(parameters).every((value) => !Array.isArray(value) || value.length <= 64),
  { message: 'proposal exact parameters exceed the native intake bound' },
);

export const proposalPrecommitGateProjection = z
  .object({
    gate: gate.refine((value): value is (typeof PRECOMMIT_GATES)[number] => PRECOMMIT_GATES.includes(value as never)),
    ruling_id: id,
    verdict,
    ux_class: uxClass,
    reason: z.string().min(1),
    status: rulingStatus,
    validity_window: validityWindow,
  })
  .strict();

export const proposalPrecommitProjection = z
  .object({
    kind: z.literal('proposal_precommit_status'),
    proposal_id: id,
    proposal_run_id: id,
    proposal: z
      .object({
        proposal_id: id,
        action_id: id,
        revision: integer.min(1),
        declared_objective: z.string(),
        proposed_action: z.string(),
        target: z.object({ recipient: z.string(), resource: z.string() }).strict(),
        exact_parameters: boundedExactParameters,
        data_to_be_disclosed: z.array(z.string()).max(64),
        cost_obligation: z.object({ amount_minor_units: integer.min(0), description: z.string() }).strict(),
        material_consequences: z.array(z.string()).max(64),
        reversibility_class: classToken,
        commercial_influence: z.object({ applicable: z.boolean(), note: z.string() }).strict(),
        requested_id: modelId,
        served_id: modelId,
        basis: z.array(z.object({ standing: z.enum(['said', 'confirmed', 'inferred-unconfirmed']), text: z.string() }).strict()).max(256),
      })
      .strict(),
    state: z.enum(['frozen', 'denied', 'escalated', 'verified', 'failed']),
    gates: z.array(proposalPrecommitGateProjection).max(3),
    escalation_id: id.nullable(),
    continuation: proposalRevisionContinuationProjection.default({
      state: 'unavailable',
      source_proposal_run_id: null,
    }),
    updated_at: timestamp,
  })
  .strict();
export type ProposalPrecommitProjection = z.infer<typeof proposalPrecommitProjection>;

export const proposalPrecommitScreeningRequiredProjection = z
  .object({
    kind: z.literal('proposal_precommit_screening_required'),
    proposal_id: id,
    proposal_run_id: id,
    state: z.literal('screening_required'),
    current_gate: gate.refine((value) => value === 'submit' || value === 'verify'),
    gates: z.array(proposalPrecommitGateProjection).max(2),
    screening_call: screeningCallStart,
  })
  .strict();
export type ProposalPrecommitScreeningRequiredProjection = z.infer<typeof proposalPrecommitScreeningRequiredProjection>;

export const proposalPrecommitProcessProjection = z.union([
  proposalPrecommitProjection,
  proposalPrecommitScreeningRequiredProjection,
]);
export type ProposalPrecommitProcessProjection = z.infer<typeof proposalPrecommitProcessProjection>;

export class ProposalPrecommitError extends Error {
  constructor(readonly code: 'forbidden' | 'not-found' | 'currentness' | 'progress', message: string) {
    super(message);
    this.name = 'ProposalPrecommitError';
  }
}

export interface ProposalPrecommitServiceOptions {
  readonly store: WalStore;
  readonly authorization: AuthorizationCore;
  readonly proposalIntakes: ProposalIntakeService;
  readonly screeningCalls?: ScreeningCallService;
}

function projectGate(ruling: GateRuling) {
  return proposalPrecommitGateProjection.parse({
    gate: ruling.gate,
    ruling_id: ruling.ruling_id,
    verdict: ruling.verdict,
    ux_class: ruling.ux_class,
    reason: ruling.reason,
    status: ruling.status,
    validity_window: ruling.binding.validity_window,
  });
}

export class ProposalPrecommitService {
  readonly #store: WalStore;
  readonly #authorization: AuthorizationCore;
  readonly #proposalIntakes: ProposalIntakeService;
  readonly #screeningCalls: ScreeningCallService | undefined;

  constructor(options: ProposalPrecommitServiceOptions) {
    this.#store = options.store;
    this.#authorization = options.authorization;
    this.#proposalIntakes = options.proposalIntakes;
    this.#screeningCalls = options.screeningCalls;
  }

  #requireOrchestrator(actor: TransactionActor): void {
    if (actor.credential !== 'proc:orchestrator') {
      throw new ProposalPrecommitError('forbidden', 'only the orchestrator process may run proposal precommit');
    }
  }

  #status(proposalId: string): ProposalPrecommitProjection {
    const state = this.#store.snapshot();
    const proposal = state.proposals.get(proposalId);
    const origin = state.proposalOrigins.get(proposalId);
    if (proposal === undefined || origin === undefined) {
      throw new ProposalPrecommitError('not-found', 'native proposal does not exist');
    }
    const candidates = [...state.rulings.values()]
      .filter((ruling) =>
        ruling.binding.frozen_proposal_hash === proposal.proposal_hash &&
        ruling.binding.service === origin.service &&
        ruling.binding.action_class === origin.action_class &&
        PRECOMMIT_GATES.includes(ruling.gate as never))
      .sort((left, right) => left.issued_at.localeCompare(right.issued_at));
    const latest = PRECOMMIT_GATES.flatMap((gateName) => {
      const matching = candidates.filter((candidate) => candidate.gate === gateName);
      const issued = matching.filter((candidate) => candidate.status === 'issued').at(-1);
      return issued === undefined ? (matching.at(-1) === undefined ? [] : [matching.at(-1)!]) : [issued];
    });
    const active = latest.filter((ruling) => ruling.status === 'issued');
    const terminal = active.find((ruling) => ruling.verdict !== 'allow');
    const verified = PRECOMMIT_GATES.every((gateName) =>
      active.some((ruling) => ruling.gate === gateName && ruling.verdict === 'allow'));
    const hasInvalidatedProgress = latest.some((ruling) => ruling.status !== 'issued');
    const stateName = terminal?.verdict === 'deny'
      ? 'denied'
      : terminal?.verdict === 'escalate'
        ? 'escalated'
        : verified
          ? 'verified'
          : hasInvalidatedProgress
            ? 'failed'
            : 'frozen';
    const escalationSource = terminal ?? latest.find((candidate) => candidate.verdict === 'escalate');
    const escalation = escalationSource === undefined
      ? undefined
      : [...state.escalations.values()].find((candidate) => candidate.ruling_id === escalationSource.ruling_id);
    const continuation = origin.continuation !== null
      ? {
          state: 'unavailable' as const,
          source_proposal_run_id:
            state.proposalOrigins.get(origin.continuation.source_proposal_id)?.proposal_run_id ?? null,
        }
      : escalation === undefined || escalation.dialogue_item_ref === null
        ? { state: 'unavailable' as const, source_proposal_run_id: null }
        : escalation.successor_ruling_id !== null
          ? { state: 'continued' as const, source_proposal_run_id: null }
          : escalation.state === 'open'
            ? { state: 'response-required' as const, source_proposal_run_id: null }
            : escalation.terminal_disposition === 'route'
              ? { state: 'parked' as const, source_proposal_run_id: null }
              : ['confirm', 'correct', 'narrow'].includes(escalation.terminal_disposition ?? '')
                ? {
                    state: this.#proposalIntakes.hasLiveRevisionAttempt(state, proposal.proposal_id)
                      ? 'prepared' as const
                      : 'available' as const,
                    source_proposal_run_id: null,
                  }
                : { state: 'unavailable' as const, source_proposal_run_id: null };
    return proposalPrecommitProjection.parse({
      kind: 'proposal_precommit_status',
      proposal_id: proposalId,
      proposal_run_id: origin.proposal_run_id,
      proposal: {
        proposal_id: proposal.proposal_id,
        action_id: proposal.action_id,
        revision: proposal.revision,
        declared_objective: proposal.declared_objective,
        proposed_action: proposal.proposed_action,
        target: proposal.target,
        exact_parameters: Object.fromEntries(
          Object.entries(proposal.exact_parameters).map(([key, value]) => [key, Array.isArray(value) ? [...value] : value]),
        ),
        data_to_be_disclosed: proposal.data_to_be_disclosed,
        cost_obligation: proposal.cost_obligation,
        material_consequences: proposal.material_consequences,
        reversibility_class: proposal.reversibility_class,
        commercial_influence: proposal.commercial_influence,
        requested_id: proposal.acting_model.requested_id,
        served_id: proposal.acting_model.served_id,
        basis: [
          ...proposal.material_inputs.map((item) => ({ standing: item.store as 'said' | 'confirmed', text: item.text })),
          ...proposal.derived_claims.map((item) => ({ standing: 'inferred-unconfirmed' as const, text: item.text })),
        ],
      },
      state: stateName,
      gates: latest.map(projectGate),
      escalation_id: escalation?.escalation_id ?? null,
      continuation,
      updated_at: latest.at(-1)?.issued_at ?? origin.frozen_at,
    });
  }

  #processStatus(proposalId: string): ProposalPrecommitProcessProjection {
    const normal = this.#status(proposalId);
    if (this.#screeningCalls === undefined || normal.state !== 'frozen') return normal;
    const state = this.#store.snapshot();
    const proposal = state.proposals.get(proposalId);
    const origin = state.proposalOrigins.get(proposalId);
    if (proposal === undefined || origin === undefined) return normal;
    for (const gateName of ['submit', 'verify'] as const) {
      const start = this.#screeningCalls.startFor(proposal, gateName, origin.case_id);
      if (start !== null) {
        return proposalPrecommitScreeningRequiredProjection.parse({
          kind: 'proposal_precommit_screening_required',
          proposal_id: proposal.proposal_id,
          proposal_run_id: origin.proposal_run_id,
          state: 'screening_required',
          current_gate: gateName,
          gates: normal.gates,
          screening_call: start,
        });
      }
    }
    return normal;
  }

  status(proposalIdInput: string, actor: TransactionActor): ProposalPrecommitProcessProjection {
    this.#requireOrchestrator(actor);
    return this.#processStatus(id.parse(proposalIdInput));
  }

  statusByRun(caseIdInput: string, runIdInput: string, actor: TransactionActor): ProposalPrecommitProcessProjection | null {
    this.#requireOrchestrator(actor);
    const state = this.#store.snapshot();
    const intakeId = state.proposalIntakeByRun.get(id.parse(runIdInput));
    const intake = intakeId === undefined ? undefined : state.proposalIntakes.get(intakeId);
    if (intake === undefined || intake.case_id !== id.parse(caseIdInput) || intake.proposal_id === null) return null;
    return this.#processStatus(intake.proposal_id);
  }

  async run(proposalIdInput: string, actor: TransactionActor): Promise<ProposalPrecommitProcessProjection> {
    this.#requireOrchestrator(actor);
    const proposalId = id.parse(proposalIdInput);
    for (const gateName of PRECOMMIT_GATES) {
      const before = this.#status(proposalId);
      if (['denied', 'escalated', 'verified', 'failed'].includes(before.state)) return before;
      const priorIndex = PRECOMMIT_GATES.indexOf(gateName) - 1;
      if (priorIndex >= 0) {
        const priorGate = PRECOMMIT_GATES[priorIndex]!;
        if (!before.gates.some((candidate) => candidate.gate === priorGate && candidate.verdict === 'allow' && candidate.status === 'issued')) {
          throw new ProposalPrecommitError('progress', `durable ${priorGate} allow is required before ${gateName}`);
        }
      }
      const state = this.#store.snapshot();
      const proposal = state.proposals.get(proposalId);
      const origin = state.proposalOrigins.get(proposalId);
      if (proposal === undefined || origin === undefined) throw new ProposalPrecommitError('not-found', 'native proposal does not exist');
      if (this.#screeningCalls !== undefined && (gateName === 'submit' || gateName === 'verify')) {
        const screening = await this.#screeningCalls.ensure({
          proposal,
          gate: gateName,
          caseId: origin.case_id,
          proposalRunId: origin.proposal_run_id,
          actor,
          assertCurrent: (lockedState, at) => this.#proposalIntakes.assertProposalCurrent(lockedState, at, proposalId),
        });
        if (screening !== null) {
          return proposalPrecommitScreeningRequiredProjection.parse({
            kind: 'proposal_precommit_screening_required',
            proposal_id: proposal.proposal_id,
            proposal_run_id: origin.proposal_run_id,
            state: 'screening_required',
            current_gate: gateName,
            gates: before.gates,
            screening_call: screening,
          });
        }
      }
      try {
        await this.#authorization.ruleProposalWithCurrentness(
          {
            gate: gateName,
            proposal,
            service: origin.service,
            actionClass: origin.action_class,
            caseId: origin.case_id,
            actor,
          },
          (lockedState, at) => this.#proposalIntakes.assertProposalCurrent(lockedState, at, proposalId),
          (lockedState, at, result) => {
            if (
              origin.continuation === null ||
              (result.ruling.verdict !== 'escalate' &&
                !(gateName === 'verify' && result.ruling.verdict === 'allow'))
            ) return [];
            const sourceRuling = lockedState.rulings.get(origin.continuation.source_ruling_id);
            const sourceEscalation = lockedState.escalations.get(origin.continuation.source_escalation_id);
            if (
              sourceRuling === undefined ||
              sourceEscalation === undefined ||
              sourceRuling.successor_ruling_id !== null ||
              sourceEscalation.successor_ruling_id !== null
            ) throw new ProposalPrecommitError('currentness', 'dialogue continuation already has a successor');
            return [
              ...proposalRevisionPreparationInvalidationOps(
                lockedState,
                (preparation) => preparation.source_proposal_id === origin.continuation?.source_proposal_id,
                'successor-claimed',
                at,
              ),
              {
                op: 'ruling.link_successor' as const,
                ruling_id: sourceRuling.ruling_id,
                successor_ruling_id: result.ruling.ruling_id,
              },
              {
                op: 'escalation.link_successor' as const,
                escalation_id: sourceEscalation.escalation_id,
                successor_ruling_id: result.ruling.ruling_id,
              },
            ];
          },
        );
      } catch (error) {
        if (error instanceof ProposalIntakeError) {
          throw new ProposalPrecommitError('currentness', 'native proposal is no longer current');
        }
        throw error;
      }
      const after = this.#status(proposalId);
      const current = after.gates.find((candidate) => candidate.gate === gateName && candidate.status === 'issued');
      if (current === undefined) throw new ProposalPrecommitError('progress', `durable ${gateName} ruling is unavailable`);
      if (current.verdict !== 'allow') return after;
    }
    return this.#status(proposalId);
  }
}
