// SPDX-License-Identifier: AGPL-3.0-only
/** Authorization-owned read model for ADR-002's fixed, role-scoped projections. */
import { join } from 'node:path';

import {
  applicantExtractProjection,
  approvedModelsProjection,
  escalationDetailProjection,
  escalationListProjection,
  escalationStatusProjection,
  mandateListProjection,
  mandateProjection,
  recordVerificationAlarmProjection,
  recordVerificationProjection,
  recordViewProjection,
  rulingProjection,
  type ApplicantExtractProjection,
  type ApprovedModelsProjection,
  type EscalationDetailProjection,
  type EscalationStatusProjection,
  type RecordVerificationProjection,
  type RecordViewProjection,
  type RulingProjection,
} from './authorizationProjection.js';
import { type CardInspection, CardRegistry } from './cardRegistry.js';
import {
  RecordVerificationError,
  type CheckpointArtifact,
  type RecordsVerificationReport,
} from './checkpoint.js';
import { GENESIS_PREV_HASH, readVerifiedChainEntries, verifyChain } from './chain.js';
import {
  type ApprovedModelEntry,
  type CredentialLabel,
  type Disposition,
  type EscalationRecord,
  type FrozenProposal,
  type GateRuling,
  type Mandate,
  recordEntry,
  type RecordEntry,
} from './schemas/index.js';
import { mandateVersionKey } from './state.js';
import type { TransactionActor, WalStore } from './walStore.js';

const LOCAL_RECEIPT_NOTICE =
  'A true lodgment receipt requires independent custody, which this POC does not provide.' as const;

type RecordVerificationBody =
  | RecordVerificationProjection
  | ReturnType<typeof recordVerificationAlarmProjection.parse>;

interface ProjectedRead<T> {
  readonly body: T;
  readonly readLengths: Readonly<Record<string, number>>;
}

export class AuthorizationReadSideError extends Error {
  constructor(
    readonly code: 'forbidden' | 'record-integrity-alarm',
    message: string,
  ) {
    super(message);
    this.name = 'AuthorizationReadSideError';
  }
}

export interface AuthorizationReadSideOptions {
  readonly store: WalStore;
  readonly cards: CardRegistry;
  readonly recordsRoot: string;
  readonly worldId: string;
  readonly verifyRecordLayer: () => Promise<RecordsVerificationReport>;
}

function requireCredential(actor: TransactionActor, allowed: readonly CredentialLabel[]): void {
  if (!(allowed as readonly string[]).includes(actor.credential)) {
    throw new AuthorizationReadSideError('forbidden', `credential ${actor.credential} cannot use this read`);
  }
}

function projectRuling(ruling: GateRuling): RulingProjection {
  return rulingProjection.parse({
    ruling_id: ruling.ruling_id,
    verdict: ruling.verdict,
    ux_class: ruling.ux_class,
    reason: ruling.reason,
    status: ruling.status,
    successor_ruling_id: ruling.successor_ruling_id ?? null,
    validity_window: ruling.binding.validity_window,
  });
}

function projectMandate(mandate: Mandate) {
  const {
    binding: ignoredBinding,
    replay_protection: ignoredReplay,
    revocation_endpoint: ignoredRevocation,
    ...projection
  } = mandate;
  void ignoredBinding;
  void ignoredReplay;
  void ignoredRevocation;
  return mandateProjection.parse(projection);
}

function cardStatus(approval: ApprovedModelEntry, inspection: CardInspection | undefined) {
  if (inspection === undefined || !inspection.signatureValid || inspection.withdrawn || inspection.integrityAlarm) {
    return 'withdrawn' as const;
  }
  if (inspection.card.card_version < approval.card_version) return 'withdrawn' as const;
  if (inspection.card.card_version === approval.card_version && inspection.digest !== approval.card_digest) {
    return 'withdrawn' as const;
  }
  return inspection.card.card_version === approval.card_version ? ('current' as const) : ('superseded' as const);
}

function effectiveDataClasses(approval: ApprovedModelEntry, inspection: CardInspection | undefined) {
  const result: Record<string, string[]> = {};
  for (const modelRoleValue of approval.roles) {
    const approved = approval.data_classes[modelRoleValue] ?? [];
    const declared = inspection?.card.declared_data_classes[modelRoleValue] ?? [];
    const declaredSet = new Set(declared);
    result[modelRoleValue] = approved.filter((tag) => declaredSet.has(tag));
  }
  return result;
}

function roleFromCredential(actor: TransactionActor): 'principal' | 'case_officer' | 'applicant' | null {
  if (actor.credential === 'role:principal') return 'principal';
  if (actor.credential === 'role:case_officer') return 'case_officer';
  if (actor.credential === 'role:applicant') return 'applicant';
  return null;
}

function isRoutedTo(escalation: EscalationRecord, actor: TransactionActor): boolean {
  const actorRole = roleFromCredential(actor);
  return (
    actorRole !== null &&
    (actorRole === escalation.contract.decision_and_route.eligible_role ||
      escalation.contract.decision_and_route.substitute_roles.includes(actorRole))
  );
}

function proposalForEscalation(
  escalation: EscalationRecord,
  proposals: ReadonlyMap<string, FrozenProposal>,
  proposalByHash: ReadonlyMap<string, string>,
): FrozenProposal {
  const proposalId = proposalByHash.get(escalation.frozen_proposal_hash);
  const proposal = proposalId === undefined ? undefined : proposals.get(proposalId);
  if (proposal === undefined) throw new AuthorizationReadSideError('record-integrity-alarm', 'escalation lost proposal');
  return proposal;
}

function proposalRevisionRef(proposal: FrozenProposal) {
  return { proposal_id: proposal.proposal_id, revision: proposal.revision, action_id: proposal.action_id };
}

function projectCheckpoint(checkpoint: CheckpointArtifact, world: string) {
  return {
    checkpoint_id: checkpoint.checkpoint_id,
    seq: checkpoint.seq,
    created_at: checkpoint.created_at,
    composite_digest: checkpoint.composite_digest,
    world_streams: checkpoint.streams
      .filter((stream) => stream.world === world)
      .map(({ stream, length, head_hash }) => ({ stream, length, head_hash })),
  };
}

function splitEnvelope(raw: Readonly<Record<string, unknown>>) {
  const { seq, prev_hash, entry_hash, ...entry } = raw;
  return { seq, prev_hash, entry_hash, entry };
}

function envelopeHead(entries: readonly ReturnType<typeof splitEnvelope>[]) {
  const latest = entries.at(-1);
  return {
    length: entries.length,
    head_hash: latest === undefined ? GENESIS_PREV_HASH : String(latest.entry_hash),
  };
}

function sameHead(
  left: { readonly length: number; readonly head_hash: string },
  right: { readonly length: number; readonly head_hash: string },
): boolean {
  return left.length === right.length && left.head_hash === right.head_hash;
}

function effectProjection(entry: RecordEntry) {
  const event = entry.commitment_and_effect;
  if (event === null) return null;
  return {
    entry_id: entry.entry_id,
    at: entry.at,
    event: event.event,
    effect_id: event.effect_id,
    outcome:
      event.event === 'effect_outcome'
        ? event.outcome
        : event.event === 'retry_served'
          ? event.recorded_outcome
          : null,
  };
}

function interventionProjection(entry: RecordEntry) {
  const event = entry.human_intervention_event;
  if (event === null) return null;
  if (event.event === 'late_disposition_ignored') {
    return {
      entry_id: entry.entry_id,
      at: entry.at,
      kind: event.event,
      disposition: event.attempted_disposition,
    };
  }
  const payload = event.payload;
  let selected: Disposition | null = null;
  if (payload.kind === 'disposition_recorded') selected = payload.disposition;
  if (payload.kind === 'dialogue_response_recorded') selected = payload.disposition;
  if (payload.kind === 'dialogue_timeout' || payload.kind === 'escalation_timeout') {
    selected = payload.applied_default;
  }
  return { entry_id: entry.entry_id, at: entry.at, kind: payload.kind, disposition: selected };
}

export class AuthorizationReadSide {
  readonly #store: WalStore;
  readonly #cards: CardRegistry;
  readonly #recordsRoot: string;
  readonly #worldId: string;
  readonly #verifyRecordLayer: () => Promise<RecordsVerificationReport>;

  constructor(options: AuthorizationReadSideOptions) {
    this.#store = options.store;
    this.#cards = options.cards;
    this.#recordsRoot = options.recordsRoot;
    this.#worldId = options.worldId;
    this.#verifyRecordLayer = options.verifyRecordLayer;
  }

  #readMaterializedRecords() {
    const action = readVerifiedChainEntries(
      join(this.#recordsRoot, this.#worldId, 'action.jsonl'),
      'record-entry',
    ).map((entry) => splitEnvelope(entry));
    const access = readVerifiedChainEntries(
      join(this.#recordsRoot, this.#worldId, 'access.jsonl'),
      'access-entry',
    ).map((entry) => splitEnvelope(entry));
    const writerHeads = this.#store.chainHeads();
    if (!sameHead(envelopeHead(action), writerHeads.action) || !sameHead(envelopeHead(access), writerHeads.access)) {
      throw new AuthorizationReadSideError(
        'record-integrity-alarm',
        'materialized record chain diverges from the current durable writer head',
      );
    }
    return { action, access };
  }

  #assertCurrentWriterHeads(): void {
    const expected = this.#store.chainHeads();
    const files = [
      { stream: 'wal' as const, file: 'wal.jsonl', domain: 'wal-entry' as const },
      { stream: 'action' as const, file: 'action.jsonl', domain: 'record-entry' as const },
      { stream: 'access' as const, file: 'access.jsonl', domain: 'access-entry' as const },
    ];
    for (const item of files) {
      const actual = verifyChain(join(this.#recordsRoot, this.#worldId, item.file), item.domain);
      if (!actual.ok || !sameHead(actual, expected[item.stream])) {
        throw new RecordVerificationError('chain-tamper', `${item.stream} differs from its current writer head`);
      }
    }
  }

  ruling(rulingId: string, actor: TransactionActor): RulingProjection | null {
    requireCredential(actor, ['proc:orchestrator', 'proc:services_host']);
    const ruling = this.#store.snapshot().rulings.get(rulingId);
    return ruling === undefined ? null : projectRuling(ruling);
  }

  approvedModels(mandateId: string, actor: TransactionActor): ApprovedModelsProjection | null {
    requireCredential(actor, ['proc:orchestrator', 'role:principal', 'role:case_officer']);
    const state = this.#store.snapshot();
    const status = state.mandateStatus.get(mandateId);
    const mandateValue =
      status === undefined ? undefined : state.mandates.get(mandateVersionKey(mandateId, status.version));
    if (mandateValue === undefined) return null;
    return approvedModelsProjection.parse({
      mandate_id: mandateValue.mandate_id,
      mandate_version: mandateValue.version,
      mandate_state: mandateValue.state,
      models: mandateValue.approved_models
        .filter((approval) => approval.roles.includes('acting'))
        .map((approval) => {
          const inspection = this.#cards.get(approval.card_id);
          const digestMatches = inspection?.digest === approval.card_digest;
          return {
            approval,
            effective_data_classes: effectiveDataClasses(approval, inspection),
            card_status: cardStatus(approval, inspection),
            signature_status: inspection?.signatureValid === true ? 'valid' : 'invalid',
            integrity_alarm:
              inspection === undefined ||
              inspection.integrityAlarm ||
              !inspection.signatureValid ||
              inspection.card.card_version < approval.card_version ||
              (inspection.card.card_version === approval.card_version && !digestMatches),
            current_card_digest: inspection?.digest ?? null,
            verifying_key_id: inspection?.keyId ?? null,
            current_card: inspection?.card ?? null,
          };
        }),
    });
  }

  mandates(actor: TransactionActor) {
    requireCredential(actor, ['role:principal', 'role:case_officer']);
    const state = this.#store.snapshot();
    const current = [...state.mandateStatus.entries()]
      .map(([mandateId, status]) => state.mandates.get(mandateVersionKey(mandateId, status.version)))
      .filter((value): value is Mandate => value !== undefined)
      .sort((left, right) => left.mandate_id.localeCompare(right.mandate_id))
      .map(projectMandate);
    return mandateListProjection.parse({ mandates: current });
  }

  escalations(actor: TransactionActor) {
    requireCredential(actor, ['role:principal', 'role:case_officer']);
    const state = this.#store.snapshot();
    const escalations = [...state.escalations.values()]
      .filter((escalation) => isRoutedTo(escalation, actor))
      .sort((left, right) => left.opened_at.localeCompare(right.opened_at) || left.escalation_id.localeCompare(right.escalation_id))
      .map((escalation) => {
        const proposal = proposalForEscalation(escalation, state.proposals, state.proposalByHash);
        return {
          escalation_id: escalation.escalation_id,
          ruling_id: escalation.ruling_id,
          status: escalation.state,
          trigger: escalation.contract.trigger_and_state.trigger,
          eligible_role: escalation.contract.decision_and_route.eligible_role,
          substitute_roles: escalation.contract.decision_and_route.substitute_roles,
          opened_at: escalation.opened_at,
          expires_at: escalation.expires_at,
          permitted_dispositions: escalation.contract.permitted_dispositions,
          terminal_disposition: escalation.terminal_disposition,
          proposal_revision_ref: proposalRevisionRef(proposal),
        };
      });
    return escalationListProjection.parse({ escalations });
  }

  escalation(
    escalationId: string,
    actor: TransactionActor,
  ): EscalationDetailProjection | EscalationStatusProjection | null {
    requireCredential(actor, ['proc:orchestrator', 'role:principal', 'role:case_officer', 'role:applicant']);
    const state = this.#store.snapshot();
    const escalation = state.escalations.get(escalationId);
    if (escalation === undefined) return null;
    const proposal = proposalForEscalation(escalation, state.proposals, state.proposalByHash);
    if (actor.credential === 'proc:orchestrator') {
      return escalationStatusProjection.parse({
        escalation_id: escalation.escalation_id,
        status: escalation.state,
        proposal_revision_ref: proposalRevisionRef(proposal),
        response_bound: { not_before: escalation.opened_at, not_after: escalation.expires_at },
        terminal_disposition: escalation.terminal_disposition,
      });
    }
    if (!isRoutedTo(escalation, actor)) return null;
    const ruling = state.rulings.get(escalation.ruling_id);
    if (ruling === undefined) throw new AuthorizationReadSideError('record-integrity-alarm', 'escalation lost ruling');
    const dialogueEvent = state.actionRecords.find(
      (entry) =>
        entry.human_intervention_event?.event === 'human_intervention_event' &&
        entry.human_intervention_event.escalation_id === escalation.escalation_id &&
        entry.human_intervention_event.payload.kind === 'dialogue_trigger_raised',
    );
    const payload =
      dialogueEvent?.human_intervention_event?.event === 'human_intervention_event'
        ? dialogueEvent.human_intervention_event.payload
        : undefined;
    return escalationDetailProjection.parse({
      escalation_id: escalation.escalation_id,
      ruling_id: escalation.ruling_id,
      status: escalation.state,
      trigger: escalation.contract.trigger_and_state.trigger,
      eligible_role: escalation.contract.decision_and_route.eligible_role,
      substitute_roles: escalation.contract.decision_and_route.substitute_roles,
      opened_at: escalation.opened_at,
      expires_at: escalation.expires_at,
      permitted_dispositions: escalation.contract.permitted_dispositions,
      terminal_disposition: escalation.terminal_disposition,
      proposal_revision_ref: proposalRevisionRef(proposal),
      question_text: payload?.kind === 'dialogue_trigger_raised' ? payload.question_text : null,
      contract: escalation.contract,
      ruling: projectRuling(ruling),
    });
  }

  records(actor: TransactionActor): ProjectedRead<RecordViewProjection> {
    requireCredential(actor, ['role:principal', 'role:case_officer']);
    try {
      const { action, access } = this.#readMaterializedRecords();
      return {
        body: recordViewProjection.parse({
          world_id: this.#worldId,
          action_chain: { length: action.length, entries: action },
          access_chain: { length: access.length, entries: access },
        }),
        readLengths: {
          [`${this.#worldId}/action`]: action.length,
          [`${this.#worldId}/access`]: access.length,
        },
      };
    } catch {
      throw new AuthorizationReadSideError('record-integrity-alarm', 'record chain failed verification');
    }
  }

  async verification(actor: TransactionActor): Promise<ProjectedRead<RecordVerificationBody>> {
    requireCredential(actor, ['role:principal', 'role:case_officer']);
    return this.#verification();
  }

  async #verification(): Promise<ProjectedRead<RecordVerificationBody>> {
    try {
      this.#assertCurrentWriterHeads();
      const report = await this.#verifyRecordLayer();
      const checkpoint = report.checkpoint === null ? null : projectCheckpoint(report.checkpoint, this.#worldId);
      const latest =
        report.latestPushedCheckpoint === null
          ? null
          : {
              checkpoint: projectCheckpoint(report.latestPushedCheckpoint.artifact, this.#worldId),
              commit_sha: report.latestPushedCheckpoint.commitSha,
              repo_url: report.latestPushedCheckpoint.repoUrl,
            };
      return {
        body: recordVerificationProjection.parse({
          status: 'no-divergence-detected',
          mode: report.mode,
          checkpoint,
          latest_pushed_checkpoint: latest,
          open_window: { entries: report.unanchoredWindowEntries, minutes: report.unanchoredWindowMinutes },
          warnings: report.warnings,
          message: report.message,
        }),
        readLengths: report.readLengths,
      };
    } catch (error) {
      if (error instanceof RecordVerificationError) {
        return {
          body: recordVerificationAlarmProjection.parse({
            status: 'alarm',
            code: error.code,
            message: 'record verification detected a divergence',
          }),
          readLengths: {},
        };
      }
      throw error;
    }
  }

  async applicantExtract(actor: TransactionActor): Promise<ProjectedRead<ApplicantExtractProjection>> {
    requireCredential(actor, ['role:applicant']);
    const verification = await this.#verification();
    if (verification.body.status === 'alarm') {
      throw new AuthorizationReadSideError('record-integrity-alarm', 'applicant extract refused after alarm');
    }
    let actionEnvelopes: ReturnType<typeof splitEnvelope>[];
    let accessLength: number;
    try {
      const materialized = this.#readMaterializedRecords();
      actionEnvelopes = materialized.action;
      accessLength = materialized.access.length;
    } catch {
      throw new AuthorizationReadSideError('record-integrity-alarm', 'record chain failed verification');
    }
    const entries = actionEnvelopes.map((envelope) => recordEntry.parse(envelope.entry));
    const state = this.#store.snapshot();
    const proposalForRuling = (rulingId: string) => {
      const ruling = state.rulings.get(rulingId);
      const proposalId = ruling === undefined ? undefined : state.proposalByHash.get(ruling.binding.frozen_proposal_hash);
      return proposalId === undefined ? undefined : state.proposals.get(proposalId);
    };
    const proposals = [...state.proposals.values()]
      .filter((proposal) => entries.some((entry) => proposalForRuling(entry.admissibility_decision.ruling_id)?.proposal_id === proposal.proposal_id))
      .sort((left, right) => left.created_at.localeCompare(right.created_at) || left.proposal_id.localeCompare(right.proposal_id));
    const actions = proposals.map((proposal) => {
      const proposalRulings = [...state.rulings.values()]
        .filter((ruling) => ruling.binding.frozen_proposal_hash === proposal.proposal_hash)
        .sort((left, right) => left.issued_at.localeCompare(right.issued_at));
      const selectedRuling = proposalRulings.at(-1);
      if (selectedRuling === undefined) {
        throw new AuthorizationReadSideError('record-integrity-alarm', 'proposal lost ruling');
      }
      const related = entries.filter(
        (entry) => proposalForRuling(entry.admissibility_decision.ruling_id)?.proposal_id === proposal.proposal_id,
      );
      const challenge = [...related].reverse().find((entry) => entry.challenge_and_remedy !== null)?.challenge_and_remedy ?? null;
      const latestRelated = related.at(-1);
      return {
        action_id: proposal.action_id,
        proposal_id: proposal.proposal_id,
        revision: proposal.revision,
        declared_objective: proposal.declared_objective,
        proposed_action: proposal.proposed_action,
        target: proposal.target,
        material_consequences: proposal.material_consequences,
        authority: {
          mandate_id: selectedRuling.binding.mandate_id,
          mandate_version: selectedRuling.binding.mandate_version,
        },
        system_use_decision: selectedRuling.binding.system_use_decision,
        system_use_current_at_record: latestRelated?.system_use_current_at_record ?? false,
        ruling: {
          ruling_id: selectedRuling.ruling_id,
          verdict: selectedRuling.verdict,
          reason: selectedRuling.reason,
          status: selectedRuling.status,
        },
        effects: related.map(effectProjection).filter((value) => value !== null),
        interventions: related.map(interventionProjection).filter((value) => value !== null),
        challenge_and_remedy: challenge,
      };
    });
    const latest = verification.body.latest_pushed_checkpoint;
    const anchoredActionLength =
      latest?.checkpoint.world_streams.find((stream) => stream.stream === 'action')?.length ?? 0;
    const actionEntries = actionEnvelopes.flatMap((envelope, index) => {
      const entry = entries[index];
      if (entry === undefined) return [];
      const proposal = proposalForRuling(entry.admissibility_decision.ruling_id);
      if (proposal === undefined) return [];
      return [
        {
          entry_id: entry.entry_id,
          action_id: proposal.action_id,
          index: envelope.seq,
          inside_anchored_prefix: latest !== null && Number(envelope.seq) < anchoredActionLength,
          system_use_decision: entry.system_use_decision,
          system_use_current_at_record: entry.system_use_current_at_record,
        },
      ];
    });
    return {
      body: applicantExtractProjection.parse({
        world_id: this.#worldId,
        scope: { role: 'applicant', resources: [...new Set(actions.map((action) => action.target.resource))].sort() },
        actions,
        receipt: {
          kind: 'local-record-receipt',
          notice: LOCAL_RECEIPT_NOTICE,
          latest_pushed_checkpoint:
            latest === null
              ? null
              : {
                  checkpoint_id: latest.checkpoint.checkpoint_id,
                  composite_digest: latest.checkpoint.composite_digest,
                  remote_commit_sha: latest.commit_sha,
                  repo_url: latest.repo_url,
                  action_chain_length_at_anchor: anchoredActionLength,
                },
          action_entries: actionEntries,
          open_window: verification.body.open_window,
        },
      }),
      readLengths: {
        [`${this.#worldId}/action`]: actionEnvelopes.length,
        [`${this.#worldId}/access`]: accessLength,
        ...verification.readLengths,
      },
    };
  }
}
