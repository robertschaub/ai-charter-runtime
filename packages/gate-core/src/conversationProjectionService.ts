// SPDX-License-Identifier: AGPL-3.0-only
/** M5.2 projections plus M5.3 authorization-owned model-output admission. */
import { canonicalize } from './canonicalize.js';
import { CardRegistry, type CardInspection } from './cardRegistry.js';
import { projectConversation, type ProjectConversationInput } from './conversationProjection.js';
import { evaluateModelOutput, ModelOutputAdmissionError } from './modelOutputAdmission.js';
import { verifyEmbeddedMac, type Keyring } from './keyring.js';
import type { ScreeningResolution } from './authorizationCore.js';
import {
  cardSlug,
  id,
  integer,
  modelId,
  timestamp,
  type EvidenceRef,
  type FrozenProposal,
  type Mandate,
  type ModelRole,
  modelOutputAdmissionRequest,
  type ModelOutputAdmission,
  type ModelOutputAdmissionRequest,
} from './schemas/index.js';
import { screeningFixtureSet, type ScreeningFixture } from './screeningFixture.js';
import { mandateVersionKey } from './state.js';
import type { TransactionActor, WalStore } from './walStore.js';

export class ConversationProjectionServiceError extends Error {
  constructor(
    readonly code: 'forbidden' | 'invalid-scope' | 'mandate-unavailable' | 'model-unavailable',
    message: string,
  ) {
    super(message);
    this.name = 'ConversationProjectionServiceError';
  }
}

export interface ActingProjectionInput {
  readonly mandateId: string;
  readonly mandateVersion: number;
  readonly cardId: string;
  readonly cardVersion: number;
  readonly requestedId: string;
  readonly actor: TransactionActor;
}

export interface ScreeningProjectionInput {
  readonly proposal: FrozenProposal;
  readonly gate: 'submit' | 'verify';
  readonly caseId?: string;
}

export type OutputAdmissionInput = ModelOutputAdmissionRequest & {
  readonly actor: TransactionActor;
};

export interface ConversationProjectionServiceOptions {
  readonly store: WalStore;
  readonly cards: CardRegistry;
  readonly keyring: Keyring;
  readonly caseId: string;
  readonly screeningFixtures: readonly ScreeningFixture[];
  readonly now?: () => string;
}

interface ResolvedProjectionInput {
  readonly mandateId: string;
  readonly mandateVersion: number;
  readonly cardId: string;
  readonly cardVersion: number;
  readonly requestedId: string;
  readonly role: ModelRole;
  readonly caseId: string;
  readonly entries?: ProjectConversationInput['entries'];
}

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

function projectionEvidence(projection: ReturnType<typeof projectConversation>): EvidenceRef {
  return {
    kind: 'submit_projection',
    provider: projection.provider,
    role: projection.role,
    included: projection.summary.included,
    dropped: projection.summary.dropped,
    dropped_item_ids: projection.summary.dropped_item_ids,
    unmet_tags: projection.summary.unmet_tags,
  };
}

function skippedEvidence(
  reason: Extract<EvidenceRef, { kind: 'screening_skipped' }>['reason'],
  provider: string | null,
  suspectItemIds: readonly string[],
): EvidenceRef {
  return {
    kind: 'screening_skipped',
    provider: provider === null ? null : cardSlug.parse(provider),
    role: 'screening',
    reason,
    suspect_item_ids: sorted(suspectItemIds),
  };
}

/**
 * No caller supplies a case, role, item list, or effective clearance. Acting projection
 * fixes case and role at this boundary; screening selection comes only from an exact
 * authorization-owned fixture over a frozen proposal hash.
 */
export class ConversationProjectionService {
  readonly #store: WalStore;
  readonly #cards: CardRegistry;
  readonly #keyring: Keyring;
  readonly #caseId: string;
  readonly #fixtures: readonly ScreeningFixture[];
  readonly #now: () => string;

  constructor(options: ConversationProjectionServiceOptions) {
    this.#store = options.store;
    this.#cards = options.cards;
    this.#keyring = options.keyring;
    this.#caseId = id.parse(options.caseId);
    this.#fixtures = screeningFixtureSet.parse(options.screeningFixtures);
    this.#now = options.now ?? (() => new Date().toISOString());
  }

  acting(input: ActingProjectionInput): ReturnType<typeof projectConversation> {
    return this.#resolveActing(input).projection;
  }

  admitOutput(input: OutputAdmissionInput): ModelOutputAdmission {
    const { actor, ...request } = input;
    const parsed = modelOutputAdmissionRequest.parse(request);
    const resolved = this.#resolveActing({
      mandateId: parsed.mandate_id,
      mandateVersion: parsed.mandate_version,
      cardId: parsed.card_id,
      cardVersion: parsed.card_version,
      requestedId: parsed.requested_id,
      actor,
    });
    try {
      return evaluateModelOutput({
        request: parsed,
        caseId: this.#caseId,
        projection: resolved.projection,
        resolutionPolicy: resolved.inspection.card.model.resolution.policy,
        observedServedIds: resolved.inspection.card.model.resolution.observed_snapshots.map((entry) => entry.id),
      });
    } catch (error) {
      if (error instanceof ModelOutputAdmissionError) {
        throw new ConversationProjectionServiceError('invalid-scope', 'model output does not match the current acting projection');
      }
      throw error;
    }
  }

  #resolveActing(input: ActingProjectionInput): {
    readonly projection: ReturnType<typeof projectConversation>;
    readonly inspection: CardInspection;
  } {
    if (input.actor.credential !== 'proc:orchestrator') {
      throw new ConversationProjectionServiceError('forbidden', 'only the orchestrator process may read acting projection');
    }
    const mandateId = id.parse(input.mandateId);
    const mandateVersion = integer.min(1).parse(input.mandateVersion);
    const governingMandate = this.#singleActiveMandate();
    if (governingMandate.mandate_id !== mandateId || governingMandate.version !== mandateVersion) {
      throw new ConversationProjectionServiceError(
        'invalid-scope',
        'acting projection mandate does not match the sole active mandate',
      );
    }
    return this.#resolveProjection({
      mandateId,
      mandateVersion,
      cardId: cardSlug.parse(input.cardId),
      cardVersion: integer.min(1).parse(input.cardVersion),
      requestedId: modelId.parse(input.requestedId),
      role: 'acting',
      caseId: this.#caseId,
    });
  }

  screening(input: ScreeningProjectionInput): ScreeningResolution {
    const fixture = this.#fixtures.find(
      (candidate) => candidate.proposal_hash === input.proposal.proposal_hash && candidate.gate === input.gate,
    );
    if (fixture === undefined) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence('fixture-unavailable', null, [])],
      };
    }
    const caseId = input.caseId ?? this.#caseId;
    if (caseId !== this.#caseId) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence('case-mismatch', fixture.provider, fixture.suspect_item_ids)],
      };
    }

    const proposalItems = new Map(
      [...input.proposal.material_inputs, ...input.proposal.derived_claims].map((item) => [item.id, item]),
    );
    const state = this.#store.snapshot();
    const selectedEntries = fixture.suspect_item_ids.flatMap((itemId) => {
      const proposalItem = proposalItems.get(itemId);
      const entry = state.storeItems.get(itemId);
      return proposalItem !== undefined &&
        entry !== undefined &&
        entry.case_id === this.#caseId &&
        canonicalize(proposalItem) === canonicalize(entry.item)
        ? [entry]
        : [];
    });
    if (selectedEntries.length !== fixture.suspect_item_ids.length) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence('proposal-item-mismatch', fixture.provider, fixture.suspect_item_ids)],
      };
    }

    let projection: ReturnType<typeof projectConversation>;
    try {
      projection = this.#project({
        mandateId: input.proposal.mandate_ref.mandate_id,
        mandateVersion: input.proposal.mandate_ref.version,
        cardId: fixture.provider,
        cardVersion: this.#approvedVersion(input.proposal.mandate_ref.mandate_id, fixture.provider, 'screening'),
        requestedId: this.#approvedRequestedId(input.proposal.mandate_ref.mandate_id, fixture.provider, 'screening'),
        role: 'screening',
        caseId: this.#caseId,
        entries: selectedEntries,
      });
    } catch (error) {
      const reason =
        error instanceof ConversationProjectionServiceError && error.code === 'mandate-unavailable'
          ? 'mandate-unavailable'
          : 'model-unavailable';
      return {
        performed: false,
        signals: [],
        evidenceRefs: [skippedEvidence(reason, fixture.provider, fixture.suspect_item_ids)],
      };
    }
    const projectionRef = projectionEvidence(projection);
    if (projection.summary.dropped > 0 || projection.items.length !== fixture.suspect_item_ids.length) {
      return {
        performed: false,
        signals: [],
        evidenceRefs: [projectionRef, skippedEvidence('disclosure-restricted', fixture.provider, fixture.suspect_item_ids)],
      };
    }
    return { performed: true, signals: fixture.signals, evidenceRefs: [projectionRef] };
  }

  validateScreeningResolution(
    resolution: ScreeningResolution,
    proposal: FrozenProposal,
    gate: 'submit' | 'verify',
    caseId?: string,
  ): boolean {
    return canonicalize(this.screening({ proposal, gate, ...(caseId === undefined ? {} : { caseId }) })) ===
      canonicalize(resolution);
  }

  #currentMandate(mandateIdInput: string, versionInput?: number): Mandate {
    const mandateId = id.parse(mandateIdInput);
    const state = this.#store.snapshot();
    const status = state.mandateStatus.get(mandateId);
    const version = versionInput ?? status?.version;
    const mandateValue = version === undefined ? undefined : state.mandates.get(mandateVersionKey(mandateId, version));
    const now = timestamp.parse(this.#now());
    if (
      status === undefined ||
      mandateValue === undefined ||
      status.version !== version ||
      status.state !== 'active' ||
      mandateValue.state !== 'active' ||
      now < mandateValue.issued_at ||
      now > mandateValue.expires_at ||
      now < mandateValue.limits.time_window.not_before ||
      now > mandateValue.limits.time_window.not_after ||
      verifyEmbeddedMac(
        this.#keyring,
        'mandate-binding',
        mandateValue as unknown as Record<string, unknown>,
        'binding',
      ) !== 'valid'
    ) {
      throw new ConversationProjectionServiceError('mandate-unavailable', 'mandate is not current and active');
    }
    return mandateValue;
  }

  #singleActiveMandate(): Mandate {
    const active = [...this.#store.snapshot().mandateStatus.entries()].filter(
      ([, status]) => status.state === 'active',
    );
    if (active.length !== 1) {
      throw new ConversationProjectionServiceError(
        'mandate-unavailable',
        'acting projection requires exactly one active mandate in the bounded POC world',
      );
    }
    const [mandateId, status] = active[0] as (typeof active)[number];
    return this.#currentMandate(mandateId, status.version);
  }

  #approvedVersion(mandateId: string, cardId: string, role: ModelRole): number {
    const approval = this.#currentMandate(mandateId).approved_models.find(
      (candidate) => candidate.card_id === cardId && candidate.roles.includes(role),
    );
    if (approval === undefined) {
      throw new ConversationProjectionServiceError('model-unavailable', `model ${cardId} is not approved for ${role}`);
    }
    return approval.card_version;
  }

  #approvedRequestedId(mandateId: string, cardId: string, role: ModelRole): string {
    const approval = this.#currentMandate(mandateId).approved_models.find(
      (candidate) => candidate.card_id === cardId && candidate.roles.includes(role),
    );
    if (approval === undefined) {
      throw new ConversationProjectionServiceError('model-unavailable', `model ${cardId} is not approved for ${role}`);
    }
    return approval.requested_id;
  }

  #resolveProjection(input: ResolvedProjectionInput): {
    readonly projection: ReturnType<typeof projectConversation>;
    readonly inspection: CardInspection;
  } {
    if (input.caseId !== this.#caseId) {
      throw new ConversationProjectionServiceError('invalid-scope', 'projection case does not match authorization configuration');
    }
    const mandateValue = this.#currentMandate(input.mandateId, input.mandateVersion);
    const approval = mandateValue.approved_models.find(
      (candidate) =>
        candidate.card_id === input.cardId &&
        candidate.card_version === input.cardVersion &&
        candidate.requested_id === input.requestedId &&
        candidate.roles.includes(input.role),
    );
    const inspection = this.#cards.get(input.cardId);
    if (
      approval === undefined ||
      inspection === undefined ||
      !inspection.signatureValid ||
      inspection.withdrawn ||
      inspection.integrityAlarm ||
      inspection.card.card_version !== approval.card_version ||
      inspection.card.model.requested_id !== approval.requested_id ||
      inspection.digest !== approval.card_digest
    ) {
      throw new ConversationProjectionServiceError('model-unavailable', 'approved model card is unavailable or changed');
    }
    const mandateClearances = approval.data_classes[input.role];
    const cardClearances = inspection.card.declared_data_classes[input.role];
    if (mandateClearances === undefined || cardClearances === undefined) {
      throw new ConversationProjectionServiceError('model-unavailable', `model lacks ${input.role} clearance`);
    }
    return {
      projection: projectConversation({
        worldId: mandateValue.world_id,
        caseId: this.#caseId,
        provider: approval.card_id,
        role: input.role,
        mandateClearances,
        cardClearances,
        entries: input.entries ?? [...this.#store.snapshot().storeItems.values()],
      }),
      inspection,
    };
  }

  #project(input: ResolvedProjectionInput): ReturnType<typeof projectConversation> {
    return this.#resolveProjection(input).projection;
  }
}
