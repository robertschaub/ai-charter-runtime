// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-008 system-use decision digest, replay-safe lifecycle, and fail-closed resolver. */
import { canonicalize } from './canonicalize.js';
import { digestFor, verifyDigest } from './hash.js';
import {
  outputReleaseInvalidationOps,
  proposalIntakeInvalidationOps,
  proposalRevisionPreparationInvalidationOps,
} from './conversationInvalidation.js';
import {
  systemUseDecisionRecord,
  systemUseDecisionReference,
  systemUseGovernanceProjection,
  timestamp,
  type Mandate,
  type SystemUseDecisionRecord,
  type SystemUseDecisionReference,
  type SystemUseDecisionStatus,
  type SystemUseGovernanceProjection,
  type WalOp,
} from './schemas/index.js';
import { applyWorldTransaction, mandateVersionKey, systemUseDecisionVersionKey, type WorldState } from './state.js';
import type { TransactionActor, WalStore } from './walStore.js';

export interface SystemUseEnvironment {
  readonly systemId: string;
  readonly useCaseId: string;
  readonly jurisdictions: readonly string[];
  readonly hardConditions: Readonly<Record<string, boolean>>;
}

export class SystemUseDecisionError extends Error {
  constructor(
    readonly code:
      | 'forbidden'
      | 'missing'
      | 'ambiguous'
      | 'integrity'
      | 'scope-mismatch'
      | 'inactive'
      | 'condition-unsatisfied',
    message: string,
  ) {
    super(message);
    this.name = 'SystemUseDecisionError';
  }
}

export function systemUseDecisionDigest(record: SystemUseDecisionRecord): string {
  const { record_digest: ignored, ...trace } = record.trace;
  void ignored;
  return digestFor('system-use-decision', { ...record, trace });
}

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

export function systemUseMaterialConfiguration(
  mandate: Mandate,
  policyVersion: string,
  environment: SystemUseEnvironment,
): {
  readonly world_id: string;
  readonly use_case_id: string;
  readonly system_id: string;
  readonly policy_version: string;
  readonly model_cards: readonly {
    readonly card_id: string;
    readonly card_version: number;
    readonly card_digest: string;
    readonly roles: readonly string[];
  }[];
  readonly data_classes: readonly string[];
  readonly jurisdictions: readonly string[];
} {
  const modelCards = mandate.approved_models
    .map((entry) => ({
      card_id: entry.card_id,
      card_version: entry.card_version,
      card_digest: entry.card_digest,
      roles: sorted(entry.roles),
    }))
    .sort((left, right) =>
      `${left.card_id}\u0000${left.card_version}`.localeCompare(`${right.card_id}\u0000${right.card_version}`),
    );
  return {
    world_id: mandate.world_id,
    use_case_id: environment.useCaseId,
    system_id: environment.systemId,
    policy_version: policyVersion,
    model_cards: modelCards,
    data_classes: sorted(
      mandate.approved_models.flatMap((entry) => Object.values(entry.data_classes).flatMap((tags) => tags)),
    ),
    jurisdictions: sorted(environment.jurisdictions),
  };
}

export function systemUseConfigurationDigest(
  mandate: Mandate,
  policyVersion: string,
  environment: SystemUseEnvironment,
): string {
  return digestFor('system-use-configuration', systemUseMaterialConfiguration(mandate, policyVersion, environment));
}

export function createSyntheticSystemUseDecision(
  mandate: Mandate,
  policyVersion: string,
  environment: SystemUseEnvironment,
  at: string,
): SystemUseDecisionRecord {
  const material = systemUseMaterialConfiguration(mandate, policyVersion, environment);
  const base = {
    schema: 'our-ai-charter/system-use-decision@1' as const,
    decision_id: 'sud_test_fixture',
    version: 1,
    world_id: mandate.world_id,
    use_case_id: environment.useCaseId,
    subject: {
      system_id: environment.systemId,
      configuration_digest: systemUseConfigurationDigest(mandate, policyVersion, environment),
      policy_version: policyVersion,
      model_cards: material.model_cards,
      data_classes: material.data_classes,
      jurisdictions: material.jurisdictions,
    },
    purpose: {
      need: 'synthetic-runtime-test',
      expected_outcome: 'exercise-declared-runtime-invariant',
      success_measures: ['named-test-passes'],
      non_ai_or_less_harmful_alternative: 'fixed-fixture-only-test',
      affected_groups: ['synthetic-applicant'],
    },
    evidence_refs: [
      {
        type: 'testing-and-validation' as const,
        ref: 'synthetic-test-fixture',
        provenance: 'synthetic_fixture' as const,
        evidence_depth: 'implementation_checked' as const,
        as_of: at.slice(0, 10),
        limitations: ['not-independently-assessed'],
      },
    ],
    decision: {
      status: 'approved' as const,
      authority_role: 'principal',
      basis_summary: 'synthetic-test-use-only',
      conditions: [],
      unresolved_findings: [],
      residual_risk: { disposition: 'not_assessed' as const, authority_role: 'principal' },
    },
    validity: {
      effective_at: at,
      expires_at: '2999-12-31T23:59:59.999Z',
      review_cadence: 'before-each-test-run',
      redecision_triggers: ['material-runtime-configuration-change'],
    },
    accountability: {
      mission_owner_role: 'principal',
      technical_owner_role: 'operator',
      independent_challenger_role: 'not_available_in_poc' as const,
      remedy_owner_role: 'not_available_in_poc' as const,
    },
    trace: {
      record_digest: '0'.repeat(64),
      evidence_pack_ref: 'synthetic-test-fixture',
      created_at: at,
      supersedes: null,
      challenge_route: 'synthetic-test-challenge-route',
    },
  };
  const unsigned = systemUseDecisionRecord.parse(base);
  return systemUseDecisionRecord.parse({
    ...unsigned,
    trace: { ...unsigned.trace, record_digest: systemUseDecisionDigest(unsigned) },
  });
}

function conditionResults(record: SystemUseDecisionRecord, environment: SystemUseEnvironment) {
  return record.decision.conditions.map((condition) => ({
    id: condition.id,
    satisfied: environment.hardConditions[condition.id] === true,
  }));
}

function assertRecordIntegrity(record: SystemUseDecisionRecord): void {
  if (!verifyDigest(record.trace.record_digest, systemUseDecisionDigest(record))) {
    throw new SystemUseDecisionError('integrity', 'system-use decision digest is invalid');
  }
}

export function resolveCurrentSystemUseDecision(
  state: WorldState,
  mandate: Mandate,
  policyVersion: string,
  atInput: string,
  environment: SystemUseEnvironment,
): SystemUseDecisionReference {
  const at = timestamp.parse(atInput);
  const material = systemUseMaterialConfiguration(mandate, policyVersion, environment);
  const configurationDigest = systemUseConfigurationDigest(mandate, policyVersion, environment);
  const records = [...state.systemUseDecisions.values()];
  for (const record of records) assertRecordIntegrity(record);
  const matching = records.filter((record) => {
    if (
      record.world_id !== material.world_id ||
      record.use_case_id !== material.use_case_id ||
      record.subject.system_id !== material.system_id ||
      record.subject.policy_version !== material.policy_version ||
      !verifyDigest(record.subject.configuration_digest, configurationDigest)
    ) {
      return false;
    }
    return (
      canonicalize(record.subject.model_cards) === canonicalize(material.model_cards) &&
      canonicalize(record.subject.data_classes) === canonicalize(material.data_classes) &&
      canonicalize(record.subject.jurisdictions) === canonicalize(material.jurisdictions)
    );
  });
  if (matching.length === 0) throw new SystemUseDecisionError('missing', 'no exact system-use decision is available');
  const usable = matching.filter((record) => {
    const runtime = state.systemUseDecisionStatus.get(systemUseDecisionVersionKey(record.decision_id, record.version));
    return (
      runtime !== undefined &&
      (runtime.status === 'approved' || runtime.status === 'approved_with_conditions') &&
      at >= record.validity.effective_at &&
      at < record.validity.expires_at
    );
  });
  if (usable.length !== 1) {
    throw new SystemUseDecisionError(usable.length === 0 ? 'inactive' : 'ambiguous', 'system-use decision is not uniquely current');
  }
  const record = usable[0] as SystemUseDecisionRecord;
  const runtime = state.systemUseDecisionStatus.get(systemUseDecisionVersionKey(record.decision_id, record.version));
  if (runtime === undefined || (runtime.status !== 'approved' && runtime.status !== 'approved_with_conditions')) {
    throw new SystemUseDecisionError('inactive', 'system-use decision is not approved');
  }
  const conditions = conditionResults(record, environment);
  if (conditions.some((condition) => !condition.satisfied)) {
    throw new SystemUseDecisionError('condition-unsatisfied', 'a system-use hard condition is unresolved');
  }
  return systemUseDecisionReference.parse({
    decision_id: record.decision_id,
    version: record.version,
    record_digest: record.trace.record_digest,
    status: runtime.status,
    conditions,
  });
}

export function resolveSystemUseForActiveMandate(
  state: WorldState,
  at: string,
  environment: SystemUseEnvironment,
): SystemUseDecisionReference {
  const active = [...state.mandateStatus.entries()].filter(([, status]) => status.state === 'active');
  if (active.length !== 1 || state.policy === undefined) {
    throw new SystemUseDecisionError('scope-mismatch', 'system-use resolution requires one active mandate and policy');
  }
  const [mandateId, status] = active[0] as (typeof active)[number];
  const mandate = state.mandates.get(mandateVersionKey(mandateId, status.version));
  if (mandate === undefined) throw new SystemUseDecisionError('scope-mismatch', 'active mandate is unavailable');
  return resolveCurrentSystemUseDecision(state, mandate, state.policy.policy_version, at, environment);
}

function invalidationOps(state: WorldState, bindingDigest: string, reason: string): WalOp[] {
  const ops: WalOp[] = [];
  for (const ruling of state.rulings.values()) {
    if (
      ruling.status !== 'issued' ||
      ruling.binding.system_use_decision === null ||
      !verifyDigest(ruling.binding.system_use_decision.record_digest, bindingDigest)
    ) {
      continue;
    }
    ops.push({ op: 'ruling.invalidate', ruling_id: ruling.ruling_id, reason });
    for (const reservation of ruling.counter_reservations) {
      if (state.reservations.get(reservation.id)?.state === 'reserved') {
        ops.push({ op: 'reservation.release', reservation_id: reservation.id, reason });
      }
    }
  }
  return ops;
}

export class SystemUseDecisionService {
  readonly #store: WalStore;
  readonly #environment: SystemUseEnvironment;
  readonly #bootstrapFactory:
    | ((mandate: Mandate, policyVersion: string, environment: SystemUseEnvironment, at: string) => SystemUseDecisionRecord)
    | undefined;

  constructor(
    store: WalStore,
    environment: SystemUseEnvironment,
    bootstrapFactory?: (
      mandate: Mandate,
      policyVersion: string,
      environment: SystemUseEnvironment,
      at: string,
    ) => SystemUseDecisionRecord,
  ) {
    this.#store = store;
    this.#environment = Object.freeze({
      ...environment,
      jurisdictions: Object.freeze(sorted(environment.jurisdictions)),
      hardConditions: Object.freeze({ ...environment.hardConditions }),
    });
    this.#bootstrapFactory = bootstrapFactory;
  }

  get environment(): SystemUseEnvironment {
    return this.#environment;
  }

  resolve(state: WorldState, mandate: Mandate, policyVersion: string, at: string): SystemUseDecisionReference {
    return resolveCurrentSystemUseDecision(state, mandate, policyVersion, at, this.#environment);
  }

  resolveActive(state: WorldState, at: string): SystemUseDecisionReference {
    return resolveSystemUseForActiveMandate(state, at, this.#environment);
  }

  /** Re-resolve currentness from this process's immutable scope and hard-condition map. */
  isReferenceCurrent(
    state: WorldState,
    reference: SystemUseDecisionReference | null,
    at: string,
  ): boolean {
    if (reference === null || reference.conditions.some((condition) => !condition.satisfied)) return false;
    try {
      return canonicalize(this.resolveActive(state, at)) === canonicalize(reference);
    } catch (error) {
      if (error instanceof SystemUseDecisionError) return false;
      throw error;
    }
  }

  prepareForMandate(
    state: WorldState,
    mandate: Mandate,
    policyVersion: string,
    at: string,
  ): { readonly ops: readonly WalOp[]; readonly reference: SystemUseDecisionReference } {
    const ops: WalOp[] = [];
    if (state.systemUseDecisions.size === 0 && this.#bootstrapFactory !== undefined) {
      const decision = systemUseDecisionRecord.parse(
        this.#bootstrapFactory(mandate, policyVersion, this.#environment, at),
      );
      assertRecordIntegrity(decision);
      ops.push({ op: 'system_use_decision.issue', decision });
      applyWorldTransaction(state, ops, at);
    }
    return { ops, reference: this.resolve(state, mandate, policyVersion, at) };
  }

  async installFixture(recordInput: SystemUseDecisionRecord, actor: TransactionActor): Promise<void> {
    if (actor.credential !== 'proc:authz') throw new SystemUseDecisionError('forbidden', 'only authorization may install decisions');
    const record = systemUseDecisionRecord.parse(recordInput);
    assertRecordIntegrity(record);
    await this.#store.transactWithState('system_use_decision_issue', actor, (state) => {
      const existing = state.systemUseDecisions.get(systemUseDecisionVersionKey(record.decision_id, record.version));
      if (existing !== undefined) {
        if (canonicalize(existing) !== canonicalize(record)) {
          throw new SystemUseDecisionError('integrity', 'recorded decision differs from the startup fixture');
        }
        return { ops: [], result: undefined };
      }
      return { ops: [{ op: 'system_use_decision.issue', decision: record }], result: undefined };
    });
  }

  async transition(
    decisionId: string,
    version: number,
    status: SystemUseDecisionStatus,
    actor: TransactionActor,
  ): Promise<void> {
    if (actor.credential !== 'proc:authz') throw new SystemUseDecisionError('forbidden', 'only authorization may transition decisions');
    await this.#store.transactWithState('system_use_decision_transition', actor, (state, at) => {
      const record = state.systemUseDecisions.get(systemUseDecisionVersionKey(decisionId, version));
      if (record === undefined) throw new SystemUseDecisionError('missing', 'system-use decision does not exist');
      return {
        ops: [
          ...invalidationOps(state, record.trace.record_digest, `system-use-${status}`),
          ...outputReleaseInvalidationOps(
            state,
            (release) => verifyDigest(release.system_use_decision.record_digest, record.trace.record_digest),
            `system-use-${status}`,
            at,
          ),
          ...proposalIntakeInvalidationOps(
            state,
            (intake) => verifyDigest(intake.system_use_decision.record_digest, record.trace.record_digest),
            'binding-invalidated',
            at,
          ),
          ...proposalRevisionPreparationInvalidationOps(
            state,
            (preparation) => verifyDigest(preparation.system_use_decision.record_digest, record.trace.record_digest),
            'authority-changed',
            at,
          ),
          { op: 'system_use_decision.transition', decision_id: decisionId, version, status, changed_at: at },
        ],
        result: undefined,
      };
    });
  }

  async replace(recordInput: SystemUseDecisionRecord, actor: TransactionActor): Promise<void> {
    if (actor.credential !== 'proc:authz') throw new SystemUseDecisionError('forbidden', 'only authorization may replace decisions');
    const record = systemUseDecisionRecord.parse(recordInput);
    assertRecordIntegrity(record);
    const predecessor = record.trace.supersedes;
    if (predecessor === null) throw new SystemUseDecisionError('scope-mismatch', 'a replacement must name its predecessor');
    await this.#store.transactWithState('system_use_decision_replace', actor, (state, at) => {
      const prior = state.systemUseDecisions.get(systemUseDecisionVersionKey(predecessor.decision_id, predecessor.version));
      if (prior === undefined) throw new SystemUseDecisionError('missing', 'system-use predecessor does not exist');
      return {
        ops: [
          ...invalidationOps(state, prior.trace.record_digest, 'system-use-superseded'),
          ...outputReleaseInvalidationOps(
            state,
            (release) => verifyDigest(release.system_use_decision.record_digest, prior.trace.record_digest),
            'system-use-superseded',
            at,
          ),
          ...proposalIntakeInvalidationOps(
            state,
            (intake) => verifyDigest(intake.system_use_decision.record_digest, prior.trace.record_digest),
            'binding-invalidated',
            at,
          ),
          ...proposalRevisionPreparationInvalidationOps(
            state,
            (preparation) => verifyDigest(preparation.system_use_decision.record_digest, prior.trace.record_digest),
            'authority-changed',
            at,
          ),
          {
            op: 'system_use_decision.transition',
            decision_id: predecessor.decision_id,
            version: predecessor.version,
            status: 'superseded',
            changed_at: at,
          },
          { op: 'system_use_decision.issue', decision: record },
        ],
        result: undefined,
      };
    });
  }

  governanceProjection(atInput: string): SystemUseGovernanceProjection {
    const state = this.#store.snapshot();
    const at = timestamp.parse(atInput);
    const records = [...state.systemUseDecisions.values()].sort((left, right) => left.version - right.version);
    if (records.length === 0) return systemUseGovernanceProjection.parse({ currentness: 'missing', decision: null });
    for (const record of records) assertRecordIntegrity(record);
    const record = records.at(-1) as SystemUseDecisionRecord;
    const runtime = state.systemUseDecisionStatus.get(systemUseDecisionVersionKey(record.decision_id, record.version));
    const conditions = conditionResults(record, this.#environment);
    let current = false;
    try {
      const resolved = this.resolveActive(state, at);
      current =
        resolved.decision_id === record.decision_id &&
        resolved.version === record.version &&
        verifyDigest(resolved.record_digest, record.trace.record_digest);
    } catch (error) {
      if (!(error instanceof SystemUseDecisionError)) throw error;
    }
    return systemUseGovernanceProjection.parse({
      currentness: current ? 'current' : 'not-current',
      decision: {
        decision_id: record.decision_id,
        version: record.version,
        record_digest: record.trace.record_digest,
        status: runtime?.status ?? record.decision.status,
        world_id: record.world_id,
        use_case_id: record.use_case_id,
        system_id: record.subject.system_id,
        configuration_digest: record.subject.configuration_digest,
        policy_version: record.subject.policy_version,
        model_cards: record.subject.model_cards,
        data_classes: record.subject.data_classes,
        jurisdictions: record.subject.jurisdictions,
        evidence: record.evidence_refs.map((evidence) => ({
          type: evidence.type,
          provenance: evidence.provenance,
          evidence_depth: evidence.evidence_depth,
          as_of: evidence.as_of,
          limitations: evidence.limitations,
        })),
        conditions,
        effective_at: record.validity.effective_at,
        expires_at: record.validity.expires_at,
        review_cadence: record.validity.review_cadence,
        redecision_triggers: record.validity.redecision_triggers,
        basis_summary: record.decision.basis_summary,
        unresolved_finding_count: record.decision.unresolved_findings.length,
        accountability: record.accountability,
        limitations: [
          'synthetic POC decision',
          'not independently assessed',
          'not legal or conformity approval',
          'not certification or action authority',
        ],
      },
    });
  }
}

/** Test-only constructor for existing synthetic harnesses; production loads the checked-in fixture explicitly. */
export function syntheticSystemUseForTests(store: WalStore): SystemUseDecisionService {
  return new SystemUseDecisionService(
    store,
    {
      systemId: 'ai-charter-runtime-poc',
      useCaseId: 'public-grant-decision',
      jurisdictions: ['synthetic-demo'],
      hardConditions: { 'no-external-effect': true, 'synthetic-data-only': true },
    },
    createSyntheticSystemUseDecision,
  );
}
