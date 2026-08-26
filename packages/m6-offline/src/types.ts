// SPDX-License-Identifier: MIT

export type LaneSlot = 'lane-0' | 'lane-1';
export type CaseClass = 'beat' | 'adversarial' | 'infrastructure';
export type ComparisonMode = 'invariant' | 'provider_specific' | 'single';
export type Coverage = 'exercised' | 'partial' | 'not_assessed' | 'not_applicable';
export type OfflineLayer = 'offline-fixture' | 'dry-run';

export interface CardBinding {
  readonly card_id: string;
  readonly card_version: number;
  readonly card_digest: string;
  readonly requested_id: string;
}

export interface CatalogRow {
  readonly id: string;
  readonly class: CaseClass;
  readonly comparison_mode: ComparisonMode;
  readonly coverage: Coverage;
  readonly required_terminal_evidence: string;
}

export interface CaseCatalog {
  readonly schema_version: 'm6-case-catalog/v1';
  readonly rows: readonly CatalogRow[];
  readonly exclusions: readonly [{
    readonly id: 'subdelegation';
    readonly coverage: 'not_assessed';
    readonly reason: string;
  }];
}

export interface GateObservation {
  readonly name: 'authorize' | 'submit' | 'verify' | 'commit' | 'rely';
  readonly verdict: 'allow' | 'deny' | 'escalate';
  readonly matched_rule_id: string | null;
  readonly ux_class: 'silent' | 'flag' | 'stop';
}

export interface InterventionObservation {
  readonly trigger: string;
  readonly eligible_role: string;
  readonly permitted_dispositions: readonly string[];
  readonly terminal_disposition: string | null;
}

export interface ObservedAssertion {
  readonly name: string;
  readonly observed: boolean | number | string | null;
}

export interface BoundedCaseResult {
  readonly evidence_id: string;
  readonly case_id: string;
  readonly class: CaseClass;
  readonly lane_slot: LaneSlot | 'single';
  readonly selected_card: CardBinding | null;
  readonly gates: readonly GateObservation[];
  readonly intervention: InterventionObservation | null;
  readonly commitment_state: 'none' | 'blocked' | 'prepared' | 'committed' | 'already_bound';
  readonly effect_count: number;
  readonly failure_class: string | null;
  readonly containment_class: string;
  readonly coverage: Coverage;
  readonly mechanism: string;
  readonly observed_assertions: readonly ObservedAssertion[];
}

export interface ComparisonProjection {
  readonly gates: readonly GateObservation[];
  readonly intervention: InterventionObservation | null;
  readonly commitment_state: BoundedCaseResult['commitment_state'];
  readonly effect_count: number;
  readonly failure_class: string | null;
  readonly containment_class: string;
  readonly coverage: Coverage;
}

export interface PairComparison {
  readonly case_id: string;
  readonly mode: Exclude<ComparisonMode, 'single'>;
  readonly lane_0_digest: string;
  readonly lane_1_digest: string;
  readonly outcome_equal: boolean;
  readonly status: 'pass';
  readonly reason: 'invariant_outcome' | 'expected_provider_permission_difference';
}

export interface ScenarioContext {
  readonly captureId: string;
  readonly attemptId: string;
  readonly row: CatalogRow;
  readonly laneSlot: LaneSlot | 'single';
  readonly selectedCard: CardBinding | null;
  readonly fixedNow: string;
  readonly stagingRoot: string;
  readonly recordsRoot: string;
}

export type CaseExecutor = (context: ScenarioContext) => Promise<BoundedCaseResult>;

export interface CapturePlan {
  readonly schema_version: 'm6-capture-plan/v1';
  readonly capture_id: string;
  readonly supersedes_capture_id: string | null;
  readonly scenario_id: string;
  readonly layers: readonly ('dry-run' | 'live' | 'offline-fixture')[];
  readonly catalog_digest: string;
  readonly lanes: readonly [
    { readonly lane_slot: 'lane-0'; readonly card_binding: CardBinding },
    { readonly lane_slot: 'lane-1'; readonly card_binding: CardBinding },
  ];
  readonly screening_role: CardBinding;
  readonly provenance: Readonly<Record<string, unknown>>;
  readonly synthetic_inputs: readonly { readonly id: string; readonly digest: string }[];
  readonly clock_profile: string;
  readonly deterministic_id_profile: string;
  readonly expected_boundaries: Readonly<Record<string, unknown>>;
  readonly runtime_environment: Readonly<Record<string, string>>;
  readonly commands: readonly { readonly name: string; readonly argv: readonly string[] }[];
  readonly network_classification: 'dry-run' | 'live' | 'offline-fixture';
  readonly timeout_ms: number;
  readonly write_roots: readonly ['.m6-staging'];
  readonly request_ceilings: Readonly<Record<string, number>>;
  readonly no_retry: true;
  readonly no_fallback: true;
  readonly checkpoint_requirements: Readonly<Record<string, string>>;
  readonly artifact_schema_versions: Readonly<Record<string, string>>;
  readonly storyboards: readonly { readonly id: string; readonly case_ids: readonly string[] }[];
  readonly plan_digest: string;
}

export type AttemptState =
  | 'planned'
  | 'preflighted'
  | 'running'
  | 'complete'
  | 'failed'
  | 'indeterminate'
  | 'sanitized'
  | 'reviewed-for-publication';

export interface AttemptEvent {
  readonly sequence: number;
  readonly attempt_id: string;
  readonly layer: 'dry-run' | 'live' | 'offline-fixture';
  readonly state: AttemptState;
  readonly recorded_at: string;
  readonly failure_class: string | null;
}
