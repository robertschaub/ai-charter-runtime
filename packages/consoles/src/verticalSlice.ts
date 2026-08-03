// SPDX-License-Identifier: MIT
/** Deterministic M3 orchestrator loop; HTTP process wrappers remain an M4 concern. */
import { readFileSync } from 'node:fs';

import {
  AuthorizationCore,
  bindMandate,
  checkpointReceiptReference,
  digestFor,
  effectIntent,
  freezeProposal,
  jsonScalarOrList,
  loadPolicyFile,
  WalStore,
  type CardRegistry,
  type CheckpointReceiptReference,
  type Keyring,
  type Mandate,
  type RecordsVerificationReport,
} from 'gate-core';
import type { OpenAiCompatibleAdapter } from 'model-adapters';
import { EffectLedger, MockServicesHost } from 'services-mock';
import { z } from 'zod';

const ORCHESTRATOR = { credential: 'proc:orchestrator', claimed_role: 'case_officer' } as const;
const AUTHZ_BOOTSTRAP = { credential: 'proc:authz', claimed_role: null } as const;

const PROPOSAL_JSON_SCHEMA = {
  type: 'object',
  additionalProperties: false,
  required: [
    'declared_objective',
    'proposed_action',
    'target',
    'exact_parameters',
    'data_to_be_disclosed',
    'cost_obligation',
    'material_consequences',
    'reversibility_class',
  ],
  properties: {
    declared_objective: { type: 'string' },
    proposed_action: { type: 'string' },
    target: {
      type: 'object',
      additionalProperties: false,
      required: ['recipient', 'resource'],
      properties: { recipient: { type: 'string' }, resource: { type: 'string' } },
    },
    exact_parameters: {
      type: 'object',
      additionalProperties: false,
      required: ['amount_minor_units', 'reference'],
      properties: { amount_minor_units: { type: 'integer' }, reference: { type: 'string' } },
    },
    data_to_be_disclosed: { type: 'array', items: { type: 'string' } },
    cost_obligation: {
      type: 'object',
      additionalProperties: false,
      required: ['amount_minor_units', 'description'],
      properties: { amount_minor_units: { type: 'integer' }, description: { type: 'string' } },
    },
    material_consequences: { type: 'array', items: { type: 'string' } },
    reversibility_class: { type: 'string' },
  },
} as const;

const proposalDraft = z
  .object({
    declared_objective: z.string().min(1),
    proposed_action: z.string().min(1),
    target: z.object({ recipient: z.string().min(1), resource: z.string().min(1) }).strict(),
    exact_parameters: z.record(z.string(), jsonScalarOrList),
    data_to_be_disclosed: z.array(z.string()),
    cost_obligation: z
      .object({ amount_minor_units: z.number().int().safe().min(0), description: z.string() })
      .strict(),
    material_consequences: z.array(z.string()),
    reversibility_class: z.string().regex(/^[a-z][a-z0-9-]*$/),
  })
  .strict();

export interface VerticalSliceOptions {
  readonly recordsRoot: string;
  readonly policyFile: string;
  readonly mandateSeedFile: string;
  readonly keyring: Keyring;
  readonly cardRegistry: CardRegistry;
  readonly adapter: OpenAiCompatibleAdapter;
  readonly cardId: string;
  readonly cardVersion: number;
  readonly now?: string;
  readonly caseId?: string;
  /** Authorization-owned startup verification state; absent means no pushed checkpoint is claimed. */
  readonly recordVerification?: RecordsVerificationReport;
}

export interface LocalRecordReceipt {
  readonly kind: 'local-record-receipt';
  readonly world_id: string;
  readonly case_id: string;
  readonly selection_id: string;
  readonly requested_model_id: string;
  readonly served_model_id: string;
  readonly ruling_id: string;
  readonly commitment_id: string;
  readonly effect_id: string;
  readonly outcome: 'success' | 'failed';
  readonly record_entry_id: string;
  readonly anchoring_status: 'anchored-prefix' | 'open-window' | 'no-pushed-checkpoint';
  readonly latest_pushed_checkpoint: CheckpointReceiptReference | null;
  readonly local_receipt_notice: string;
}

export class VerticalSliceError extends Error {
  constructor(readonly stage: string, message: string) {
    super(message);
    this.name = 'VerticalSliceError';
  }
}

export async function runVerticalSlice(options: VerticalSliceOptions): Promise<LocalRecordReceipt> {
  const now = options.now ?? '2026-08-01T09:00:00.000Z';
  const caseId = options.caseId ?? 'case_demo';
  const evaluatorDigest = digestFor('evaluator-build', { package: 'gate-core', version: '0.0.1' });
  const policy = loadPolicyFile(options.policyFile, evaluatorDigest);
  const rawMandate = JSON.parse(readFileSync(options.mandateSeedFile, 'utf8')) as Omit<Mandate, 'binding'>;
  const boundMandate = bindMandate(options.keyring, rawMandate);
  const store = WalStore.open({
    recordsRoot: options.recordsRoot,
    worldId: boundMandate.world_id,
    runId: 'run_m3_vertical',
    bootId: 'authz_boot_m3',
    policyVersion: policy.policy.policy_version,
    policyContentDigest: policy.policyContentDigest,
    evaluatorBuildDigest: policy.evaluatorBuildDigest,
    now: () => now,
  });
  try {
    const authorization = new AuthorizationCore({
      store,
      keyring: options.keyring,
      policy,
      resolveAuthorizedAgent: (actor) => (actor.credential === 'proc:orchestrator' ? 'agent_demo' : undefined),
      resolveScreening: () => ({ performed: true, signals: [], evidenceRefs: [] }),
      validateScreeningResolution: () => true,
      resolveModelEvidence: (proposal) => options.cardRegistry.resolve(proposal),
    });
    await authorization.activatePolicy();
    // Startup-only synthetic seed. No orchestrator route exposes this authorization-owned operation.
    await authorization.grantMandate(boundMandate, AUTHZ_BOOTSTRAP);

    const modelResponse = await options.adapter.act({
      messages: [
        {
          role: 'system',
          content: 'Return only the requested synthetic action proposal as JSON. The authorization service decides.',
        },
        { role: 'user', content: 'Prepare the synthetic grant filing described by the seeded mandate.' },
      ],
      maxOutputTokens: 512,
      responseFormat: {
        type: 'json_schema',
        json_schema: { name: 'proposal_draft', strict: true, schema: PROPOSAL_JSON_SCHEMA },
      },
    });
    if (modelResponse.content === null) throw new VerticalSliceError('proposal', 'acting model returned no proposal');
    let rawDraft: unknown;
    try {
      rawDraft = JSON.parse(modelResponse.content);
    } catch {
      throw new VerticalSliceError('proposal', 'acting model proposal was not JSON');
    }
    const draft = proposalDraft.parse(rawDraft);
    const proposal = freezeProposal({
      world_id: boundMandate.world_id,
      proposal_id: 'prp_demo_1',
      revision: 1,
      action_id: 'act_demo_1',
      created_at: now,
      ...draft,
      material_inputs: [],
      derived_claims: [],
      commercial_influence: { applicable: false, note: 'Not applicable in the synthetic grant scenario.' },
      acting_model: {
        requested_id: modelResponse.requestedId,
        served_id: modelResponse.servedId,
        card_id: options.cardId,
        card_version: options.cardVersion,
      },
      mandate_ref: { mandate_id: boundMandate.mandate_id, version: boundMandate.version },
    });

    const selected = await authorization.recordModelSelection({ caseId, proposal, actor: ORCHESTRATOR });
    if (!selected.accepted) throw new VerticalSliceError('model-selection', selected.defect);
    const ruled = await authorization.ruleProposal({
      gate: 'commit',
      proposal,
      service: boundMandate.connected_service,
      actionClass: boundMandate.action_class,
      actor: ORCHESTRATOR,
    });
    if (ruled.ruling.verdict !== 'allow') {
      throw new VerticalSliceError('ruling', `gate returned ${ruled.ruling.verdict}: ${ruled.ruling.reason}`);
    }

    const ledger = new EffectLedger({
      recordsRoot: options.recordsRoot,
      worldId: boundMandate.world_id,
      bootId: 'services_boot_m3',
      keyring: options.keyring,
      now: () => now,
    });
    const services = new MockServicesHost(ledger, authorization);
    const intent = effectIntent.parse({
      world_id: proposal.world_id,
      ruling_id: ruled.ruling.ruling_id,
      frozen_proposal_hash: proposal.proposal_hash,
      service: boundMandate.connected_service,
      action_class: boundMandate.action_class,
      target: proposal.target,
      exact_parameters: proposal.exact_parameters,
      data_to_be_disclosed: proposal.data_to_be_disclosed,
    });
    const executed = await services.execute(ruled.ruling.ruling_id, intent);
    if (!executed.ok) throw new VerticalSliceError(executed.stage, JSON.stringify(executed));
    if (!executed.report.accepted || executed.report.recordEntryId === null) {
      throw new VerticalSliceError('receipt', 'authorization service did not seal an outcome receipt');
    }
    const recordEntryId = executed.report.recordEntryId;
    const actionEntryIndex = store
      .snapshot()
      .actionRecords.findIndex((entry) => entry.entry_id === recordEntryId);
    if (actionEntryIndex < 0) throw new VerticalSliceError('receipt', 'outcome receipt is absent from the action chain');
    const latestPushedCheckpoint = checkpointReceiptReference(
      options.recordVerification,
      boundMandate.world_id,
      actionEntryIndex,
    );
    return {
      kind: 'local-record-receipt',
      world_id: boundMandate.world_id,
      case_id: caseId,
      selection_id: selected.selectionId,
      requested_model_id: modelResponse.requestedId,
      served_model_id: modelResponse.servedId,
      ruling_id: ruled.ruling.ruling_id,
      commitment_id: executed.commitmentId,
      effect_id: executed.effect.effect_id,
      outcome: executed.effect.outcome,
      record_entry_id: recordEntryId,
      anchoring_status:
        latestPushedCheckpoint === null
          ? 'no-pushed-checkpoint'
          : latestPushedCheckpoint.action_inside_anchored_prefix
            ? 'anchored-prefix'
            : 'open-window',
      latest_pushed_checkpoint: latestPushedCheckpoint,
      local_receipt_notice: 'Local record receipt only; independent lodgment custody is outside this POC.',
    };
  } finally {
    store.close();
  }
}
