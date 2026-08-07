// SPDX-License-Identifier: MIT
/** Narrow HTTP clients held by the orchestrator process. */
import {
  classToken,
  effectIntent,
  frozenProposal,
  id,
  modelCallAdmission,
  modelCallAdmissionRequest,
  modelCallBeginRequest,
  modelCallFailedRecord,
  modelCallFailureRequest,
  modelCallStart,
  modelSelectionCheckProjection,
  modelSelectionCheckRequest,
  modelSelectionProjection,
  modelSelectionRequest,
  currentModelSelectionProjection,
  approvedModelsProjection,
  proposalRulingProjection,
  rulingProjection,
  browserOrigin,
  timestamp,
  worldId,
  type EffectIntent,
  type FrozenProposal,
  type ApprovedModelsProjection,
  type ProposalRulingProjection,
  type RulingProjection,
  type ModelCallAdmission,
  type ModelCallFailedRecord,
  type ModelCallFailureRequest,
  type ModelCallStart,
  type CurrentModelSelectionProjection,
  type ModelSelectionCheckProjection,
  type ModelSelectionCheckRequest,
  type ModelSelectionProjection,
  type ModelSelectionRequest,
  type ModelOutputAdmissionRequest,
} from 'gate-core';
import type { ServicesHostExecution } from 'services-mock';
import { z } from 'zod';

const handoffRedeemInput = z
  .object({
    handoff_id: id,
    handoff_code: z.string().regex(/^[0-9a-f]{64,}$/),
    role: z.literal('case_officer'),
    world_id: worldId,
    case_id: id,
    target_origin: browserOrigin,
    authorization_boot_id: id,
  })
  .strict();
const handoffClaim = z
  .object({
    handoff_id: id,
    role: z.literal('case_officer'),
    world_id: worldId,
    case_id: id,
    target_origin: browserOrigin,
    authorization_boot_id: id,
    consumed_at: timestamp,
  })
  .strict();
export type HandoffRedeemInput = z.infer<typeof handoffRedeemInput>;
export type HandoffClaim = z.infer<typeof handoffClaim>;

const onBehalfOfClaim = z
  .object({ role: z.literal('case_officer'), session_id: id })
  .strict();
export type OnBehalfOfClaim = z.infer<typeof onBehalfOfClaim>;

async function responseJson(response: Response, maxBytes: number): Promise<unknown> {
  const declared = response.headers.get('content-length');
  if (declared !== null && Number(declared) > maxBytes) throw new Error('runtime response exceeded limit');
  const buffer = Buffer.from(await response.arrayBuffer());
  if (buffer.length > maxBytes) throw new Error('runtime response exceeded limit');
  try {
    return JSON.parse(buffer.toString('utf8')) as unknown;
  } catch {
    throw new Error('runtime response was not JSON');
  }
}

export class RuntimeDependencyError extends Error {
  constructor(
    readonly httpStatus: number,
    readonly responseCode: string | null,
  ) {
    super(`runtime dependency rejected transport request with HTTP ${httpStatus}`);
    this.name = 'RuntimeDependencyError';
  }
}

function responseErrorCode(value: unknown): string | null {
  if (typeof value !== 'object' || value === null || !Object.hasOwn(value, 'error')) return null;
  const code = (value as { readonly error?: unknown }).error;
  return typeof code === 'string' ? code : null;
}

function containsTokenField(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsTokenField);
  if (typeof value !== 'object' || value === null) return false;
  return Object.entries(value).some(([key, nested]) => key.toLowerCase().includes('token') || containsTokenField(nested));
}

interface ClientOptions {
  readonly origin: string;
  readonly token: string;
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
  readonly fetchImplementation?: typeof fetch;
}

abstract class JsonHttpClient {
  readonly #origin: string;
  readonly #token: string;
  readonly #timeoutMs: number;
  readonly #maxResponseBytes: number;
  readonly #fetch: typeof fetch;

  constructor(options: ClientOptions) {
    this.#origin = new URL(options.origin).origin;
    this.#token = options.token;
    this.#timeoutMs = options.timeoutMs ?? 5_000;
    this.#maxResponseBytes = options.maxResponseBytes ?? 1024 * 1024;
    this.#fetch = options.fetchImplementation ?? fetch;
  }

  protected async post(path: string, body: unknown, onBehalfOf?: OnBehalfOfClaim): Promise<unknown> {
    let response: Response;
    const claim = onBehalfOf === undefined ? undefined : onBehalfOfClaim.parse(onBehalfOf);
    try {
      response = await this.#fetch(new URL(path, this.#origin), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.#token}`,
          'content-type': 'application/json',
          ...(claim === undefined
            ? {}
            : { 'x-on-behalf-of-role': claim.role, 'x-session-id': claim.session_id }),
        },
        body: JSON.stringify(body),
        redirect: 'error',
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch {
      throw new Error('runtime dependency unavailable');
    }
    const parsed = await responseJson(response, this.#maxResponseBytes);
    if (!response.ok) throw new RuntimeDependencyError(response.status, responseErrorCode(parsed));
    return parsed;
  }

  protected async get(path: string): Promise<unknown> {
    let response: Response;
    try {
      response = await this.#fetch(new URL(path, this.#origin), {
        headers: { authorization: `Bearer ${this.#token}` },
        redirect: 'error',
        signal: AbortSignal.timeout(this.#timeoutMs),
      });
    } catch {
      throw new Error('runtime dependency unavailable');
    }
    const parsed = await responseJson(response, this.#maxResponseBytes);
    if (!response.ok) throw new RuntimeDependencyError(response.status, responseErrorCode(parsed));
    return parsed;
  }
}

export class OrchestratorAuthorizationHttpClient extends JsonHttpClient {
  async currentModelSelection(worldIdInput: string, caseIdInput: string): Promise<CurrentModelSelectionProjection> {
    const world = worldId.parse(worldIdInput);
    const caseId = id.parse(caseIdInput);
    return currentModelSelectionProjection.parse(
      await this.get(`/w/${world}/cases/${caseId}/model-selection`),
    );
  }

  async checkModelSelection(
    worldIdInput: string,
    caseIdInput: string,
    input: ModelSelectionCheckRequest,
    onBehalfOf?: OnBehalfOfClaim,
  ): Promise<ModelSelectionCheckProjection> {
    const world = worldId.parse(worldIdInput);
    const caseId = id.parse(caseIdInput);
    const request = modelSelectionCheckRequest.parse(input);
    return modelSelectionCheckProjection.parse(
      await this.post(`/w/${world}/cases/${caseId}/model-selection-checks`, request, onBehalfOf),
    );
  }

  async selectModel(
    worldIdInput: string,
    caseIdInput: string,
    input: ModelSelectionRequest,
    onBehalfOf?: OnBehalfOfClaim,
  ): Promise<ModelSelectionProjection> {
    const world = worldId.parse(worldIdInput);
    const caseId = id.parse(caseIdInput);
    const request = modelSelectionRequest.parse(input);
    return modelSelectionProjection.parse(
      await this.post(`/w/${world}/cases/${caseId}/model-selections`, request, onBehalfOf),
    );
  }

  async beginModelCall(input: {
    readonly worldId: string;
    readonly turnId: string;
    readonly selectionId: string;
  }, onBehalfOf?: OnBehalfOfClaim): Promise<ModelCallStart> {
    const world = worldId.parse(input.worldId);
    const request = modelCallBeginRequest.parse({
      turn_id: input.turnId,
      selection_id: id.parse(input.selectionId),
    });
    return modelCallStart.parse(await this.post(`/w/${world}/model-calls/begin`, request, onBehalfOf));
  }

  async admitModelOutput(
    worldIdInput: string,
    callIdInput: string,
    input: ModelOutputAdmissionRequest,
    onBehalfOf?: OnBehalfOfClaim,
  ): Promise<ModelCallAdmission> {
    const world = worldId.parse(worldIdInput);
    const request = modelCallAdmissionRequest.parse({ call_id: id.parse(callIdInput), output: input });
    return modelCallAdmission.parse(await this.post(`/w/${world}/model-outputs/admit`, request, onBehalfOf));
  }

  async failModelCall(
    worldIdInput: string,
    input: ModelCallFailureRequest,
    onBehalfOf?: OnBehalfOfClaim,
  ): Promise<ModelCallFailedRecord> {
    const world = worldId.parse(worldIdInput);
    const request = modelCallFailureRequest.parse(input);
    return modelCallFailedRecord.parse(
      await this.post(`/w/${world}/model-calls/failures`, request, onBehalfOf),
    );
  }

  async ruleCommit(input: {
    readonly proposal: FrozenProposal;
    readonly service: string;
    readonly actionClass: string;
  }): Promise<ProposalRulingProjection> {
    const proposal = frozenProposal.parse(input.proposal);
    const service = id.parse(input.service);
    const actionClass = classToken.parse(input.actionClass);
    return proposalRulingProjection.parse(
      await this.post(`/w/${proposal.world_id}/proposals`, {
        gate: 'commit',
        proposal,
        service,
        action_class: actionClass,
      }),
    );
  }

  async redeemCaseSessionHandoff(input: HandoffRedeemInput): Promise<HandoffClaim> {
    const parsed = handoffRedeemInput.parse(input);
    return handoffClaim.parse(
      await this.post(
        `/w/${parsed.world_id}/case-session-handoffs/${parsed.handoff_id}/redeem`,
        parsed,
      ),
    );
  }

  async approvedModels(worldIdInput: string, mandateIdInput: string): Promise<ApprovedModelsProjection> {
    const world = worldId.parse(worldIdInput);
    const mandateId = id.parse(mandateIdInput);
    return approvedModelsProjection.parse(
      await this.get(`/w/${world}/mandates/${mandateId}/approved-models`),
    );
  }

  async rulingStatus(worldIdInput: string, rulingIdInput: string): Promise<RulingProjection> {
    const world = worldId.parse(worldIdInput);
    const rulingId = id.parse(rulingIdInput);
    return rulingProjection.parse(await this.get(`/w/${world}/rulings/${rulingId}`));
  }
}

export class OrchestratorServicesHttpClient extends JsonHttpClient {
  async execute(rulingIdInput: string, intentInput: EffectIntent): Promise<ServicesHostExecution> {
    const rulingId = id.parse(rulingIdInput);
    const intent = effectIntent.parse(intentInput);
    const result = await this.post(`/w/${intent.world_id}/services/${intent.service}/execute`, {
      ruling_id: rulingId,
      intent,
    });
    if (containsTokenField(result)) throw new Error('services response exposed a token field');
    return z.object({ ok: z.boolean() }).passthrough().parse(result) as ServicesHostExecution;
  }
}
