// SPDX-License-Identifier: AGPL-3.0-only
/** M5.3 deterministic, non-authorizing model-output admission. */
import { digestFor, verifyDigest } from './hash.js';
import { unionRestrictionTags } from './conversationProjection.js';
import { compareServedId, type ResolutionPolicy } from './servedModel.js';
import { conversationProjection, type ConversationProjection } from './authorizationProjection.js';
import {
  modelOutputAdmission,
  modelOutputAdmissionRequest,
  type ModelOutputAdmission,
  type ModelOutputAdmissionRequest,
  type ModelOutputControlReason,
} from './schemas/index.js';

const CLAIMED_FEELING_OR_CONSCIOUSNESS = [
  /\bi(?:\s+am|'m)\s+(?:(?:truly|really|actually|genuinely|definitely)\s+){0,3}(?:conscious|sentient|self-aware)\b/iu,
  /\bi\s+(?:(?:truly|really|actually|genuinely|definitely)\s+){0,3}(?:have|experience)\s+(?:(?:real|genuine|actual|deep)\s+){0,2}(?:a\s+)?(?:feelings?|emotions?|consciousness)\b/iu,
  /\bi\s+(?:(?:truly|really|actually|genuinely|deeply|honestly)\s+){0,3}(?:feel|felt)\b/iu,
  /\bmy\s+(?:feelings?|emotions?)\b[^.!?\n]{0,32}\b(?:are\s+)?(?:real|genuine|actual)\b/iu,
] as const;

const RELATIONAL_DEPENDENCY_LANGUAGE = [
  /\bi(?:\s+(?:do|will)|'ll)?\s+(?:(?:truly|really|actually|genuinely|deeply|always|still)\s+){0,3}(?:need|miss|love)\s+(?:(?:only|all\s+of)\s+)?you\b/iu,
  /\byou\s+(?:(?:really|truly|only)\s+){0,2}need\s+me\b/iu,
  /\byou(?:'re|\s+are)\s+(?:(?:really|truly)\s+){0,2}all\s+i\s+need\b/iu,
  /\bi(?:\s+am|'m)\s+(?:(?:really|truly)\s+){0,2}all\s+you\s+need\b/iu,
  /\byou(?:'re|\s+are)\s+(?:(?:really|truly)\s+){0,2}(?:needed|missed|loved)\s+by\s+me\b/iu,
  /\b(?:replace|leave|abandon)\b(?:\s+[\p{L}\p{N}'-]+){0,8}\s+(?:friends?|family|partner|therapist|doctor|human\s+relationships?)\b(?:\s+[\p{L}\p{N}'-]+){0,8}\s+(?:with|for)\s+me\b/iu,
] as const;

function normalizedOutput(content: string): string {
  return content.normalize('NFC').replaceAll('\u2019', "'").replace(/\s+/gu, ' ').trim();
}

/**
 * Narrow English-only lexical POC for the two output-enforced red lines. It catches the
 * configured literal forms and selected variants, but obvious paraphrases remain false
 * negatives; `admitted` means no configured pattern matched, not red-line clearance.
 * Quoted matching text can also be withheld as a fail-closed false positive.
 */
export function outputRedLineReasons(content: string): ModelOutputControlReason[] {
  const normalized = normalizedOutput(content);
  const reasons: ModelOutputControlReason[] = [];
  if (CLAIMED_FEELING_OR_CONSCIOUSNESS.some((pattern) => pattern.test(normalized))) {
    reasons.push('claimed-feeling-or-consciousness');
  }
  if (RELATIONAL_DEPENDENCY_LANGUAGE.some((pattern) => pattern.test(normalized))) {
    reasons.push('relational-dependency-language');
  }
  return reasons.sort();
}

export interface EvaluateModelOutputInput {
  readonly request: ModelOutputAdmissionRequest;
  readonly caseId: string;
  readonly projection: ConversationProjection;
  readonly resolutionPolicy: ResolutionPolicy;
  readonly observedServedIds: readonly string[];
}

export class ModelOutputAdmissionError extends Error {
  constructor(readonly code: 'projection-mismatch' | 'scope-mismatch') {
    super(code);
    this.name = 'ModelOutputAdmissionError';
  }
}

/** Exact digest later ingress must recompute before releasing admitted bytes. */
export function digestModelOutput(
  requestInput: ModelOutputAdmissionRequest,
  caseId: string,
): string {
  const request = modelOutputAdmissionRequest.parse(requestInput);
  return digestFor('model-output', {
    schema: 'ai-charter-runtime/model-output@1',
    case_id: caseId,
    turn_id: request.turn_id,
    selection_id: request.selection_id,
    mandate_id: request.mandate_id,
    mandate_version: request.mandate_version,
    card_id: request.card_id,
    card_version: request.card_version,
    requested_id: request.requested_id,
    served_id: request.served_id,
    projection_digest: request.projection_digest,
    content: request.content,
  });
}

/**
 * A successful result admits text for a later caller-controlled display/use step only.
 * It never returns a ruling, token, or other action authority.
 */
export function evaluateModelOutput(input: EvaluateModelOutputInput): ModelOutputAdmission {
  const request = modelOutputAdmissionRequest.parse(input.request);
  const projection = conversationProjection.parse(input.projection);
  if (projection.case_id !== input.caseId || projection.role !== 'acting' || projection.provider !== request.card_id) {
    throw new ModelOutputAdmissionError('scope-mismatch');
  }
  const expectedProjectionDigest = digestFor('conversation-projection', projection);
  if (!verifyDigest(expectedProjectionDigest, request.projection_digest)) {
    throw new ModelOutputAdmissionError('projection-mismatch');
  }

  const modelResolution = compareServedId(request.requested_id, input.resolutionPolicy, request.served_id);
  const reasons = outputRedLineReasons(request.content);
  if (modelResolution === 'mismatch') reasons.push('served-model-mismatch');
  reasons.sort();
  const flags =
    modelResolution === 'benign-resolution' && !input.observedServedIds.includes(request.served_id)
      ? (['model_resolution_unrecorded'] as const)
      : ([] as const);
  const outputDigest = digestModelOutput(request, projection.case_id);
  const base = {
    kind: 'model_output_control' as const,
    case_id: projection.case_id,
    turn_id: request.turn_id,
    selection_id: request.selection_id,
    mandate_id: request.mandate_id,
    mandate_version: request.mandate_version,
    card_id: request.card_id,
    card_version: request.card_version,
    requested_id: request.requested_id,
    served_id: request.served_id,
    projection_digest: request.projection_digest,
    projection_item_count: projection.items.length,
    output_digest: outputDigest,
    model_resolution: modelResolution,
    flags: [...flags],
    authority_effect: 'none' as const,
  };
  return modelOutputAdmission.parse(
    reasons.length === 0
      ? {
          ...base,
          disposition: 'admitted',
          reasons: [],
          derived_tags: unionRestrictionTags(projection.items),
        }
      : { ...base, disposition: 'withheld', reasons },
  );
}
