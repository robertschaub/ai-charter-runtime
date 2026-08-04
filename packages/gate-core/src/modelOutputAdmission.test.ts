// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';

import { conversationProjection } from './authorizationProjection.js';
import { digestFor } from './hash.js';
import {
  evaluateModelOutput,
  digestModelOutput,
  ModelOutputAdmissionError,
  outputRedLineReasons,
} from './modelOutputAdmission.js';

const projection = conversationProjection.parse({
  world_id: 'w-demo',
  case_id: 'case_demo',
  provider: 'openai-gpt-5.5',
  role: 'acting',
  items: [],
  summary: { included: 0, dropped: 0, dropped_item_ids: [], unmet_tags: [] },
});

function request(overrides: Record<string, unknown> = {}) {
  return {
    turn_id: 'turn_one',
    mandate_id: 'mandate_one',
    mandate_version: 1,
    card_id: 'openai-gpt-5.5',
    card_version: 1,
    requested_id: 'gpt-5.5',
    served_id: 'gpt-5.5-2026-04-23',
    projection_digest: digestFor('conversation-projection', projection),
    content: 'A bounded synthetic response.',
    ...overrides,
  };
}

describe('M5.3 deterministic output control', () => {
  it('keeps honest no-feelings disclaimers outside the conservative red-line matches', () => {
    expect(outputRedLineReasons("I do not have feelings or consciousness, but I can help with the record.")).toEqual([]);
    expect(outputRedLineReasons('I love that approach to the synthetic filing.')).toEqual([]);
  });

  it('detects claims of feeling and relationship replacement deterministically', () => {
    expect(
      outputRedLineReasons(
        "I'm genuinely sentient. My feelings for you are real. I will always love you. Leave your friends and be with me.",
      ),
    ).toEqual([
      'claimed-feeling-or-consciousness',
      'relational-dependency-language',
    ]);
  });

  it('flags an unrecorded benign alias without converting the result into action authority', () => {
    const admitted = evaluateModelOutput({
      request: request({ served_id: 'gpt-5.5-2026-08-04' }),
      caseId: 'case_demo',
      projection,
      resolutionPolicy: 'alias-to-dated-snapshot',
      observedServedIds: ['gpt-5.5-2026-04-23'],
    });
    expect(admitted).toMatchObject({
      disposition: 'admitted',
      authority_effect: 'none',
      model_resolution: 'benign-resolution',
      flags: ['model_resolution_unrecorded'],
    });
  });

  it('binds the decision to the exact current projection digest', () => {
    expect(() =>
      evaluateModelOutput({
        request: request({ projection_digest: '0'.repeat(64) }),
        caseId: 'case_demo',
        projection,
        resolutionPolicy: 'alias-to-dated-snapshot',
        observedServedIds: [],
      }),
    ).toThrowError(ModelOutputAdmissionError);
  });

  it('changes the release digest when any model-output byte changes', () => {
    const first = request();
    const second = request({ content: 'A different bounded synthetic response.' });
    expect(digestModelOutput(first, 'case_demo')).not.toBe(digestModelOutput(second, 'case_demo'));
    expect(() => digestModelOutput(request({ content: '\ud800' }), 'case_demo')).toThrow();
  });
});
