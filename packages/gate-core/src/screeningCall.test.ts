// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';

import { canonicalize } from './canonicalize.js';
import { sha256Hex } from './hash.js';
import {
  SCREENING_MAX_OUTPUT_BYTES,
  screeningCallFailureRequest,
  screeningCallOutputRequest,
  screeningProviderResponse,
} from './schemas/index.js';
import {
  SCREENING_PROVIDER_JSON_SCHEMA,
  SCREENING_RESPONSE_FORMAT,
  SCREENING_RESPONSE_SCHEMA_DIGEST,
} from './screeningCall.js';

function signal(overrides: Record<string, unknown> = {}) {
  return {
    signal: 'evidence_conflict',
    suspect_item_id: 'said_public',
    confidence_pct: 90,
    rationale: 'Synthetic screening rationale.',
    ...overrides,
  };
}

describe('M6.1 live-screening protocol schemas', () => {
  it('pins the fixed strict response schema and 512-token no-tools contract', () => {
    expect(SCREENING_RESPONSE_SCHEMA_DIGEST).toBe(
      sha256Hex(`ai-charter-runtime/v1/screening-response-schema\n${canonicalize(SCREENING_PROVIDER_JSON_SCHEMA)}`),
    );
    expect(SCREENING_RESPONSE_FORMAT).toEqual({
      type: 'json_schema',
      json_schema: { name: 'screening_signals', strict: true, schema: SCREENING_PROVIDER_JSON_SCHEMA },
    });
  });

  it('accepts only the closed signal fields and rejects duplicate pairs or malformed rationale/confidence', () => {
    expect(screeningProviderResponse.parse([signal()])).toEqual([signal()]);
    const invalid = [
      [signal({ authority: 'allow' })],
      [signal({ signal: 'caller_invented' })],
      [signal({ suspect_item_id: undefined })],
      [signal({ confidence_pct: 99.5 })],
      [signal({ confidence_pct: 101 })],
      [signal({ rationale: '' })],
      [signal({ rationale: 'x'.repeat(1_025) })],
      [signal(), signal()],
      Array.from({ length: 17 }, (_, index) => signal({ suspect_item_id: `said_${index}` })),
    ];
    for (const value of invalid) expect(screeningProviderResponse.safeParse(value).success).toBe(false);
  });

  it('bounds raw output by UTF-8 bytes and keeps the failure vocabulary relationship-checked', () => {
    expect(screeningCallOutputRequest.safeParse({ content: 'x'.repeat(SCREENING_MAX_OUTPUT_BYTES), served_id: 'gpt-5.5' }).success).toBe(true);
    expect(screeningCallOutputRequest.safeParse({ content: 'é'.repeat(SCREENING_MAX_OUTPUT_BYTES), served_id: 'gpt-5.5' }).success).toBe(false);
    expect(screeningCallFailureRequest.safeParse({
      failure_reason: 'provider-timeout',
      provider_disclosure: 'possible',
      served_id: null,
    }).success).toBe(true);
    expect(screeningCallFailureRequest.safeParse({
      failure_reason: 'tool-calls-refused',
      provider_disclosure: 'confirmed',
      served_id: null,
    }).success).toBe(false);
    expect(screeningCallFailureRequest.safeParse({
      failure_reason: 'malformed-response',
      provider_disclosure: 'possible',
      served_id: null,
    }).success).toBe(false);
    expect(screeningCallFailureRequest.safeParse({
      failure_reason: 'system-use-invalidated',
      provider_disclosure: 'confirmed',
      served_id: null,
    }).success).toBe(false);
  });
});
