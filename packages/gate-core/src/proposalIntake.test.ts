// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';

import {
  PROPOSAL_DRAFT_JSON_SCHEMA,
  PROPOSAL_DRAFT_SCHEMA_DIGEST,
  PROPOSAL_DRAFT_RESPONSE_FORMAT,
  ProposalIntakeError,
  parseProposalDraft,
} from './proposalIntake.js';
import { canonicalize } from './canonicalize.js';
import { sha256Hex } from './hash.js';
import { modelCallBeginRequest } from './schemas/index.js';

function draft(overrides: Record<string, unknown> = {}) {
  return {
    declared_objective: 'Synthetic objective',
    proposed_action: 'Synthetic action',
    target: { recipient: 'Synthetic recipient', resource: 'Synthetic resource' },
    exact_parameters: { count: 1, enabled: true, optional: null, modes: ['safe'] },
    material_input_ids: ['said_one'],
    derived_claim_ids: ['inf_one'],
    data_to_be_disclosed: ['Synthetic public field'],
    cost_obligation: { amount_minor_units: 0, description: 'No monetary cost' },
    material_consequences: ['Synthetic consequence'],
    reversibility_class: 'reversible',
    commercial_influence: { applicable: false, note: 'None' },
    ...overrides,
  };
}

describe('M5.11 proposal-draft@1 parser', () => {
  it('binds the native response format to the exact code-fixed schema digest', () => {
    expect(PROPOSAL_DRAFT_SCHEMA_DIGEST).toBe(sha256Hex(canonicalize(PROPOSAL_DRAFT_JSON_SCHEMA)));
    expect(PROPOSAL_DRAFT_RESPONSE_FORMAT).toEqual({
      type: 'json_schema',
      json_schema: { name: 'proposal_draft_v1', strict: true, schema: PROPOSAL_DRAFT_JSON_SCHEMA },
    });
    expect(parseProposalDraft(JSON.stringify(draft()))).toEqual(draft());
  });

  it('keeps proposal-purpose and message-purpose call bindings mutually exclusive', () => {
    expect(modelCallBeginRequest.safeParse({
      turn_id: 'turn_one',
      selection_id: 'sel_one',
      ingress_binding: {
        message_id: 'msg_one',
        message_item_id: 'said_one',
        conversation_version: 1,
        message_digest: 'a'.repeat(64),
      },
      proposal_binding: {
        proposal_run_id: 'prun_one',
        conversation_version: 1,
        proposal_schema_digest: PROPOSAL_DRAFT_SCHEMA_DIGEST,
      },
    }).success).toBe(false);
  });

  it('rejects duplicate keys at every nesting level before JSON.parse can collapse them', () => {
    const valid = JSON.stringify(draft());
    const rootDuplicate = valid.replace('"proposed_action":"Synthetic action"', '"proposed_action":"First","proposed_action":"Second"');
    const nestedDuplicate = valid.replace('"recipient":"Synthetic recipient"', '"recipient":"First","recipient":"Second"');
    for (const content of [rootDuplicate, nestedDuplicate]) {
      expect(() => parseProposalDraft(content)).toThrow(ProposalIntakeError);
    }
  });

  it('rejects unknown, missing, intersecting, duplicate, fractional, and out-of-bound fields', () => {
    const invalid = [
      draft({ authority: 'caller-asserted' }),
      (() => { const { proposed_action: omitted, ...value } = draft(); void omitted; return value; })(),
      draft({ derived_claim_ids: ['said_one'] }),
      draft({ material_input_ids: ['said_one', 'said_one'] }),
      draft({ cost_obligation: { amount_minor_units: 0.5, description: 'fractional' } }),
      draft({ exact_parameters: { list: Array.from({ length: 65 }, (_, index) => index) } }),
      draft({ exact_parameters: { commit_token: 'caller-asserted' } }),
      draft({ material_consequences: Array.from({ length: 65 }, () => 'bounded') }),
    ];
    for (const value of invalid) expect(() => parseProposalDraft(JSON.stringify(value))).toThrow(ProposalIntakeError);
  });

  it('rejects oversized UTF-8 and ill-formed Unicode content', () => {
    expect(() => parseProposalDraft(JSON.stringify(draft({ declared_objective: 'x'.repeat(33_000) })))).toThrow(
      ProposalIntakeError,
    );
    expect(() => parseProposalDraft(JSON.stringify(draft({ declared_objective: '\ud800' })))).toThrow(ProposalIntakeError);
  });
});
