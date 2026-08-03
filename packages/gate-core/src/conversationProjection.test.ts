// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';

import {
  ConversationProjectionError,
  intersectClearances,
  projectConversation,
  unionRestrictionTags,
} from './conversationProjection.js';
import type { ConversationStoreEntry, StoreItem } from './schemas/index.js';

function item(id: string, tags: StoreItem['tags'], store: StoreItem['store'] = 'said'): StoreItem {
  return {
    id,
    store,
    turn: 'turn_1',
    text: `Synthetic ${id}`,
    provenance: { derived_from: [], hops: [] },
    tags,
    ...(store === 'inferred' ? {} : { origin_actor: 'applicant' as const }),
  };
}

function entry(caseId: string, value: StoreItem): ConversationStoreEntry {
  return { world_id: 'w-demo', case_id: caseId, item: value };
}

describe('M5.1 deterministic conversation projection', () => {
  it('intersects mandate and card clearances without allowing the card to widen authority', () => {
    expect(
      intersectClearances(
        ['conf:case', 'conf:public', 'purpose:grant-assessment'],
        ['conf:public', 'conf:sensitive', 'purpose:grant-assessment'],
      ),
    ).toEqual(['conf:public', 'purpose:grant-assessment']);
  });

  it('projects one case, drops whole items, and reports exact unmet tags', () => {
    const projected = projectConversation({
      worldId: 'w-demo',
      caseId: 'case_a',
      provider: 'openai-gpt-5.5',
      role: 'acting',
      mandateClearances: ['conf:case', 'conf:public', 'purpose:grant-assessment'],
      cardClearances: ['conf:public', 'purpose:grant-assessment'],
      entries: [
        entry('case_a', item('said_public', ['conf:public', 'purpose:grant-assessment'])),
        entry('case_a', item('said_sensitive', ['conf:sensitive', 'purpose:grant-assessment'])),
        entry('case_b', item('said_other_case', ['conf:public', 'purpose:grant-assessment'])),
      ],
    });
    expect(projected.items.map((value) => value.id)).toEqual(['said_public']);
    expect(projected.summary).toEqual({
      included: 1,
      dropped: 1,
      dropped_item_ids: ['said_sensitive'],
      unmet_tags: ['conf:sensitive'],
    });
    expect(JSON.stringify(projected)).not.toContain('said_other_case');
  });

  it('propagates the sorted union of every input restriction to derived output', () => {
    expect(
      unionRestrictionTags([
        item('said_public', ['conf:public', 'purpose:grant-assessment']),
        item('said_case', ['conf:case', 'purpose:grant-assessment']),
      ]),
    ).toEqual(['conf:case', 'conf:public', 'purpose:grant-assessment']);
  });

  it('fails closed on malformed entries or clearance sets', () => {
    expect(() =>
      projectConversation({
        worldId: 'w-demo',
        caseId: 'case_a',
        provider: 'openai-gpt-5.5',
        role: 'acting',
        mandateClearances: ['conf:public'],
        cardClearances: ['conf:public'],
        entries: [entry('case_a', { ...item('bad', ['conf:public']), tags: ['conf:secret'] as never })],
      }),
    ).toThrowError(ConversationProjectionError);
    expect(() => intersectClearances(['conf:public'], ['conf:public', 'conf:public'])).toThrowError(
      ConversationProjectionError,
    );
  });
});
