// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from 'vitest';

import { CaseConversationStore, toBrowserConversation } from './caseConversation.js';
import type { CaseSessionRecord } from './caseSessionStore.js';
import { ModelOutputQuarantine, type ModelTurnOutcome } from './modelTurnCoordinator.js';

const DIGEST = 'a'.repeat(64);
const TARGET = {
  card_id: 'publicai-apertus-v1.5-70b',
  card_version: 1,
  requested_id: 'swiss-ai/apertus-v1.5-70b',
};

function session(overrides: Partial<CaseSessionRecord> = {}): CaseSessionRecord {
  return {
    session_id: 'session_message',
    token_digest: DIGEST,
    handoff_id: 'handoff_message',
    role: 'case_officer',
    world_id: 'w-demo',
    case_id: 'case_demo',
    target_origin: 'http://127.0.0.1:7802',
    authorization_boot_id: 'authz_boot_message',
    created_at: '2026-08-07T09:00:00.000Z',
    expires_at: '2026-08-07T09:15:00.000Z',
    state: 'active',
    ...overrides,
  };
}

function current(selectionId = 'sel_message') {
  return {
    state: 'selected' as const,
    authorization_boot_id: 'authz_boot_message',
    case_id: 'case_demo',
    selection: {
      world_id: 'w-demo',
      selection_id: selectionId,
      case_id: 'case_demo',
      kind: 'initial' as const,
      predecessor_selection_id: null,
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      target: { ...TARGET, card_digest: DIGEST, verifying_key_id: 'card_test' },
      system_use_decision: {
        decision_id: 'sud_message',
        version: 1,
        record_digest: DIGEST,
        status: 'approved' as const,
        conditions: [],
      },
      check_id: 'msc_message',
      selected_at: '2026-08-07T09:00:00.000Z',
      authority_effect: 'none' as const,
    },
    latest_observation: null,
  };
}

function released(turnId: string): ModelTurnOutcome {
  return {
    disposition: 'released',
    admission: {
      kind: 'model_output_control',
      disposition: 'admitted',
      authority_effect: 'none',
      case_id: 'case_demo',
      turn_id: turnId,
      selection_id: 'sel_message',
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      card_id: TARGET.card_id,
      card_version: TARGET.card_version,
      requested_id: TARGET.requested_id,
      served_id: TARGET.requested_id,
      model_resolution: 'exact',
      projection_digest: DIGEST,
      projection_item_count: 1,
      output_digest: DIGEST,
      flags: [],
      derived_tags: [],
      reasons: [],
    },
    ingestion: {
      kind: 'output_release_consumption_result',
      release_id: 'rel_message',
      state: 'consumed',
      event_id: 'event_output',
      item_id: 'item_output',
      conversation_version: 3,
      recorded_at: '2026-08-07T09:00:01.000Z',
    },
  };
}

function store(now = () => '2026-08-07T09:00:00.000Z') {
  let sequence = 0;
  return new CaseConversationStore({
    now,
    nextPreparationId: () => `msgp_${++sequence}`,
    nextMessageId: () => `msg_${sequence}`,
    nextTurnId: () => `turn_${sequence}`,
  });
}

describe('M5.10 browser conversation custody', () => {
  it('enforces the exact Unicode, control, whitespace, and UTF-8 byte boundary before custody', () => {
    const conversations = store();
    for (const invalid of ['', '   ', 'control\u0000', '\ud800', 'a'.repeat(8_193)]) {
      expect(() => conversations.create(invalid, session(), current())).toThrowError('message-preparation-invalid');
    }
    expect(conversations.create('😀'.repeat(2_048), session(), current())).toMatchObject({
      preparation_id: 'msgp_1',
      message_id: 'msg_1',
      turn_id: 'turn_1',
    });
  });

  it('burns replaced and consumed bytes, and a preparation can be used only once', async () => {
    const conversations = store();
    const fill = vi.spyOn(Buffer.prototype, 'fill');
    const first = conversations.create('synthetic first secret', session(), current());
    const second = conversations.create('synthetic second secret', session(), current());
    const quarantine = new ModelOutputQuarantine();
    await expect(
      conversations.use(first.preparation_id, session(), async () => released(first.turn_id), quarantine),
    ).resolves.toBeNull();
    const observed: string[] = [];
    await expect(
      conversations.use(
        second.preparation_id,
        session(),
        async (input) => {
          observed.push(input.text);
          return released(input.turnId);
        },
        quarantine,
      ),
    ).resolves.toMatchObject({ state: 'released', provider_disclosure: 'confirmed', quarantine: null });
    expect(observed).toEqual(['synthetic second secret']);
    await expect(
      conversations.use(second.preparation_id, session(), async () => released(second.turn_id), quarantine),
    ).resolves.toBeNull();
    expect(fill.mock.contexts.filter((value): value is Buffer => Buffer.isBuffer(value))).not.toHaveLength(0);
    expect(
      fill.mock.contexts
        .filter((value): value is Buffer => Buffer.isBuffer(value))
        .every((value) => value.every((byte) => byte === 0)),
    ).toBe(true);
    fill.mockRestore();
  });

  it('burns elapsed or selection-stale preparations without retaining browser status', () => {
    let at = '2026-08-07T09:00:00.000Z';
    const conversations = store(() => at);
    const elapsed = conversations.create('synthetic elapsed', session(), current());
    at = elapsed.expires_at;
    conversations.expire();
    expect(conversations.status(elapsed.turn_id, session())).toBeNull();

    at = '2026-08-07T09:00:00.000Z';
    const stale = conversations.create('synthetic stale selection', session(), current());
    conversations.burnStaleForCase('w-demo', 'case_demo', 'sel_replacement');
    expect(conversations.status(stale.turn_id, session())).toBeNull();
  });

  it('marks use consuming before awaiting the dependency so a concurrent replay cannot enter', async () => {
    const conversations = store();
    const prepared = conversations.create('Synthetic concurrent message.', session(), current());
    const quarantine = new ModelOutputQuarantine();
    let finish: ((outcome: ModelTurnOutcome) => void) | undefined;
    const pending = conversations.use(
      prepared.preparation_id,
      session(),
      () => new Promise<ModelTurnOutcome>((resolve) => {
        finish = resolve;
      }),
      quarantine,
    );
    await expect(
      conversations.use(prepared.preparation_id, session(), async () => released(prepared.turn_id), quarantine),
    ).resolves.toBeNull();
    if (finish === undefined) throw new Error('synthetic operation did not start');
    finish(released(prepared.turn_id));
    await expect(pending).resolves.toMatchObject({ state: 'released' });
  });

  it('rejects a terminal coordinator result that does not match the prepared turn binding', async () => {
    const conversations = store();
    const prepared = conversations.create('Synthetic binding mismatch.', session(), current());
    const quarantine = new ModelOutputQuarantine();
    const destroy = vi.spyOn(quarantine, 'destroy');
    await expect(
      conversations.use(
        prepared.preparation_id,
        session(),
        async () => {
          const outcome = released(prepared.turn_id);
          if (outcome.disposition !== 'released') throw new Error('expected synthetic released outcome');
          return {
            ...outcome,
            admission: { ...outcome.admission, turn_id: 'turn_other' },
          };
        },
        quarantine,
      ),
    ).resolves.toMatchObject({
      state: 'failed',
      provider_disclosure: 'confirmed',
      terminal_reason: 'admission-binding-invalid',
    });
    expect(destroy).toHaveBeenCalledWith(prepared.turn_id);
  });

  it('constructs both browser event variants field-by-field with exact keys', () => {
    const projected = toBrowserConversation({
      case_id: 'case_demo',
      conversation_version: 3,
      events: [
        {
          speaker: 'case_officer',
          message_id: 'msg_1',
          turn_id: 'turn_1',
          text: 'Synthetic question',
          recorded_at: '2026-08-07T09:00:00.000Z',
        },
        {
          speaker: 'model',
          message_id: 'msg_1',
          turn_id: 'turn_1',
          text: 'Synthetic inference',
          recorded_at: '2026-08-07T09:00:01.000Z',
          requested_id: TARGET.requested_id,
          served_id: TARGET.requested_id,
          classification: 'inferred-unconfirmed',
        },
      ],
    });
    expect(Object.keys(projected.events[0] ?? {}).sort()).toEqual([
      'message_id',
      'recorded_at',
      'speaker',
      'text',
      'turn_id',
    ]);
    expect(Object.keys(projected.events[1] ?? {}).sort()).toEqual([
      'classification',
      'message_id',
      'recorded_at',
      'requested_id',
      'served_id',
      'speaker',
      'text',
      'turn_id',
    ]);
  });
});
