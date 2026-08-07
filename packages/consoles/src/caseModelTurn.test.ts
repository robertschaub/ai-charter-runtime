// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from 'vitest';

import { CaseModelTurnStore } from './caseModelTurn.js';
import type { CaseSessionRecord } from './caseSessionStore.js';
import { ModelOutputQuarantine, ModelTurnError } from './modelTurnCoordinator.js';

const TARGET = {
  card_id: 'publicai-apertus-v1.5-70b',
  card_version: 1,
  requested_id: 'swiss-ai/apertus-v1.5-70b',
};
const DIGEST = 'a'.repeat(64);

function session(overrides: Partial<CaseSessionRecord> = {}): CaseSessionRecord {
  return {
    session_id: 'session_turn',
    token_digest: DIGEST,
    handoff_id: 'handoff_turn',
    role: 'case_officer',
    world_id: 'w-demo',
    case_id: 'case_demo',
    target_origin: 'http://127.0.0.1:7802',
    authorization_boot_id: 'authz_boot_turn',
    created_at: '2026-08-07T09:00:00.000Z',
    expires_at: '2026-08-07T09:15:00.000Z',
    state: 'active',
    ...overrides,
  };
}

function current(selectionId = 'sel_turn') {
  return {
    state: 'selected' as const,
    authorization_boot_id: 'authz_boot_turn',
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
        decision_id: 'sud_turn',
        version: 1,
        record_digest: DIGEST,
        status: 'approved' as const,
        conditions: [],
      },
      check_id: 'msc_turn',
      selected_at: '2026-08-07T09:00:00.000Z',
      authority_effect: 'none' as const,
    },
    latest_observation: null,
  };
}

describe('M5.9 browser model-turn custody', () => {
  it('issues one boot/session/selection-bound preparation and consumes it once', () => {
    const ids = ['mtp_first', 'mtp_second'];
    const turns = ['turn_first', 'turn_second'];
    const store = new CaseModelTurnStore({
      now: () => '2026-08-07T09:00:00.000Z',
      nextPreparationId: () => ids.shift() ?? 'mtp_exhausted',
      nextTurnId: () => turns.shift() ?? 'turn_exhausted',
    });
    expect(store.create(session(), current())).toEqual({
      preparation_id: 'mtp_first',
      turn_id: 'turn_first',
      selection_id: 'sel_turn',
      target: TARGET,
      issued_at: '2026-08-07T09:00:00.000Z',
      expires_at: '2026-08-07T09:02:00.000Z',
    });
    const second = store.create(session(), current());
    expect(store.status('turn_first', session())).toBeNull();
    expect(store.beginUse(second.preparation_id, session({ session_id: 'session_other' }))).toBeNull();
    expect(store.beginUse(second.preparation_id, session())).toEqual({
      preparationId: 'mtp_second',
      turnId: 'turn_second',
      selectionId: 'sel_turn',
      target: TARGET,
    });
    expect(store.beginUse(second.preparation_id, session())).toBeNull();
  });

  it('refuses stale boot and reports provider uncertainty without inventing confirmation', () => {
    const store = new CaseModelTurnStore({
      now: () => '2026-08-07T09:00:00.000Z',
      nextPreparationId: () => 'mtp_uncertain',
      nextTurnId: () => 'turn_uncertain',
    });
    expect(() => store.create(session({ authorization_boot_id: 'authz_boot_other' }), current())).toThrow();
    const preparation = store.create(session(), current());
    store.beginUse(preparation.preparation_id, session());
    store.markProviderPossible(preparation.turn_id);
    expect(store.fail(preparation.turn_id, new ModelTurnError('provider-failure', 'possible'))).toEqual({
      turn_id: 'turn_uncertain',
      selection_id: 'sel_turn',
      target: TARGET,
      state: 'failed',
      provider_disclosure: 'possible',
      requested_id: TARGET.requested_id,
      served_id: null,
      terminal_reason: 'provider-failure',
      quarantine: null,
    });
  });

  it('destroys quarantine metadata and retains only a discarded status on selection change', () => {
    const store = new CaseModelTurnStore({
      now: () => '2026-08-07T09:00:00.000Z',
      nextPreparationId: () => 'mtp_quarantine',
      nextTurnId: () => 'turn_quarantine',
    });
    const preparation = store.create(session(), current());
    store.beginUse(preparation.preparation_id, session());
    const quarantine = new ModelOutputQuarantine();
    const destroy = vi.spyOn(quarantine, 'destroy');
    store.complete(preparation.turn_id, {
      disposition: 'quarantined',
      admission: {
        kind: 'model_output_control',
        disposition: 'admitted',
        authority_effect: 'none',
        case_id: 'case_demo',
        turn_id: preparation.turn_id,
        selection_id: 'sel_turn',
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
      quarantine: {
        kind: 'quarantined_model_output',
        release_state: 'sealed-no-release-path',
        call_id: 'mcl_turn',
        case_id: 'case_demo',
        turn_id: preparation.turn_id,
        selection_id: 'sel_turn',
        card_id: TARGET.card_id,
        card_version: TARGET.card_version,
        requested_id: TARGET.requested_id,
        served_id: TARGET.requested_id,
        projection_digest: DIGEST,
        output_digest: DIGEST,
        derived_tags: [],
      },
    }, quarantine);
    store.discardSelection('sel_turn', quarantine);
    expect(destroy).toHaveBeenCalledWith('turn_quarantine');
    expect(store.status('turn_quarantine', session())).toMatchObject({
      state: 'discarded',
      provider_disclosure: 'confirmed',
      terminal_reason: 'selection-changed',
      quarantine: null,
    });
  });

  it('retains confirmed disclosure evidence when session cleanup races a terminal failure', () => {
    const store = new CaseModelTurnStore({
      now: () => '2026-08-07T09:00:00.000Z',
      nextPreparationId: () => 'mtp_cleanup_race',
      nextTurnId: () => 'turn_cleanup_race',
    });
    const preparation = store.create(session(), current());
    store.beginUse(preparation.preparation_id, session());
    const quarantine = new ModelOutputQuarantine();
    store.markProviderPossible(preparation.turn_id);
    store.discardSession('session_turn', quarantine);
    expect(
      store.fail(
        preparation.turn_id,
        new ModelTurnError('provider-protocol', 'confirmed', TARGET.requested_id),
      ),
    ).toMatchObject({
      state: 'discarded',
      provider_disclosure: 'confirmed',
      served_id: TARGET.requested_id,
      terminal_reason: 'session-ended',
      quarantine: null,
    });
  });

  it('fails closed at the fixed in-memory status capacity', () => {
    const store = new CaseModelTurnStore({
      maxRecords: 1,
      now: () => '2026-08-07T09:00:00.000Z',
      nextPreparationId: () => 'mtp_bounded',
      nextTurnId: () => 'turn_bounded',
    });
    const preparation = store.create(session(), current());
    store.beginUse(preparation.preparation_id, session());
    store.fail(preparation.turn_id, new ModelTurnError('authorization-refused'));
    expect(() => store.create(session({ session_id: 'session_next' }), current())).toThrowError('model-turn-capacity');
  });

  it('rejects a coordinator outcome that does not match the stored turn binding', () => {
    const store = new CaseModelTurnStore({
      now: () => '2026-08-07T09:00:00.000Z',
      nextPreparationId: () => 'mtp_bad_binding',
      nextTurnId: () => 'turn_bad_binding',
    });
    const preparation = store.create(session(), current());
    store.beginUse(preparation.preparation_id, session());
    const quarantine = new ModelOutputQuarantine();
    const destroy = vi.spyOn(quarantine, 'destroy');
    expect(() => store.complete(preparation.turn_id, {
      disposition: 'withheld',
      admission: {
        kind: 'model_output_control',
        disposition: 'withheld',
        authority_effect: 'none',
        case_id: 'case_demo',
        turn_id: preparation.turn_id,
        selection_id: 'sel_wrong',
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        card_id: TARGET.card_id,
        card_version: TARGET.card_version,
        requested_id: TARGET.requested_id,
        served_id: TARGET.requested_id,
        model_resolution: 'mismatch',
        projection_digest: DIGEST,
        projection_item_count: 1,
        output_digest: DIGEST,
        flags: [],
        reasons: ['served-model-mismatch'],
      },
    }, quarantine)).toThrowError(ModelTurnError);
    expect(destroy).toHaveBeenCalledWith(preparation.turn_id);
  });
});
