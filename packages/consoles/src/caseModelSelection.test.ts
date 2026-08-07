// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import type { CaseSessionRecord } from './caseSessionStore.js';
import {
  CaseModelSelectionPreparationError,
  CaseModelSelectionPreparationStore,
  toBrowserApprovedModels,
  toBrowserCurrentModelSelection,
  toBrowserModelSelectionResult,
} from './caseModelSelection.js';

const DIGEST = 'a'.repeat(64);
const TARGET = {
  card_id: 'publicai-apertus-v1.5-70b',
  card_version: 1,
  requested_id: 'swiss-ai/apertus-v1.5-70b',
};

const binding = (expectedCurrentSelectionId: string | null = null) => ({
  target: TARGET,
  expectedCurrentSelectionId,
});

function session(overrides: Partial<CaseSessionRecord> = {}): CaseSessionRecord {
  return {
    session_id: 'session_one',
    token_digest: 'b'.repeat(64),
    handoff_id: 'handoff_one',
    role: 'case_officer',
    world_id: 'w-demo',
    case_id: 'case_demo',
    target_origin: 'http://127.0.0.1:7802',
    authorization_boot_id: 'authz_boot_one',
    created_at: '2026-08-05T10:00:00.000Z',
    expires_at: '2026-08-05T10:15:00.000Z',
    state: 'active',
    ...overrides,
  };
}

function check(
  checkId: string,
  overrides: {
    readonly boot?: string;
    readonly predecessor?: string | null;
    readonly expiresAt?: string;
    readonly target?: typeof TARGET;
  } = {},
) {
  const resolvedTarget = overrides.target ?? TARGET;
  return {
    check: {
      kind: 'model_selection_check' as const,
      world_id: 'w-demo',
      check_id: checkId,
      authorization_boot_id: overrides.boot ?? 'authz_boot_one',
      case_id: 'case_demo',
      authenticated_actor: 'proc:orchestrator' as const,
      expected_current_selection_id: overrides.predecessor ?? null,
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      target: { ...resolvedTarget, card_digest: DIGEST, verifying_key_id: 'card_test' },
      system_use_decision: {
        decision_id: 'sud_demo',
        version: 1,
        record_digest: DIGEST,
        status: 'approved' as const,
        conditions: [],
      },
      policy_version: 'policy-test',
      policy_content_digest: DIGEST,
      evaluator_build_id: 'build-test',
      issued_at: '2026-08-05T10:00:00.000Z',
      expires_at: overrides.expiresAt ?? '2026-08-05T10:05:00.000Z',
      state: 'issued' as const,
      consumed_at: null,
    },
    evidence: {
      approval: {
        ...resolvedTarget,
        card_digest: DIGEST,
        roles: ['acting' as const],
        data_classes: { acting: ['conf:case'] },
      },
      effective_data_classes: { acting: ['conf:case'] },
      card_status: 'current' as const,
      signature_status: 'valid' as const,
      integrity_alarm: false,
      current_card_digest: DIGEST,
      verifying_key_id: 'card_test',
      current_card: null,
    },
  };
}

function transition(selectionId: string, predecessor: string | null = null) {
  return {
    world_id: 'w-demo',
    selection_id: selectionId,
    case_id: 'case_demo',
    kind: predecessor === null ? ('initial' as const) : ('switch' as const),
    predecessor_selection_id: predecessor,
    mandate_id: 'mdt_demo_grant',
    mandate_version: 1,
    target: { ...TARGET, card_digest: DIGEST, verifying_key_id: 'card_test' },
    system_use_decision: {
      decision_id: 'sud_demo',
      version: 1,
      record_digest: DIGEST,
      status: 'approved' as const,
      conditions: [],
    },
    check_id: 'msc_hidden',
    selected_at: '2026-08-05T10:00:01.000Z',
    authority_effect: 'none' as const,
  };
}

describe('ADR-010 browser model-selection preparations', () => {
  it('caps one preparation by browser/session/check expiry and consumes it once', () => {
    let at = '2026-08-05T10:00:00.000Z';
    const ids = ['msp_first', 'msp_second'];
    const store = new CaseModelSelectionPreparationStore({
      now: () => at,
      nextPreparationId: () => ids.shift() ?? 'msp_repeated',
    });
    const first = store.create(session(), check('msc_first'), binding());
    expect(first).toEqual({
      preparation_id: 'msp_first',
      target: TARGET,
      issued_at: at,
      expires_at: '2026-08-05T10:02:00.000Z',
    });
    const second = store.create(session(), check('msc_second'), binding());
    expect(store.beginUse(first.preparation_id, session())).toBeNull();
    expect(store.beginUse(second.preparation_id, session())).toEqual({
      preparationId: 'msp_second',
      checkId: 'msc_second',
      expectedCurrentSelectionId: null,
      target: TARGET,
    });
    expect(store.beginUse(second.preparation_id, session())).toBeNull();
    expect(store.activeCount()).toBe(1);
    store.burn(second.preparation_id);
    expect(store.activeCount()).toBe(0);

    const expiring = new CaseModelSelectionPreparationStore({
      now: () => at,
      nextPreparationId: () => 'msp_expiring',
    });
    const short = expiring.create(
      session(),
      check('msc_short', { expiresAt: '2026-08-05T10:00:30.000Z' }),
      binding(),
    );
    expect(short.expires_at).toBe('2026-08-05T10:00:30.000Z');
    at = short.expires_at;
    expect(expiring.beginUse(short.preparation_id, session())).toBeNull();
  });

  it('binds boot/session/predecessor and exposes no operation that enumerates hidden checks', () => {
    const store = new CaseModelSelectionPreparationStore({
      now: () => '2026-08-05T10:00:00.000Z',
      nextPreparationId: () => 'msp_bound',
    });
    expect(() => store.create(session(), check('msc_wrong_boot', { boot: 'authz_boot_two' }), binding())).toThrowError(
      CaseModelSelectionPreparationError,
    );
    expect(() => store.create(session(), check('msc_wrong_predecessor', { predecessor: 'sel_a' }), binding())).toThrowError(
      CaseModelSelectionPreparationError,
    );
    expect(() =>
      store.create(
        session(),
        check('msc_wrong_target', {
          target: { ...TARGET, requested_id: 'gpt-5.5' },
        }),
        binding(),
      ),
    ).toThrowError(CaseModelSelectionPreparationError);
    const prepared = store.create(session(), check('msc_bound', { predecessor: 'sel_a' }), binding('sel_a'));
    expect(store.beginUse(prepared.preparation_id, session({ session_id: 'session_other' }))).toBeNull();
    expect(store.activeCount()).toBe(1);
    store.burnStaleForCase('w-demo', 'case_demo', 'sel_b');
    expect(store.activeCount()).toBe(0);
    expect(Object.getOwnPropertyNames(Object.getPrototypeOf(store))).not.toContain('snapshot');
  });
});

describe('ADR-010 browser redaction', () => {
  it('removes authorization-only card, check, system-use, call, and actor bindings', () => {
    const approved = toBrowserApprovedModels({
      mandate_id: 'mdt_demo_grant',
      mandate_version: 1,
      mandate_state: 'active',
      default_acting_model: TARGET,
      models: [check('msc_models').evidence],
    });
    const current = toBrowserCurrentModelSelection({
      state: 'selected',
      authorization_boot_id: 'authz_boot_test',
      case_id: 'case_demo',
      selection: transition('sel_a'),
      latest_observation: {
        kind: 'model_selection_observation',
        world_id: 'w-demo',
        observation_id: 'mso_one',
        selection_id: 'sel_a',
        call_id: 'mcl_hidden',
        served_id: TARGET.requested_id,
        model_resolution: 'exact',
        terminal_outcome: 'admitted',
        observed_at: '2026-08-05T10:00:02.000Z',
      },
    });
    const result = toBrowserModelSelectionResult({
      kind: 'model_selection_result',
      selection: transition('sel_b', 'sel_a'),
      invalidated_ruling_count: 1,
      terminalized_open_call_count: 1,
    });
    const serialized = JSON.stringify({ approved, current, result });
    for (const hidden of [
      'authorization_boot_id',
      'card_digest',
      'current_card_digest',
      'verifying_key_id',
      'check_id',
      'system_use_decision',
      'policy_version',
      'call_id',
      'authenticated_actor',
    ]) {
      expect(serialized).not.toContain(hidden);
    }
    expect(current).toEqual({
      state: 'selected',
      case_id: 'case_demo',
      selection: {
        selection_id: 'sel_a',
        kind: 'initial',
        predecessor_selection_id: null,
        mandate_id: 'mdt_demo_grant',
        mandate_version: 1,
        selected_at: '2026-08-05T10:00:01.000Z',
        authority_effect: 'none',
        target: TARGET,
      },
      latest_observation: {
        served_id: TARGET.requested_id,
        model_resolution: 'exact',
        terminal_outcome: 'admitted',
        observed_at: '2026-08-05T10:00:02.000Z',
      },
    });
    expect(
      toBrowserCurrentModelSelection({
        state: 'unselected',
        authorization_boot_id: 'authz_boot_test',
        case_id: 'case_demo',
        selection: null,
        latest_observation: null,
      }),
    ).toEqual({ state: 'unselected', case_id: 'case_demo', selection: null, latest_observation: null });
    expect(result).toMatchObject({ selection: { selection_id: 'sel_b', predecessor_selection_id: 'sel_a' } });
  });
});
