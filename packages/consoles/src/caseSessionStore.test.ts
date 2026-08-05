// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { CaseSessionStore, type CaseSessionClaim } from './caseSessionStore.js';

const claim: CaseSessionClaim = {
  handoff_id: 'handoff_one',
  role: 'case_officer',
  world_id: 'w-demo',
  case_id: 'case_demo',
  target_origin: 'http://127.0.0.1:7802',
  authorization_boot_id: 'authz_boot_one',
  consumed_at: '2026-08-03T10:00:00.000Z',
};

describe('orchestrator-local case sessions', () => {
  it('stores only a digest, enforces world scope, and closes explicitly', () => {
    const token = 'a'.repeat(64);
    const store = new CaseSessionStore({
      now: () => '2026-08-03T10:00:00.000Z',
      randomToken: () => token,
      nextSessionId: () => 'session_one',
    });
    const created = store.create(claim);
    expect(created).toMatchObject({
      session_token: token,
      session_id: 'session_one',
      role: 'case_officer',
      world_id: 'w-demo',
      case_id: 'case_demo',
    });
    expect(JSON.stringify(store.snapshot())).not.toContain(token);
    expect(store.authenticate(token, 'w-other')).toBeNull();
    expect(store.authenticate(token, 'w-demo', 'case_other')).toBeNull();
    expect(store.authenticate(token, 'w-demo', 'case_demo')).toMatchObject({
      state: 'active',
      handoff_id: 'handoff_one',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_one',
    });
    expect(store.close(token, 'w-demo')).toBe(true);
    expect(store.authenticate(token, 'w-demo')).toBeNull();
  });

  it('expires without refresh and a fresh store represents restart invalidation', () => {
    let at = '2026-08-03T10:00:00.000Z';
    const token = 'b'.repeat(64);
    const store = new CaseSessionStore({
      ttlMs: 1_000,
      now: () => at,
      randomToken: () => token,
      nextSessionId: () => 'session_two',
    });
    store.create(claim);
    at = '2026-08-03T10:00:01.000Z';
    expect(store.authenticate(token, 'w-demo')).toBeNull();
    expect(store.snapshot()).toEqual([]);
    expect(new CaseSessionStore().authenticate(token, 'w-demo')).toBeNull();
  });
});
