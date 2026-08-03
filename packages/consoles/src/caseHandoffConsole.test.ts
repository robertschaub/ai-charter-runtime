// SPDX-License-Identifier: MIT
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  acceptsHandoffTransfer,
  parseCreatedSession,
  parseRuntimeConsoleConfig,
  shouldPollCaseState,
} from './caseHandoffConsole.js';

describe('orchestrator-origin exact-window handoff client', () => {
  it('accepts only an exact two-origin runtime configuration', () => {
    expect(
      parseRuntimeConsoleConfig({
        authorization_origin: 'http://127.0.0.1:7801',
        orchestrator_origin: 'http://127.0.0.1:7802',
      }),
    ).toEqual({
      authorization_origin: 'http://127.0.0.1:7801',
      orchestrator_origin: 'http://127.0.0.1:7802',
    });
    expect(
      parseRuntimeConsoleConfig({
        authorization_origin: 'http://127.0.0.1:7801/path',
        orchestrator_origin: 'http://127.0.0.1:7802',
      }),
    ).toBeNull();
    expect(
      parseRuntimeConsoleConfig({
        authorization_origin: 'http://127.0.0.1:7801',
        orchestrator_origin: 'http://127.0.0.1:7802',
        caller_target: 'http://attacker.invalid',
      }),
    ).toBeNull();
  });

  it('requires reciprocal origin, source, target, and strict message bindings', () => {
    const opener = {} as WindowProxy;
    const other = {} as WindowProxy;
    const data = {
      type: 'runtime.case-handoff.transfer',
      handoff_id: 'handoff_one',
      handoff_code: 'a'.repeat(64),
      role: 'case_officer',
      world_id: 'w-demo',
      case_id: 'case_demo',
      target_origin: 'http://127.0.0.1:7802',
      authorization_boot_id: 'authz_boot_one',
    };
    const event = { origin: 'http://127.0.0.1:7801', source: opener, data };
    expect(acceptsHandoffTransfer(event, event.origin, opener, data.target_origin)).toBe(true);
    expect(acceptsHandoffTransfer({ ...event, origin: 'null' }, event.origin, opener, data.target_origin)).toBe(false);
    expect(acceptsHandoffTransfer({ ...event, source: other }, event.origin, opener, data.target_origin)).toBe(false);
    expect(
      acceptsHandoffTransfer(
        { ...event, data: { ...data, target_origin: 'http://127.0.0.1:9999' } },
        event.origin,
        opener,
        data.target_origin,
      ),
    ).toBe(false);
    expect(
      acceptsHandoffTransfer({ ...event, data: { ...data, extra: true } }, event.origin, opener, data.target_origin),
    ).toBe(false);
  });

  it('keeps the fixed handoff shell free of inline and third-party executable content', () => {
    const shell = readFileSync(resolve('packages/consoles/assets/case-console/handoff.html'), 'utf8');
    expect(shell).toContain('<script type="module" src="/console/handoff.js"></script>');
    expect(shell).toContain('<link rel="stylesheet" href="/console/case-styles.css">');
    expect(shell).not.toMatch(/<script(?![^>]*\bsrc=)/i);
    expect(shell).not.toMatch(/<style\b/i);
    expect(shell).not.toMatch(/\son[a-z]+=/i);
    expect(shell).not.toMatch(/https?:\/\//i);
  });

  it('binds created sessions to one case and polls only an open dialogue mirror', () => {
    expect(
      parseCreatedSession({
        session_token: 'a'.repeat(64),
        session_id: 'session_one',
        role: 'case_officer',
        world_id: 'w-demo',
        case_id: 'case_demo',
        expires_at: '2026-08-03T10:15:00.000Z',
      }),
    ).toEqual({ session_token: 'a'.repeat(64), world_id: 'w-demo', case_id: 'case_demo' });
    expect(
      parseCreatedSession({
        session_token: 'a'.repeat(64),
        session_id: 'session_one',
        role: 'case_officer',
        world_id: 'w-demo',
        expires_at: '2026-08-03T10:15:00.000Z',
      }),
    ).toBeNull();
    expect(shouldPollCaseState({ dialogue: { status: 'open' } })).toBe(true);
    expect(shouldPollCaseState({ dialogue: { status: 'terminal' } })).toBe(false);
    expect(shouldPollCaseState({ dialogue: null })).toBe(false);
  });
});
