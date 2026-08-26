// SPDX-License-Identifier: AGPL-3.0-only
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import {
  Keyring,
  KeyringError,
  createEmbeddedMac,
  createMac,
  verifyEmbeddedMac,
  verifyMac,
} from './keyring.js';
import { DEFAULT_KEYRING_RELATIVE_PATH, loadKeyring } from './keyringLoader.js';
import type { MacStatus } from './keyring.js';

const ACTIVE_KEY = 'a'.repeat(64);
const ACTIVE_ID = 'hmac-2026-08-01';
const RETIRED_KEY = 'b'.repeat(64);
const RETIRED_ID = 'hmac-2026-07-01';

let dir: string;
let keyringPath: string;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'gate-core-keys-'));
  keyringPath = join(dir, 'hmac-keyring.json');
});

afterEach(() => {
  rmSync(dir, { recursive: true, force: true });
});

function withRetiredKeys(): Keyring {
  writeFileSync(
    keyringPath,
    JSON.stringify({
      schema: 'ai-charter-runtime/hmac-keyring/v1',
      keys: [{ key_id: RETIRED_ID, key: RETIRED_KEY, retired_at: '2026-08-01' }],
    }),
    'utf8',
  );
  return loadKeyring({ env: { GATE_HMAC_KEY: ACTIVE_KEY, GATE_HMAC_KEY_ID: ACTIVE_ID }, keyringPath });
}

describe('keyring — resolution', () => {
  it('treats an absent keyring file as an empty ring', () => {
    const keyring = loadKeyring({ env: {}, keyringPath });
    expect(keyring.keyIds()).toEqual([]);
    expect(keyring.activeKeyId).toBeUndefined();
  });

  it('resolves {active env pair} union keyring file', () => {
    const keyring = withRetiredKeys();
    expect(keyring.keyIds()).toEqual([RETIRED_ID, ACTIVE_ID].sort());
    expect(keyring.activeKeyId).toBe(ACTIVE_ID);
  });

  it('never serializes key material', () => {
    const keyring = withRetiredKeys();
    const serialized = JSON.stringify(keyring);
    expect(serialized).toContain(ACTIVE_ID);
    expect(serialized).not.toContain(ACTIVE_KEY);
    expect(serialized).not.toContain(RETIRED_KEY);
  });

  it('fails closed on a malformed active key or a keyring without an id', () => {
    expect(() => loadKeyring({ env: { GATE_HMAC_KEY: 'short', GATE_HMAC_KEY_ID: ACTIVE_ID }, keyringPath })).toThrow(
      KeyringError,
    );
    expect(() => loadKeyring({ env: { GATE_HMAC_KEY: ACTIVE_KEY }, keyringPath })).toThrow(KeyringError);
    writeFileSync(keyringPath, '{"keys":[{"key_id":"k","key":"nope"}]}', 'utf8');
    expect(() => loadKeyring({ env: {}, keyringPath })).toThrow(/64 lowercase hex/);
  });
});

describe('keyring — verifyMac keeps three distinct outcomes', () => {
  it('valid, invalid and unverifiable are never collapsed', () => {
    const keyring = withRetiredKeys();
    const subject = { mandate_id: 'mdt_1', version: 1 };
    const good = createMac(keyring, 'mandate-binding', subject);

    const statuses: Record<string, MacStatus> = {
      matching: verifyMac(keyring, 'mandate-binding', subject, good),
      // A mismatch: the subject moved under the MAC.
      mismatch: verifyMac(keyring, 'mandate-binding', { ...subject, version: 2 }, good),
      // A key id the ring does not hold — rotation, or a lost keyring.
      unknownKeyId: verifyMac(keyring, 'mandate-binding', subject, { ...good, key_id: 'hmac-2025-01-01' }),
    };

    expect(statuses).toEqual({ matching: 'valid', mismatch: 'invalid', unknownKeyId: 'unverifiable' });
    expect(new Set(Object.values(statuses)).size).toBe(3);
  });

  it('keeps a MAC made under a retired key verifiable after rotation', () => {
    const keyring = withRetiredKeys();
    const subject = { mandate_id: 'mdt_1', version: 1 };
    const oldMac = createMac(keyring, 'mandate-binding', subject, RETIRED_ID);
    expect(verifyMac(keyring, 'mandate-binding', subject, oldMac)).toBe('valid');

    // Drop the retired key from the ring: the binding becomes unverifiable, not invalid.
    const withoutRetired = loadKeyring({
      env: { GATE_HMAC_KEY: ACTIVE_KEY, GATE_HMAC_KEY_ID: ACTIVE_ID },
      keyringPath: join(dir, 'absent.json'),
    });
    expect(verifyMac(withoutRetired, 'mandate-binding', subject, oldMac)).toBe('unverifiable');
  });

  it('reports an algorithm it cannot compute as unverifiable, a broken block as invalid', () => {
    const keyring = withRetiredKeys();
    const subject = { a: 1 };
    const good = createMac(keyring, 'mandate-binding', subject);

    expect(verifyMac(keyring, 'mandate-binding', subject, { ...good, alg: 'hmac-sha512' })).toBe('unverifiable');
    expect(verifyMac(keyring, 'mandate-binding', subject, { ...good, value: 'not base64 !!' })).toBe('invalid');
    expect(verifyMac(keyring, 'mandate-binding', subject, null)).toBe('invalid');
    expect(verifyMac(keyring, 'mandate-binding', subject, { alg: 'hmac-sha256', key_id: ACTIVE_ID })).toBe('invalid');
    expect(verifyMac(keyring, 'mandate-binding', subject, {})).toBe('invalid');
  });

  it('binds a MAC to its domain, so a commit-token MAC is not a mandate binding', () => {
    const keyring = withRetiredKeys();
    const subject = { a: 1 };
    const tokenMac = createMac(keyring, 'commit-token', subject);
    expect(verifyMac(keyring, 'commit-token', subject, tokenMac)).toBe('valid');
    expect(verifyMac(keyring, 'mandate-binding', subject, tokenMac)).toBe('invalid');
  });

  it('refuses to mint a MAC with no active key', () => {
    const keyring = loadKeyring({ env: {}, keyringPath });
    expect(() => createMac(keyring, 'mandate-binding', { a: 1 })).toThrow(KeyringError);
  });
});

describe('keyring — embedded bindings', () => {
  it('covers the object minus its own binding block, so an amendment must re-bind', () => {
    const keyring = withRetiredKeys();
    const mandate = { world_id: 'w-demo', mandate_id: 'mdt_1', version: 1 };
    const bound = createEmbeddedMac(keyring, 'mandate-binding', mandate, 'binding');

    expect(verifyEmbeddedMac(keyring, 'mandate-binding', bound, 'binding')).toBe('valid');
    expect(verifyEmbeddedMac(keyring, 'mandate-binding', { ...bound, version: 2 }, 'binding')).toBe('invalid');

    // Re-binding the amended mandate restores validity — rotation is a new id, not a re-sign.
    const amended = createEmbeddedMac(keyring, 'mandate-binding', { ...mandate, version: 2 }, 'binding');
    expect(verifyEmbeddedMac(keyring, 'mandate-binding', amended, 'binding')).toBe('valid');
    expect(amended['binding']).not.toEqual(bound['binding']);
  });

  it('treats a missing binding block as invalid', () => {
    const keyring = withRetiredKeys();
    expect(verifyEmbeddedMac(keyring, 'mandate-binding', { mandate_id: 'mdt_1' }, 'binding')).toBe('invalid');
  });
});
