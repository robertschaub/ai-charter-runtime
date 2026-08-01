// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ADR-007 — HMAC key lifecycle.
 *
 * The active key lives in gitignored `.env.local` as `GATE_HMAC_KEY` (hex) with
 * `GATE_HMAC_KEY_ID`; retired keys live in gitignored `keys/hmac-keyring.json`. Rotation
 * is a new key id, never a re-signing pass, so a verifier resolves `key_id` against
 * {active} u keyring and older bindings stay verifiable.
 *
 * **Unknown key id != bad MAC.** `verifyMac` reports `unverifiable` distinctly from
 * `invalid`; both are defective authority and deny, but the record viewer must be able to
 * say which. Losing the keyring makes historical bindings *unverifiable*, not *invalid* —
 * the keyless SHA-256 chains are untouched.
 *
 * Nothing here writes, logs, or serializes key material: `Keyring.toJSON()` returns key
 * ids only.
 */
import { existsSync, readFileSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';

import type { DomainTag } from './domain.js';
import { HMAC_ALG, isHexDigest, macFor, verifyMacValue } from './hash.js';

export type MacStatus = 'valid' | 'invalid' | 'unverifiable';

export interface MacBlock {
  readonly alg: string;
  readonly key_id: string;
  readonly value: string;
}

export interface KeyringOptions {
  readonly env?: NodeJS.ProcessEnv;
  /** Defaults to `$GATE_KEYRING_PATH`, else `<cwd>/keys/hmac-keyring.json`. */
  readonly keyringPath?: string;
}

export class KeyringError extends Error {
  readonly code: 'malformed-keyring' | 'malformed-active-key' | 'duplicate-key-id' | 'no-active-key';
  constructor(code: KeyringError['code'], message: string) {
    super(message);
    this.name = 'KeyringError';
    this.code = code;
  }
}

export const DEFAULT_KEYRING_RELATIVE_PATH = 'keys/hmac-keyring.json';

interface KeyringFileEntry {
  key_id: string;
  key: string;
}

function isMacBlock(value: unknown): value is MacBlock {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const block = value as Record<string, unknown>;
  return (
    typeof block['alg'] === 'string' &&
    typeof block['key_id'] === 'string' &&
    block['key_id'].length > 0 &&
    typeof block['value'] === 'string'
  );
}

function readKeyringFile(path: string): KeyringFileEntry[] {
  // An absent file is an empty ring — a fresh checkout has no retired keys.
  if (!existsSync(path)) return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, 'utf8'));
  } catch {
    throw new KeyringError('malformed-keyring', `keyring: ${path} is not valid JSON`);
  }
  const keys =
    Array.isArray(parsed) ? parsed
    : typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>)['keys']
    : undefined;
  if (!Array.isArray(keys)) {
    throw new KeyringError('malformed-keyring', `keyring: ${path} has no keys array`);
  }
  return keys.map((raw, index) => {
    if (typeof raw !== 'object' || raw === null) {
      throw new KeyringError('malformed-keyring', `keyring: entry ${index} is not an object`);
    }
    const entry = raw as Record<string, unknown>;
    const keyId = entry['key_id'];
    const key = entry['key'];
    if (typeof keyId !== 'string' || keyId.length === 0) {
      throw new KeyringError('malformed-keyring', `keyring: entry ${index} has no key_id`);
    }
    if (!isHexDigest(key)) {
      // Never echoes the value.
      throw new KeyringError('malformed-keyring', `keyring: key ${keyId} is not 64 lowercase hex characters`);
    }
    return { key_id: keyId, key };
  });
}

export class Keyring {
  readonly #keys: ReadonlyMap<string, string>;
  readonly #activeKeyId: string | undefined;

  constructor(keys: ReadonlyMap<string, string>, activeKeyId: string | undefined) {
    this.#keys = keys;
    this.#activeKeyId = activeKeyId;
  }

  /** Hex key material for `keyId`, or `undefined` when the ring does not hold it. */
  resolve(keyId: string): string | undefined {
    return this.#keys.get(keyId);
  }

  has(keyId: string): boolean {
    return this.#keys.has(keyId);
  }

  /** The id new MACs are minted under, if an active key is configured. */
  get activeKeyId(): string | undefined {
    return this.#activeKeyId;
  }

  keyIds(): string[] {
    return [...this.#keys.keys()].sort();
  }

  /** Key ids only — key material must never reach a log, a record, or a fixture. */
  toJSON(): { active_key_id: string | undefined; key_ids: string[] } {
    return { active_key_id: this.#activeKeyId, key_ids: this.keyIds() };
  }
}

/**
 * Resolve {active env pair} u keyring file. A key id identifies exactly one byte string;
 * collisions fail closed instead of silently changing the meaning of historical MACs.
 */
export function loadKeyring(options: KeyringOptions = {}): Keyring {
  const env = options.env ?? process.env;
  const keyringPath =
    options.keyringPath ?? env['GATE_KEYRING_PATH'] ?? resolvePath(process.cwd(), DEFAULT_KEYRING_RELATIVE_PATH);

  const keys = new Map<string, string>();
  for (const entry of readKeyringFile(keyringPath)) {
    const existing = keys.get(entry.key_id);
    if (existing !== undefined) {
      throw new KeyringError('duplicate-key-id', `keyring: duplicate key id ${entry.key_id}`);
    }
    keys.set(entry.key_id, entry.key);
  }

  const activeKey = env['GATE_HMAC_KEY'];
  const activeKeyId = env['GATE_HMAC_KEY_ID'];
  let resolvedActiveId: string | undefined;
  if (activeKey !== undefined && activeKey !== '') {
    if (!isHexDigest(activeKey)) {
      throw new KeyringError('malformed-active-key', 'keyring: GATE_HMAC_KEY is not 64 lowercase hex characters');
    }
    if (activeKeyId === undefined || activeKeyId === '') {
      throw new KeyringError('malformed-active-key', 'keyring: GATE_HMAC_KEY is set without GATE_HMAC_KEY_ID');
    }
    const retired = keys.get(activeKeyId);
    if (retired !== undefined) {
      throw new KeyringError('duplicate-key-id', `keyring: active key id ${activeKeyId} is already retired`);
    }
    keys.set(activeKeyId, activeKey);
    resolvedActiveId = activeKeyId;
  }

  return new Keyring(keys, resolvedActiveId);
}

/** Mint a MAC block over `subject` under the active key (or an explicitly named one). */
export function createMac(keyring: Keyring, context: DomainTag, subject: unknown, keyId?: string): MacBlock {
  const id = keyId ?? keyring.activeKeyId;
  if (id === undefined) {
    throw new KeyringError('no-active-key', 'keyring: no active key id configured');
  }
  const key = keyring.resolve(id);
  if (key === undefined) {
    throw new KeyringError('no-active-key', `keyring: no key material for ${id}`);
  }
  return { alg: HMAC_ALG, key_id: id, value: macFor(context, subject, key) };
}

/**
 * Three outcomes, never collapsed:
 *   - `valid`        — recomputed MAC matches;
 *   - `invalid`      — mismatch, or a structurally defective block (nothing to resolve);
 *   - `unverifiable` — a well-formed block naming a key id the ring does not hold, or an
 *                      algorithm this build cannot compute.
 */
export function verifyMac(keyring: Keyring, context: DomainTag, subject: unknown, mac: unknown): MacStatus {
  if (!isMacBlock(mac)) return 'invalid';
  if (mac.alg !== HMAC_ALG) return 'unverifiable';
  const key = keyring.resolve(mac.key_id);
  if (key === undefined) return 'unverifiable';
  let expected: string;
  try {
    expected = macFor(context, subject, key);
  } catch {
    // A subject outside the canonicalization subset cannot be MAC'd, so it cannot verify.
    return 'invalid';
  }
  return verifyMacValue(expected, mac.value) ? 'valid' : 'invalid';
}

/** A copy of `object` without `field` — the field is deleted, never set to `undefined`. */
function withoutField(object: Record<string, unknown>, field: string): Record<string, unknown> {
  const copy: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(object)) {
    if (key !== field) copy[key] = value;
  }
  return copy;
}

/**
 * Embed a MAC block over the object minus that block — the ADR-007 shape used by the
 * mandate binding and the commit token.
 */
export function createEmbeddedMac<T extends Record<string, unknown>>(
  keyring: Keyring,
  context: DomainTag,
  object: T,
  field: string,
  keyId?: string,
): T & Record<string, MacBlock> {
  const subject = withoutField(object, field);
  const block = createMac(keyring, context, subject, keyId);
  return { ...object, [field]: block } as T & Record<string, MacBlock>;
}

/** Verify an embedded MAC block against the object minus that block. */
export function verifyEmbeddedMac(
  keyring: Keyring,
  context: DomainTag,
  object: Record<string, unknown>,
  field: string,
): MacStatus {
  const block = object[field];
  return verifyMac(keyring, context, withoutField(object, field), block);
}
