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
import type { DomainTag } from './domain.js';
import { HMAC_ALG, macFor, verifyMacValue } from './hash.js';

export type MacStatus = 'valid' | 'invalid' | 'unverifiable';

export interface MacBlock {
  readonly alg: string;
  readonly key_id: string;
  readonly value: string;
}

export class KeyringError extends Error {
  readonly code: 'malformed-keyring' | 'malformed-active-key' | 'duplicate-key-id' | 'no-active-key';
  constructor(code: KeyringError['code'], message: string) {
    super(message);
    this.name = 'KeyringError';
    this.code = code;
  }
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
