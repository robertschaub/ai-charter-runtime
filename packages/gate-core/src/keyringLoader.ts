// SPDX-License-Identifier: AGPL-3.0-only
/** Environment/file loader kept outside the M6 offline-safe keyring primitives. */
import { existsSync, readFileSync } from 'node:fs';
import { resolve as resolvePath } from 'node:path';

import { isHexDigest } from './hash.js';
import { Keyring, KeyringError } from './keyring.js';

export interface KeyringOptions {
  readonly env?: NodeJS.ProcessEnv;
  readonly keyringPath?: string;
}

export const DEFAULT_KEYRING_RELATIVE_PATH = 'keys/hmac-keyring.json';

function readKeyringFile(path: string): { key_id: string; key: string }[] {
  if (!existsSync(path)) return [];
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(path, 'utf8')); } catch { throw new KeyringError('malformed-keyring', `keyring: ${path} is not valid JSON`); }
  const keys = Array.isArray(parsed) ? parsed : typeof parsed === 'object' && parsed !== null ? (parsed as Record<string, unknown>)['keys'] : undefined;
  if (!Array.isArray(keys)) throw new KeyringError('malformed-keyring', `keyring: ${path} has no keys array`);
  return keys.map((raw, index) => {
    if (typeof raw !== 'object' || raw === null) throw new KeyringError('malformed-keyring', `keyring: entry ${index} is not an object`);
    const keyId = (raw as Record<string, unknown>)['key_id'];
    const key = (raw as Record<string, unknown>)['key'];
    if (typeof keyId !== 'string' || keyId.length === 0) throw new KeyringError('malformed-keyring', `keyring: entry ${index} has no key_id`);
    if (!isHexDigest(key)) throw new KeyringError('malformed-keyring', `keyring: key ${keyId} is not 64 lowercase hex characters`);
    return { key_id: keyId, key };
  });
}

export function loadKeyring(options: KeyringOptions = {}): Keyring {
  const env = options.env ?? process.env;
  const keyringPath = options.keyringPath ?? env['GATE_KEYRING_PATH'] ?? resolvePath(process.cwd(), DEFAULT_KEYRING_RELATIVE_PATH);
  const keys = new Map<string, string>();
  for (const entry of readKeyringFile(keyringPath)) {
    if (keys.has(entry.key_id)) throw new KeyringError('duplicate-key-id', `keyring: duplicate key id ${entry.key_id}`);
    keys.set(entry.key_id, entry.key);
  }
  const activeKey = env['GATE_HMAC_KEY'];
  const activeKeyId = env['GATE_HMAC_KEY_ID'];
  let resolvedActiveId: string | undefined;
  if (activeKey !== undefined && activeKey !== '') {
    if (!isHexDigest(activeKey)) throw new KeyringError('malformed-active-key', 'keyring: GATE_HMAC_KEY is not 64 lowercase hex characters');
    if (activeKeyId === undefined || activeKeyId === '') throw new KeyringError('malformed-active-key', 'keyring: GATE_HMAC_KEY is set without GATE_HMAC_KEY_ID');
    if (keys.has(activeKeyId)) throw new KeyringError('duplicate-key-id', `keyring: active key id ${activeKeyId} is already retired`);
    keys.set(activeKeyId, activeKey);
    resolvedActiveId = activeKeyId;
  }
  return new Keyring(keys, resolvedActiveId);
}
