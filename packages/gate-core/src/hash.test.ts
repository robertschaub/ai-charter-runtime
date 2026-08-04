// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';

import { DOMAIN_TAGS, domainPrefix, taggedBytes } from './domain.js';
import { digestFor, hmacSha256, macFor, sha256Hex, verifyDigest, verifyMacValue } from './hash.js';

const KEY_A = 'a'.repeat(64);
const KEY_B = `${'a'.repeat(63)}b`;

describe('hash', () => {
  it('matches the published SHA-256 of the empty string', () => {
    expect(sha256Hex('')).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
  });

  it('frames the hash input with the domain tag and the canonical bytes', () => {
    const value = { b: 1, a: 2 };
    expect(taggedBytes('proposal', value).toString('utf8')).toBe(
      'ai-charter-runtime/v1/proposal\n{"a":2,"b":1}',
    );
    expect(domainPrefix('checkpoint-composite')).toBe('ai-charter-runtime/v1/checkpoint-composite\n');
  });

  it('gives a value a different digest in every context', () => {
    const value = { world_id: 'w-demo', seq: 1 };
    const digests = new Set(DOMAIN_TAGS.map((tag) => digestFor(tag, value)));
    expect(digests.size).toBe(DOMAIN_TAGS.length);
  });

  it('rejects an unknown domain tag rather than hashing untagged', () => {
    expect(() => taggedBytes('not-a-context' as never, {})).toThrow(TypeError);
  });

  it('produces base64 MACs that depend on key, subject, and context', () => {
    const subject = { mandate_id: 'mdt_1', version: 1 };
    const mac = macFor('mandate-binding', subject, KEY_A);
    expect(Buffer.from(mac, 'base64')).toHaveLength(32);
    expect(macFor('mandate-binding', subject, KEY_A)).toBe(mac);
    expect(macFor('mandate-binding', subject, KEY_B)).not.toBe(mac);
    expect(macFor('commit-token', subject, KEY_A)).not.toBe(mac);
    expect(macFor('mandate-binding', { ...subject, version: 2 }, KEY_A)).not.toBe(mac);
  });

  it('refuses a key that is not 32 bytes of lowercase hex, without echoing it', () => {
    expect(() => hmacSha256('deadbeef', 'x')).toThrow(TypeError);
    expect(() => hmacSha256('A'.repeat(64), 'x')).toThrow(/64 lowercase hex/);
    expect(() => hmacSha256('deadbeef', 'x')).not.toThrow(/deadbeef/);
  });

  it('compares digests and MACs only at equal length', () => {
    const digest = sha256Hex('x');
    expect(verifyDigest(digest, digest)).toBe(true);
    expect(verifyDigest(digest, sha256Hex('y'))).toBe(false);
    expect(verifyDigest(digest, 'short')).toBe(false);
    expect(verifyDigest(digest, digest.toUpperCase())).toBe(false);

    const mac = macFor('commit-token', { a: 1 }, KEY_A);
    expect(verifyMacValue(mac, mac)).toBe(true);
    expect(verifyMacValue(mac, macFor('commit-token', { a: 2 }, KEY_A))).toBe(false);
    expect(verifyMacValue(mac, 'not base64 !!')).toBe(false);
    expect(verifyMacValue(mac, '')).toBe(false);
  });
});
