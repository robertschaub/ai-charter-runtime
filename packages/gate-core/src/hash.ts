// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ADR-007 — one hash, one MAC, one encoding table.
 *
 * SHA-256 everywhere from `node:crypto`; digests are lowercase hex, unprefixed, over the
 * UTF-8 bytes of the canonical string. Keys and MACs are base64. Digest and MAC
 * comparisons use `crypto.timingSafeEqual` on equal-length buffers.
 */
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';

import type { DomainTag } from './domain.js';
import { taggedBytes } from './domain.js';

/** 64 lowercase hex characters. */
export const HEX64 = /^[0-9a-f]{64}$/;

/** The MAC algorithm label carried in every MAC block. */
export const HMAC_ALG = 'hmac-sha256' as const;

export function isHexDigest(value: unknown): value is string {
  return typeof value === 'string' && HEX64.test(value);
}

/** Decode a 32-byte HMAC key from its 64-character lowercase hex form. */
export function keyHexToBytes(keyHex: string): Buffer {
  if (!isHexDigest(keyHex)) {
    // Deliberately does not echo the value: key material never reaches a message.
    throw new TypeError('hmac key must be 32 bytes as 64 lowercase hex characters');
  }
  return Buffer.from(keyHex, 'hex');
}

/** Lowercase hex SHA-256 of the given bytes (strings are hashed as UTF-8). */
export function sha256Hex(input: Buffer | string): string {
  return createHash('sha256').update(input).digest('hex');
}

/** Base64 HMAC-SHA256 of the given bytes under a hex-encoded key. */
export function hmacSha256(keyHex: string, input: Buffer | string): string {
  return createHmac('sha256', keyHexToBytes(keyHex)).update(input).digest('base64');
}

/** Constant-time comparison of two UTF-8 strings, length-checked first. */
export function timingSafeEqualUtf8(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/** Constant-time comparison of two lowercase-hex digests. */
export function verifyDigest(expected: string, actual: string): boolean {
  if (!isHexDigest(expected) || !isHexDigest(actual)) return false;
  return timingSafeEqualUtf8(expected, actual);
}

/** True when `value` round-trips through canonical base64 (rejects sloppy encodings). */
export function isCanonicalBase64(value: unknown): value is string {
  if (typeof value !== 'string' || value.length === 0) return false;
  return Buffer.from(value, 'base64').toString('base64') === value;
}

/** Constant-time comparison of two base64 MAC values, over their decoded bytes. */
export function verifyMacValue(expected: string, actual: string): boolean {
  if (!isCanonicalBase64(expected) || !isCanonicalBase64(actual)) return false;
  const left = Buffer.from(expected, 'base64');
  const right = Buffer.from(actual, 'base64');
  if (left.length !== right.length || left.length === 0) return false;
  return timingSafeEqual(left, right);
}

/** ADR-007 digest: domain tag, then canonical bytes, then SHA-256 as lowercase hex. */
export function digestFor(context: DomainTag, value: unknown): string {
  return sha256Hex(taggedBytes(context, value));
}

/** ADR-007 MAC: domain tag, then canonical bytes, then HMAC-SHA256 as base64. */
export function macFor(context: DomainTag, value: unknown, keyHex: string): string {
  return hmacSha256(keyHex, taggedBytes(context, value));
}
