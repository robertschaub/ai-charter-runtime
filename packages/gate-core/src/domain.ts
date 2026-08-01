// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ADR-007 — domain separation.
 *
 * Every digest and MAC is taken over `"ai-charter-runtime/v1/<context>\n"` followed by
 * the canonical bytes, so a digest is never valid in a context other than the one it was
 * computed for. The tag frames the hash input; it is not part of the canonical JSON.
 */
import { canonicalize } from './canonicalize.js';

export const DOMAIN_PREFIX = 'ai-charter-runtime/v1/' as const;

/** The thirteen contexts of ADR-007 (`card-revocation` is ADR-006's addition). */
export const DOMAIN_TAGS = [
  'proposal',
  'effect-intent',
  'record-entry',
  'access-entry',
  'wal-entry',
  'mandate-binding',
  'commit-token',
  'policy-set',
  'evaluator-build',
  'checkpoint',
  'checkpoint-composite',
  'model-card',
  'card-revocation',
] as const;

export type DomainTag = (typeof DOMAIN_TAGS)[number];

/** The three hash-chained streams of ADR-003, each with its own domain tag. */
export const CHAIN_DOMAIN_TAGS = ['wal-entry', 'record-entry', 'access-entry'] as const;
export type ChainDomainTag = (typeof CHAIN_DOMAIN_TAGS)[number];

export function isDomainTag(value: unknown): value is DomainTag {
  return typeof value === 'string' && (DOMAIN_TAGS as readonly string[]).includes(value);
}

export function isChainDomainTag(value: unknown): value is ChainDomainTag {
  return typeof value === 'string' && (CHAIN_DOMAIN_TAGS as readonly string[]).includes(value);
}

/** The exact prefix string that frames a digest or MAC input for `context`. */
export function domainPrefix(context: DomainTag): string {
  return `${DOMAIN_PREFIX}${context}\n`;
}

/** UTF-8 bytes of `domainPrefix(context)` followed by `canonicalize(value)`. */
export function taggedBytes(context: DomainTag, value: unknown): Buffer {
  if (!isDomainTag(context)) {
    throw new TypeError(`taggedBytes: unknown domain tag ${String(context)}`);
  }
  return Buffer.from(domainPrefix(context) + canonicalize(value), 'utf8');
}
