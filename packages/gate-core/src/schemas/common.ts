// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Shared primitives for the M1 data contracts.
 *
 * ADR-007's integer-only regime is enforced here rather than per-schema: amounts and
 * ceilings are integers in minor units (Rappen), timestamps are RFC 3339 UTC strings with
 * millisecond precision, and screening confidence is `confidence_pct`, an integer 0-100.
 * That removes floats from the data contracts entirely, so JCS's number-formatting edge
 * cases never arise — and a float reaching a schema is a build-time bug.
 */
import { z } from 'zod';

import { HEX64 } from '../hash.js';

/** ADR-007: every number in a contract is an integer. */
export const integer = z.number().int();

/** Amounts and ceilings, in minor units (Rappen). Never a float. */
export const minorUnits = integer;
export const nonNegativeMinorUnits = integer.min(0);

/** ADR-007: screening confidence is an integer percentage. */
export const confidencePct = integer.min(0).max(100);

/** RFC 3339 UTC with millisecond precision, e.g. `2026-08-01T09:32:14.512Z`. */
export const RFC3339_MS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
export const timestamp = z.string().regex(RFC3339_MS, 'expected RFC 3339 UTC with milliseconds');

/** Calendar date, the form ADR-006's card fields use (`valid_from`, `date`, `as_of`). */
export const ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
export const isoDate = z.string().regex(ISO_DATE, 'expected an ISO calendar date');

/** ADR-007: digests are lowercase hex, unprefixed (pattern shared with `hash.ts`). */
export const hexDigest = z.string().regex(HEX64, 'expected 64 lowercase hex characters');

/** ADR-007: keys and signatures are base64. */
export const base64 = z.string().regex(/^[A-Za-z0-9+/]+={0,2}$/, 'expected base64');

/** ADR-007: ids are lowercase ASCII. */
export const ID = /^[a-z0-9][a-z0-9_.:-]*$/;
export const id = z.string().regex(ID, 'expected a lowercase ascii id');

/**
 * A class label the sources name but never enumerate (risk class, reversibility class,
 * action class, ordering rule). Constrained to a lowercase token so junk still fails,
 * deliberately not turned into an invented closed vocabulary.
 */
export const classToken = z.string().regex(/^[a-z][a-z0-9-]*$/, 'expected a lowercase token');

/** ADR-002 §6: a world id is also a directory name. */
const WINDOWS_RESERVED = new Set([
  'con',
  'prn',
  'aux',
  'nul',
  ...Array.from({ length: 9 }, (_, index) => `com${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `lpt${index + 1}`),
]);

export const worldId = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]{0,31}$/, 'expected a world id of lowercase ascii, digits and hyphens')
  .refine((value) => !WINDOWS_RESERVED.has(value), 'world id must not be a Windows reserved device name');

/** ADR-006 §1: `<lane>-<requested id sanitized>`, lowercase `[a-z0-9.-]` only. */
export const cardSlug = z.string().regex(/^[a-z0-9][a-z0-9.-]*$/, 'expected a card slug');

/** ADR-006 §3: a provider-reported or requested model id. */
export const modelId = z.string().regex(/^[\x21-\x7e]+$/, 'expected a model id of printable ascii');

/** ADR-002 §2: the resolved credential label — never the token value. */
export const CREDENTIAL_LABELS = [
  'role:principal',
  'role:case_officer',
  'role:applicant',
  'proc:orchestrator',
  'proc:services_host',
  'proc:authz',
] as const;
export const credentialLabel = z.enum(CREDENTIAL_LABELS);

export const ROLES = ['principal', 'case_officer', 'applicant'] as const;
export const role = z.enum(ROLES);

/** ADR-002 §4: a claim by the calling process, never an input to an authority decision. */
export const claimedActor = z.object({
  role: role.nullable(),
  session: id.optional(),
});

/** A time window, evaluated lazily at decision time (ADR-001 §8). */
export const validityWindow = z.object({
  not_before: timestamp,
  not_after: timestamp,
});

/** ADR-007: an artifact verified on its own names its `alg` explicitly. */
export const macBlock = z.object({
  alg: z.literal('hmac-sha256'),
  key_id: id,
  value: base64,
});

export const signatureBlock = z.object({
  alg: z.literal('ed25519'),
  key_id: id,
  signature: base64,
});

/** Values that survive ADR-007 canonicalization: no floats, no dates, no class instances. */
export const jsonScalar = z.union([z.string(), integer, z.boolean(), z.null()]);
export const jsonScalarOrList = z.union([jsonScalar, z.array(jsonScalar)]);

/** ADR-005 §2 closed vocabulary, plus the one `recipient:provider:` sub-namespace. */
export const RESTRICTION_TAG_LITERALS = [
  'conf:public',
  'conf:case',
  'conf:sensitive',
  'purpose:grant-assessment',
  'recipient:officer',
  'recipient:applicant',
] as const;

/** `recipient:provider:<card-slug>`; the slug must name a card (ADR-006 §1 slug rule). */
export const PROVIDER_RECIPIENT_TAG = /^recipient:provider:[a-z0-9][a-z0-9.-]*$/;

/**
 * An unknown or malformed tag fails closed: the item becomes undisclosable everywhere and
 * raises an integrity alarm — it is never ignored (ADR-005 §2).
 */
export const restrictionTag = z.union([
  z.enum(RESTRICTION_TAG_LITERALS),
  z.string().regex(PROVIDER_RECIPIENT_TAG, 'expected recipient:provider:<card-slug>'),
]);

export type RestrictionTag = z.infer<typeof restrictionTag>;

/** True when the array is de-duplicated and in ADR-007's sort order. */
export function isSortedUnique(values: readonly string[]): boolean {
  for (let index = 1; index < values.length; index += 1) {
    const previous = values[index - 1] as string;
    const current = values[index] as string;
    if (previous >= current) return false;
  }
  return true;
}

/**
 * ADR-005 §3: a de-duplicated tag array sorted by ADR-007's rule. Canonicalization
 * preserves array order, so the producer must sort — an unsorted array would be a
 * different digest for the same tag set.
 */
export const sortedRestrictionTags = z
  .array(restrictionTag)
  .refine(isSortedUnique, 'tags must be de-duplicated and sorted by UTF-16 code unit');

/** A clearance set. Uniqueness is required; the sources do not require an order here. */
export const restrictionTagSet = z
  .array(restrictionTag)
  .refine((values) => new Set(values).size === values.length, 'clearance tags must be unique');

/** ADR-005 §5 / ADR-006 §4: clearances are role-scoped. */
export const MODEL_ROLES = ['acting', 'screening'] as const;
export const modelRole = z.enum(MODEL_ROLES);
export type ModelRole = (typeof MODEL_ROLES)[number];
