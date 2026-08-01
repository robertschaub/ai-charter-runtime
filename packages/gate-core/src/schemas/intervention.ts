// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Human-intervention contract — spec §4 (the six fields of the reference model),
 * ADR-001 §7 (disposition map), ADR-004 §5 (standing classes and the bare-confirm refusal).
 *
 * All six fields are required: "an escalation whose six intervention-contract fields are
 * not all present refuses to fire" (ADR-001 §7).
 */
import { z } from 'zod';

import { classToken, id, integer, role } from './common.js';

/** ADR-001 §7 — the general disposition set. */
export const GENERAL_DISPOSITIONS = [
  'allow-within-scope',
  'deny',
  'narrow-or-modify',
  'seek-review',
  'cancel',
  'reverse',
  'route-to-remedy',
] as const;

/** ADR-004 §4 — the dialogue disposition set, extended with `route` (flagged deviation). */
export const DIALOGUE_DISPOSITIONS = ['confirm', 'correct', 'narrow', 'permit', 'abstain', 'route'] as const;

export const DISPOSITIONS = [...GENERAL_DISPOSITIONS, ...DIALOGUE_DISPOSITIONS] as const;
export const disposition = z.enum(DISPOSITIONS);
export type Disposition = (typeof DISPOSITIONS)[number];

export const generalDisposition = z.enum(GENERAL_DISPOSITIONS);
export const dialogueDisposition = z.enum(DIALOGUE_DISPOSITIONS);

/** ADR-004 §5: standing is evidentiary, not managerial. */
export const STANDING_CLASSES = [
  'own-testimony',
  'own-interpretation',
  'own-permission',
  'third-party-fact',
] as const;
export const standingClass = z.enum(STANDING_CLASSES);
export type StandingClass = (typeof STANDING_CLASSES)[number];

/**
 * The declared fallback must itself lie within existing authority; the contract names the
 * fallback's authority basis (spec §5). Timeout never creates new authority, and for a
 * dialogue escalation the default is `abstain` or `narrow` — never proceed (ADR-004 §6).
 */
export const safeDefault = z.object({
  disposition,
  authority_basis: z.string().min(1),
  reversible: z.boolean(),
});

export const interventionContract = z.object({
  /** 1. Trigger and state. */
  trigger_and_state: z.object({
    trigger: classToken,
    state: classToken,
  }),
  /** 2. Decision and route — eligible role, competence/independence, substitute rule. */
  decision_and_route: z.object({
    eligible_role: role,
    /** Derived when the escalation is raised, from each item's `origin_actor`. */
    standing_class: standingClass,
    /** Declared, not verified — ADR-002 §8's stated limit. */
    competence_declared: z.string().min(1),
    independence_declared: z.string().min(1),
    substitute_rule: z.string().min(1),
  }),
  /** 3. Decision basis shown. */
  decision_basis_shown: z.array(z.string()).min(1),
  /** 4. Response bound and default. Bounds come from the policy file, per escalation class. */
  response_bound_and_default: z.object({
    response_bound_ms: integer.min(1),
    safe_default: safeDefault,
  }),
  /** 5. Permitted dispositions. The console renders these; the endpoint is the authority. */
  permitted_dispositions: z
    .array(disposition)
    .min(1)
    .refine((values) => new Set(values).size === values.length, 'dispositions must be unique'),
  /** 6. Record and feedback consequences. */
  record_and_feedback: z.object({
    record_events: z.array(id).min(1),
    feedback_consequence: z.string().min(1),
  }),
});

export type InterventionContract = z.infer<typeof interventionContract>;
