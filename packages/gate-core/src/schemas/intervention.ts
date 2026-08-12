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
export const safeDefault = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('stop-remains'),
      disposition: z.enum(['deny', 'seek-review', 'cancel', 'route-to-remedy', 'abstain']),
      authority_basis: z.object({ kind: z.literal('no-new-authority') }).strict(),
      reversible: z.literal(true),
    })
    .strict(),
  z
    .object({
      kind: z.literal('new-proposal'),
      disposition: z.enum(['narrow-or-modify', 'narrow']),
      authority_basis: z
        .object({
          kind: z.literal('mandate'),
          mandate_id: id,
          mandate_version: integer.min(1),
          service: id,
          action_class: classToken,
        })
        .strict(),
      reversible: z.literal(true),
    })
    .strict(),
]);

export const interventionContract = z
  .object({
    /** 1. Trigger and state. */
    trigger_and_state: z
      .object({
        trigger: classToken,
        state: classToken,
      })
      .strict(),
  /** 2. Decision and route — eligible role, competence/independence, substitute rule. */
    decision_and_route: z
      .object({
        eligible_role: role,
        /** Derived when the escalation is raised, from each item's `origin_actor`. */
        standing_class: standingClass,
        /** Declared, not verified — ADR-002 §8's stated limit. */
        competence_declared: z.string().min(1),
        independence_declared: z.string().min(1),
        /** Exact additional roles accepted by the authorization service. */
        substitute_roles: z
          .array(role)
          .default([])
          .refine((values) => new Set(values).size === values.length, 'substitute roles must be unique'),
        substitute_rule: z.string().min(1),
      })
      .strict(),
  /** 3. Decision basis shown. */
  decision_basis_shown: z.array(z.string()).min(1),
  /** 4. Response bound and default. Bounds come from the policy file, per escalation class. */
    response_bound_and_default: z
      .object({
        response_bound_ms: integer.min(1),
        safe_default: safeDefault,
      })
      .strict(),
  /** 5. Permitted dispositions. The console renders these; the endpoint is the authority. */
  permitted_dispositions: z
    .array(disposition)
    .min(1)
    .refine((values) => new Set(values).size === values.length, 'dispositions must be unique'),
  /** 6. Record and feedback consequences. */
    record_and_feedback: z
      .object({
        record_events: z.array(id).min(1),
        feedback_consequence: z.string().min(1),
      })
      .strict(),
  })
  .strict()
  .superRefine((contract, ctx) => {
    const general = contract.permitted_dispositions.filter((value) =>
      (GENERAL_DISPOSITIONS as readonly string[]).includes(value),
    );
    const dialogue = contract.permitted_dispositions.filter((value) =>
      (DIALOGUE_DISPOSITIONS as readonly string[]).includes(value),
    );
    if (general.length > 0 && dialogue.length > 0) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['permitted_dispositions'],
        message: 'general and dialogue dispositions must not be mixed in one escalation',
      });
    }
    if (contract.decision_and_route.substitute_roles.includes(contract.decision_and_route.eligible_role)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['decision_and_route', 'substitute_roles'],
        message: 'the eligible role must not also be listed as a substitute',
      });
    }
    const fallback = contract.response_bound_and_default.safe_default.disposition;
    if (!contract.permitted_dispositions.includes(fallback)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['response_bound_and_default', 'safe_default', 'disposition'],
        message: 'the declared timeout disposition must be permitted by this escalation',
      });
    }
    if (dialogue.length > 0 && fallback !== 'abstain' && fallback !== 'narrow') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['response_bound_and_default', 'safe_default', 'disposition'],
        message: 'a dialogue timeout may only abstain or narrow',
      });
    }
  });

export type InterventionContract = z.infer<typeof interventionContract>;
