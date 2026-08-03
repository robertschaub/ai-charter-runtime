// SPDX-License-Identifier: MIT
/** Orchestrator-owned, non-authoritative case mirror for ADR-004's two-hop polling. */
import { browserOrigin, id, rulingProjection, type ProposalRulingProjection, type RulingProjection } from 'gate-core';
import { z } from 'zod';

export const caseConsoleStateProjection = z
  .object({
    case_id: id,
    model_interaction_available: z.literal(false),
    ruling: rulingProjection.nullable(),
    dialogue: z
      .object({
        escalation_id: id,
        status: z.enum(['open', 'terminal']),
        response_url: z.string().url(),
      })
      .strict()
      .nullable(),
  })
  .strict();

export type CaseConsoleStateProjection = z.infer<typeof caseConsoleStateProjection>;

interface TrackedCaseRuling {
  readonly rulingId: string;
  readonly escalationId: string | null;
  readonly initial: RulingProjection;
}

export class CaseConsoleStateStore {
  readonly #tracked = new Map<string, TrackedCaseRuling>();

  track(caseIdInput: string, ruled: ProposalRulingProjection): void {
    const caseId = id.parse(caseIdInput);
    this.#tracked.set(caseId, {
      rulingId: ruled.ruling.ruling_id,
      escalationId: ruled.escalation_id,
      initial: ruled.ruling,
    });
  }

  tracked(caseIdInput: string): TrackedCaseRuling | null {
    const tracked = this.#tracked.get(id.parse(caseIdInput));
    return tracked === undefined ? null : { ...tracked };
  }

  project(
    caseIdInput: string,
    authorizationOriginInput: string,
    worldIdInput: string,
    currentRuling?: RulingProjection,
  ): CaseConsoleStateProjection {
    const caseId = id.parse(caseIdInput);
    const authorizationOrigin = browserOrigin.parse(authorizationOriginInput);
    const tracked = this.#tracked.get(caseId);
    const ruling = tracked === undefined ? null : rulingProjection.parse(currentRuling ?? tracked.initial);
    const escalationId = tracked?.escalationId ?? null;
    return caseConsoleStateProjection.parse({
      case_id: caseId,
      model_interaction_available: false,
      ruling,
      dialogue:
        escalationId === null || ruling === null
          ? null
          : {
              escalation_id: escalationId,
              status: ruling.status === 'issued' ? 'open' : 'terminal',
              response_url: `${authorizationOrigin}/console/dialogue/${worldIdInput}/${escalationId}`,
            },
    });
  }
}
