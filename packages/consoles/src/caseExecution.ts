// SPDX-License-Identifier: MIT
/** Ephemeral orchestrator wrapper for the two-gesture M6.2 execution continuation. */
import {
  browserExecutionPreparation,
  executionPreparationProjection,
  type ExecutionPreparationProjection,
} from 'gate-core';

import type { CaseSessionRecord } from './caseSessionStore.js';

interface LocalExecutionPreparation {
  readonly executionPreparationId: string;
  readonly proposalRunId: string;
  readonly sessionId: string;
  readonly worldId: string;
  readonly caseId: string;
  readonly authorizationBootId: string;
  readonly expiresAt: string;
}

export class CaseExecutionStore {
  readonly #byId = new Map<string, LocalExecutionPreparation>();
  readonly #now: () => string;

  constructor(now: () => string = () => new Date().toISOString()) {
    this.#now = now;
  }

  register(session: CaseSessionRecord, input: ExecutionPreparationProjection) {
    const preparation = executionPreparationProjection.parse(input);
    this.expire();
    const current = this.#byId.get(preparation.execution_preparation_id);
    if (current !== undefined && !this.#sameSession(current, session)) throw new Error('execution-preparation-conflict');
    const record: LocalExecutionPreparation = {
      executionPreparationId: preparation.execution_preparation_id,
      proposalRunId: preparation.proposal_run_id,
      sessionId: session.session_id,
      worldId: session.world_id,
      caseId: session.case_id,
      authorizationBootId: session.authorization_boot_id,
      expiresAt: preparation.expires_at,
    };
    this.#byId.set(record.executionPreparationId, record);
    return browserExecutionPreparation.parse({
      execution_preparation_id: record.executionPreparationId,
      proposal_run_id: record.proposalRunId,
      state: 'prepared',
      expires_at: record.expiresAt,
    });
  }

  begin(preparationId: string, proposalRunId: string, session: CaseSessionRecord): LocalExecutionPreparation | null {
    this.expire();
    const record = this.#byId.get(preparationId);
    if (record === undefined || record.proposalRunId !== proposalRunId || !this.#sameSession(record, session)) return null;
    // Consume before the dependency call: a lost response cannot cause automatic replay.
    this.#byId.delete(preparationId);
    return record;
  }

  canConsume(preparationId: string, proposalRunId: string, session: CaseSessionRecord): boolean {
    this.expire();
    const record = this.#byId.get(preparationId);
    return record !== undefined && record.proposalRunId === proposalRunId && this.#sameSession(record, session);
  }

  burnForSession(sessionId: string): void {
    for (const [preparationId, record] of this.#byId) {
      if (record.sessionId === sessionId) this.#byId.delete(preparationId);
    }
  }

  expire(): void {
    const now = this.#now();
    for (const [preparationId, record] of this.#byId) {
      if (record.expiresAt <= now) this.#byId.delete(preparationId);
    }
  }

  clear(): void {
    this.#byId.clear();
  }

  #sameSession(record: LocalExecutionPreparation, session: CaseSessionRecord): boolean {
    return record.sessionId === session.session_id && record.worldId === session.world_id &&
      record.caseId === session.case_id && record.authorizationBootId === session.authorization_boot_id;
  }
}
