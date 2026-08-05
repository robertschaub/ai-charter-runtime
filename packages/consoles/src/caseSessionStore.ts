// SPDX-License-Identifier: MIT
/** Orchestrator-local browser sessions. Raw bearers are returned once and never stored. */
import { randomBytes, randomUUID } from 'node:crypto';

import { browserOrigin, id, sha256Hex, timestamp, worldId } from 'gate-core';
import { z } from 'zod';

const MAX_SESSION_TTL_MS = 15 * 60 * 1_000;

export const caseSessionClaim = z
  .object({
    handoff_id: id,
    role: z.literal('case_officer'),
    world_id: worldId,
    case_id: id,
    target_origin: browserOrigin,
    authorization_boot_id: id,
    consumed_at: timestamp,
  })
  .strict();
export type CaseSessionClaim = z.infer<typeof caseSessionClaim>;

export interface CaseSessionRecord {
  readonly session_id: string;
  readonly token_digest: string;
  readonly handoff_id: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly target_origin: string;
  readonly authorization_boot_id: string;
  readonly created_at: string;
  readonly expires_at: string;
  state: 'active' | 'closed';
}

export interface CreatedCaseSession {
  readonly session_token: string;
  readonly session_id: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly expires_at: string;
}

export interface CaseSessionStoreOptions {
  readonly ttlMs?: number;
  readonly now?: () => string;
  readonly randomToken?: () => string;
  readonly nextSessionId?: () => string;
}

export class CaseSessionStore {
  readonly #sessions = new Map<string, CaseSessionRecord>();
  readonly #ttlMs: number;
  readonly #now: () => string;
  readonly #randomToken: () => string;
  readonly #nextSessionId: () => string;

  constructor(options: CaseSessionStoreOptions = {}) {
    this.#ttlMs = options.ttlMs ?? MAX_SESSION_TTL_MS;
    if (!Number.isInteger(this.#ttlMs) || this.#ttlMs < 1 || this.#ttlMs > MAX_SESSION_TTL_MS) {
      throw new RangeError('case session TTL must be an integer from 1 through 900000 milliseconds');
    }
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#randomToken = options.randomToken ?? (() => randomBytes(32).toString('hex'));
    this.#nextSessionId = options.nextSessionId ?? (() => `session_${randomUUID().replaceAll('-', '')}`);
  }

  #expire(at: string): void {
    for (const [digest, session] of this.#sessions) {
      if (session.expires_at <= at) this.#sessions.delete(digest);
    }
  }

  create(input: CaseSessionClaim): CreatedCaseSession {
    const claim = caseSessionClaim.parse(input);
    const at = timestamp.parse(this.#now());
    this.#expire(at);
    const rawToken = this.#randomToken();
    if (!/^[0-9a-f]{64,}$/.test(rawToken)) {
      throw new RangeError('case-session token source must provide at least 32 bytes as lowercase hex');
    }
    const digest = sha256Hex(rawToken);
    if (this.#sessions.has(digest)) throw new Error('case-session token source repeated a value');
    const sessionId = id.parse(this.#nextSessionId());
    const expiresAt = new Date(Date.parse(at) + this.#ttlMs).toISOString();
    this.#sessions.set(digest, {
      session_id: sessionId,
      token_digest: digest,
      handoff_id: claim.handoff_id,
      role: claim.role,
      world_id: claim.world_id,
      case_id: claim.case_id,
      target_origin: claim.target_origin,
      authorization_boot_id: claim.authorization_boot_id,
      created_at: at,
      expires_at: expiresAt,
      state: 'active',
    });
    return {
      session_token: rawToken,
      session_id: sessionId,
      role: claim.role,
      world_id: claim.world_id,
      case_id: claim.case_id,
      expires_at: expiresAt,
    };
  }

  authenticate(rawToken: string, world: string, caseId?: string): CaseSessionRecord | null {
    if (!/^[0-9a-f]{64,}$/.test(rawToken)) return null;
    const at = timestamp.parse(this.#now());
    this.#expire(at);
    const session = this.#sessions.get(sha256Hex(rawToken));
    if (
      session === undefined ||
      session.state !== 'active' ||
      session.world_id !== world ||
      (caseId !== undefined && session.case_id !== caseId)
    ) {
      return null;
    }
    return { ...session };
  }

  close(rawToken: string, world: string): boolean {
    const session = this.authenticate(rawToken, world);
    if (session === null) return false;
    const digest = sha256Hex(rawToken);
    const stored = this.#sessions.get(digest);
    if (stored === undefined) return false;
    stored.state = 'closed';
    return true;
  }

  snapshot(): readonly CaseSessionRecord[] {
    this.#expire(timestamp.parse(this.#now()));
    return [...this.#sessions.values()].map((session) => ({ ...session }));
  }
}
