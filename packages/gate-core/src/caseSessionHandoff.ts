// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-002 durable, boot-bound, single-use browser handoff lifecycle. */
import { randomBytes, randomUUID } from 'node:crypto';

import { sha256Hex, verifyDigest } from './hash.js';
import {
  browserOrigin,
  caseSessionHandoffRecord,
  id,
  worldId,
  type CaseSessionHandoffRecord,
  type WalOp,
} from './schemas/index.js';
import type { TransactionActor, WalStore } from './walStore.js';

const MINT_ACTOR: TransactionActor['credential'] = 'role:case_officer';
const REDEEM_ACTOR: TransactionActor['credential'] = 'proc:orchestrator';
const MAINTENANCE_ACTOR: TransactionActor = { credential: 'proc:authz', claimed_role: null };
const DEFAULT_TTL_MS = 30_000;
const MAX_TTL_MS = 30_000;

export interface CaseSessionHandoffServiceOptions {
  readonly store: WalStore;
  readonly worldId: string;
  readonly authorizationBootId: string;
  readonly targetOrigin: string;
  readonly caseExists: (caseId: string) => boolean;
  readonly ttlMs?: number;
  readonly randomCode?: () => string;
  readonly nextHandoffId?: () => string;
}

export interface MintedCaseSessionHandoff {
  readonly handoff_id: string;
  readonly handoff_code: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly target_origin: string;
  readonly authorization_boot_id: string;
  readonly expires_at: string;
}

export interface RedeemCaseSessionHandoffInput {
  readonly handoff_id: string;
  readonly handoff_code: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly target_origin: string;
  readonly authorization_boot_id: string;
}

export interface RedeemedCaseSessionClaim {
  readonly handoff_id: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly target_origin: string;
  readonly authorization_boot_id: string;
  readonly consumed_at: string;
}

export class CaseSessionHandoffError extends Error {
  constructor(readonly code: 'actor-refused' | 'case-refused' | 'handoff-refused') {
    super(code);
    this.name = 'CaseSessionHandoffError';
  }
}

function assertActor(actor: TransactionActor, expected: TransactionActor['credential']): void {
  if (actor.credential !== expected) throw new CaseSessionHandoffError('actor-refused');
  if (expected === MINT_ACTOR && actor.claimed_role !== 'case_officer') {
    throw new CaseSessionHandoffError('actor-refused');
  }
  if (expected === REDEEM_ACTOR && actor.claimed_role !== null) {
    throw new CaseSessionHandoffError('actor-refused');
  }
}

function shouldExpire(handoff: CaseSessionHandoffRecord, bootId: string, at: string): boolean {
  return handoff.state === 'issued' && (handoff.authorization_boot_id !== bootId || handoff.expires_at <= at);
}

function expiryOps(
  handoffs: ReadonlyMap<string, CaseSessionHandoffRecord>,
  bootId: string,
  at: string,
): WalOp[] {
  return [...handoffs.values()]
    .filter((handoff) => shouldExpire(handoff, bootId, at))
    .map((handoff) => ({ op: 'case_session_handoff.expire' as const, handoff_id: handoff.handoff_id }));
}

export class CaseSessionHandoffService {
  readonly #store: WalStore;
  readonly #worldId: string;
  readonly #bootId: string;
  readonly #targetOrigin: string;
  readonly #caseExists: (caseId: string) => boolean;
  readonly #ttlMs: number;
  readonly #randomCode: () => string;
  readonly #nextHandoffId: () => string;

  constructor(options: CaseSessionHandoffServiceOptions) {
    this.#store = options.store;
    this.#worldId = worldId.parse(options.worldId);
    this.#bootId = id.parse(options.authorizationBootId);
    this.#targetOrigin = browserOrigin.parse(options.targetOrigin);
    this.#caseExists = options.caseExists;
    this.#ttlMs = options.ttlMs ?? DEFAULT_TTL_MS;
    if (!Number.isInteger(this.#ttlMs) || this.#ttlMs < 1 || this.#ttlMs > MAX_TTL_MS) {
      throw new RangeError('case-session handoff TTL must be an integer from 1 through 30000 milliseconds');
    }
    this.#randomCode = options.randomCode ?? (() => randomBytes(32).toString('hex'));
    this.#nextHandoffId = options.nextHandoffId ?? (() => `handoff_${randomUUID().replaceAll('-', '')}`);
  }

  async expireIssued(): Promise<number> {
    const completed = await this.#store.transactWithState('case_session_handoff_expire', MAINTENANCE_ACTOR, (state, at) => {
      const ops = expiryOps(state.caseSessionHandoffs, this.#bootId, at);
      return { ops, result: ops.length };
    });
    return completed.result;
  }

  async mint(caseId: string, actor: TransactionActor): Promise<MintedCaseSessionHandoff> {
    assertActor(actor, MINT_ACTOR);
    const parsedCaseId = id.parse(caseId);
    if (!this.#caseExists(parsedCaseId)) throw new CaseSessionHandoffError('case-refused');
    const handoffId = id.parse(this.#nextHandoffId());
    const rawCode = this.#randomCode();
    if (!/^[0-9a-f]{64,}$/.test(rawCode)) {
      throw new RangeError('case-session handoff code source must provide at least 32 bytes as lowercase hex');
    }

    await this.#store.transactWithState('case_session_handoff_mint', actor, (state, at) => {
      const expiresAt = new Date(Date.parse(at) + this.#ttlMs).toISOString();
      const handoff = caseSessionHandoffRecord.parse({
        world_id: this.#worldId,
        handoff_id: handoffId,
        case_id: parsedCaseId,
        role: 'case_officer',
        target_origin: this.#targetOrigin,
        authorization_boot_id: this.#bootId,
        code_digest: sha256Hex(rawCode),
        created_at: at,
        expires_at: expiresAt,
        consumed_at: null,
        state: 'issued',
      });
      return {
        ops: [...expiryOps(state.caseSessionHandoffs, this.#bootId, at), { op: 'case_session_handoff.issue', handoff }],
        result: undefined,
      };
    });

    const snapshot = this.#store.snapshot().caseSessionHandoffs.get(handoffId);
    if (snapshot === undefined) throw new Error('durable handoff issue did not materialize');
    return {
      handoff_id: handoffId,
      handoff_code: rawCode,
      role: 'case_officer',
      world_id: this.#worldId,
      case_id: parsedCaseId,
      target_origin: this.#targetOrigin,
      authorization_boot_id: this.#bootId,
      expires_at: snapshot.expires_at,
    };
  }

  async redeem(input: RedeemCaseSessionHandoffInput, actor: TransactionActor): Promise<RedeemedCaseSessionClaim> {
    assertActor(actor, REDEEM_ACTOR);
    const handoffId = id.parse(input.handoff_id);
    const suppliedDigest = sha256Hex(input.handoff_code);
    const completed = await this.#store.transactWithState<
      | { readonly accepted: false }
      | { readonly accepted: true; readonly claim: RedeemedCaseSessionClaim }
    >('case_session_handoff_redeem', actor, (state, at) => {
      const current = state.caseSessionHandoffs.get(handoffId);
      const ops = expiryOps(state.caseSessionHandoffs, this.#bootId, at);
      const expiringTarget = ops.some(
        (op) => op.op === 'case_session_handoff.expire' && op.handoff_id === handoffId,
      );
      if (
        current === undefined ||
        current.state !== 'issued' ||
        expiringTarget ||
        current.world_id !== input.world_id ||
        current.case_id !== input.case_id ||
        current.role !== input.role ||
        current.target_origin !== input.target_origin ||
        current.authorization_boot_id !== input.authorization_boot_id ||
        !verifyDigest(current.code_digest, suppliedDigest)
      ) {
        return { ops, result: { accepted: false } };
      }
      const claim: RedeemedCaseSessionClaim = {
        handoff_id: current.handoff_id,
        role: current.role,
        world_id: current.world_id,
        case_id: current.case_id,
        target_origin: current.target_origin,
        authorization_boot_id: current.authorization_boot_id,
        consumed_at: at,
      };
      return {
        ops: [...ops, { op: 'case_session_handoff.consume', handoff_id: handoffId, consumed_at: at }],
        result: { accepted: true, claim },
      };
    });
    if (!completed.result.accepted) throw new CaseSessionHandoffError('handoff-refused');
    return completed.result.claim;
  }
}
