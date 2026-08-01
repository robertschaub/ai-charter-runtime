// SPDX-License-Identifier: MIT
/** Executing-service boundary: verify again, then atomically record exactly one mock effect. */
import {
  closeSync,
  existsSync,
  fsyncSync,
  linkSync,
  mkdirSync,
  openSync,
  readFileSync,
  readdirSync,
  unlinkSync,
  writeSync,
} from 'node:fs';
import { join, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';

import {
  canonicalize,
  effectIntent,
  hexDigest,
  id,
  timestamp,
  verifyCommitTokenBinding,
  verifyCommitTokenForIntent,
  worldId,
  type CommitToken,
  type EffectIntent,
  type Keyring,
} from 'gate-core';
import { z } from 'zod';

export const serviceEffectRecord = z
  .object({
    version: z.literal(1),
    world_id: worldId,
    services_host_boot_id: id,
    idempotency_key: hexDigest,
    effect_id: id,
    ruling_id: id,
    frozen_proposal_hash: hexDigest,
    effect_request_digest: hexDigest,
    service: id,
    action_class: z.string().regex(/^[a-z][a-z0-9-]*$/),
    intent: effectIntent,
    outcome: z.enum(['success', 'failed']),
    recorded_at: timestamp,
    detail: z.string().min(1).optional(),
  })
  .strict();

export type ServiceEffectRecord = z.infer<typeof serviceEffectRecord>;

export interface EffectLedgerOptions {
  readonly recordsRoot: string;
  readonly worldId: string;
  readonly bootId: string;
  readonly keyring: Keyring;
  readonly now?: () => string;
}

export interface ProposedEffectOutcome {
  readonly outcome: 'success' | 'failed';
  readonly detail?: string;
}

export type ExecuteEffectResult =
  | {
      readonly accepted: false;
      readonly reason: 'malformed' | 'invalid-mac' | 'expired' | 'binding-mismatch';
    }
  | {
      readonly accepted: true;
      readonly delivery: 'executed' | 'retry';
      readonly record: ServiceEffectRecord;
    };

export type EffectProbe =
  | { readonly state: 'recorded'; readonly boot_id: string; readonly record: ServiceEffectRecord }
  | { readonly state: 'absent'; readonly boot_id: string };

export class EffectLedgerError extends Error {
  constructor(
    readonly code: 'corrupt-ledger' | 'ledger-binding-mismatch' | 'atomic-commit-failed',
    message: string,
  ) {
    super(message);
    this.name = 'EffectLedgerError';
  }
}

function writeAll(fd: number, bytes: Buffer): void {
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset, offset);
    if (written <= 0) throw new Error('write returned no progress');
    offset += written;
  }
}

function sameBinding(record: ServiceEffectRecord, token: CommitToken, intent: EffectIntent): boolean {
  return (
    record.world_id === token.world_id &&
    record.idempotency_key === token.idempotency_key &&
    record.effect_id === token.effect_id &&
    record.ruling_id === token.ruling_id &&
    record.frozen_proposal_hash === token.frozen_proposal_hash &&
    record.effect_request_digest === token.effect_request_digest &&
    record.service === token.service &&
    record.action_class === token.action_class &&
    canonicalize(record.intent) === canonicalize(intent)
  );
}

function sameRecordBinding(left: ServiceEffectRecord, right: ServiceEffectRecord): boolean {
  return (
    left.world_id === right.world_id &&
    left.idempotency_key === right.idempotency_key &&
    left.effect_id === right.effect_id &&
    left.ruling_id === right.ruling_id &&
    left.frozen_proposal_hash === right.frozen_proposal_hash &&
    left.effect_request_digest === right.effect_request_digest &&
    left.service === right.service &&
    left.action_class === right.action_class &&
    canonicalize(left.intent) === canonicalize(right.intent)
  );
}

export class EffectLedger {
  readonly #directory: string;
  readonly #worldId: string;
  readonly #bootId: string;
  readonly #keyring: Keyring;
  readonly #now: () => string;

  constructor(options: EffectLedgerOptions) {
    this.#worldId = worldId.parse(options.worldId);
    this.#bootId = id.parse(options.bootId);
    this.#keyring = options.keyring;
    this.#now = options.now ?? (() => new Date().toISOString());
    this.#directory = resolve(options.recordsRoot, this.#worldId, 'effects');
    mkdirSync(this.#directory, { recursive: true });
    this.#removeStaleTemps();
  }

  get bootId(): string {
    return this.#bootId;
  }

  execute(
    tokenInput: unknown,
    intentInput: unknown,
    produceOutcome: (intent: EffectIntent) => ProposedEffectOutcome,
  ): ExecuteEffectResult {
    const binding = verifyCommitTokenBinding(this.#keyring, tokenInput, intentInput);
    if (!binding.valid) return { accepted: false, reason: binding.reason };
    if (binding.token.world_id !== this.#worldId) {
      return { accepted: false, reason: 'binding-mismatch' };
    }

    const existing = this.#read(binding.token.idempotency_key);
    if (existing !== undefined) {
      this.#assertBinding(existing, binding.token, binding.intent);
      return { accepted: true, delivery: 'retry', record: existing };
    }

    const now = timestamp.parse(this.#now());
    const current = verifyCommitTokenForIntent(this.#keyring, tokenInput, intentInput, now);
    if (!current.valid) return { accepted: false, reason: current.reason };

    const proposed = produceOutcome(current.intent);
    const record = serviceEffectRecord.parse({
      version: 1,
      world_id: this.#worldId,
      services_host_boot_id: this.#bootId,
      idempotency_key: current.token.idempotency_key,
      effect_id: current.token.effect_id,
      ruling_id: current.token.ruling_id,
      frozen_proposal_hash: current.token.frozen_proposal_hash,
      effect_request_digest: current.token.effect_request_digest,
      service: current.token.service,
      action_class: current.token.action_class,
      intent: current.intent,
      outcome: proposed.outcome,
      recorded_at: now,
      ...(proposed.detail === undefined ? {} : { detail: proposed.detail }),
    });
    return this.#commit(record);
  }

  probe(idempotencyKeyInput: unknown): EffectProbe {
    const key = hexDigest.parse(idempotencyKeyInput);
    const record = this.#read(key);
    return record === undefined
      ? { state: 'absent', boot_id: this.#bootId }
      : { state: 'recorded', boot_id: this.#bootId, record };
  }

  #path(key: string): string {
    return join(this.#directory, `${key}.json`);
  }

  #read(key: string): ServiceEffectRecord | undefined {
    const path = this.#path(key);
    if (!existsSync(path)) return undefined;
    try {
      return serviceEffectRecord.parse(JSON.parse(readFileSync(path, 'utf8')));
    } catch {
      throw new EffectLedgerError('corrupt-ledger', `effect ledger entry ${key} is not valid`);
    }
  }

  #assertBinding(record: ServiceEffectRecord, token: CommitToken, intent: EffectIntent): void {
    if (!sameBinding(record, token, intent)) {
      throw new EffectLedgerError(
        'ledger-binding-mismatch',
        `effect ledger entry ${record.idempotency_key} does not match the presented commitment`,
      );
    }
  }

  #commit(record: ServiceEffectRecord): ExecuteEffectResult {
    const finalPath = this.#path(record.idempotency_key);
    const tempPath = join(this.#directory, `${record.idempotency_key}.${randomUUID()}.tmp`);
    let tempExists = false;
    try {
      const bytes = Buffer.from(`${canonicalize(record)}\n`, 'utf8');
      const fd = openSync(tempPath, 'wx', 0o600);
      tempExists = true;
      try {
        writeAll(fd, bytes);
        fsyncSync(fd);
      } finally {
        closeSync(fd);
      }

      try {
        // A hard link is a create-only atomic directory-entry commit on NTFS and POSIX.
        // Unlike rename(), it cannot overwrite an existing idempotency record on Windows.
        linkSync(tempPath, finalPath);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        const winner = this.#read(record.idempotency_key);
        if (winner === undefined) {
          throw new EffectLedgerError('atomic-commit-failed', 'the winning ledger entry disappeared');
        }
        if (!sameRecordBinding(winner, record)) {
          throw new EffectLedgerError(
            'ledger-binding-mismatch',
            `effect ledger entry ${record.idempotency_key} was won by another commitment`,
          );
        }
        return { accepted: true, delivery: 'retry', record: winner };
      }

      // Windows rejects FlushFileBuffers on a read-only handle. Reopen read/write so
      // fsync covers the final directory entry's file metadata after the atomic link.
      const finalFd = openSync(finalPath, 'r+');
      try {
        fsyncSync(finalFd);
      } finally {
        closeSync(finalFd);
      }
      return { accepted: true, delivery: 'executed', record };
    } catch (error) {
      if (error instanceof EffectLedgerError) throw error;
      throw new EffectLedgerError(
        'atomic-commit-failed',
        `could not commit effect ledger entry ${record.idempotency_key}: ${(error as NodeJS.ErrnoException).code ?? 'unknown-io-error'}`,
      );
    } finally {
      if (tempExists && existsSync(tempPath)) unlinkSync(tempPath);
    }
  }

  #removeStaleTemps(): void {
    for (const name of readdirSync(this.#directory)) {
      if (name.endsWith('.tmp')) unlinkSync(join(this.#directory, name));
    }
  }
}
