// SPDX-License-Identifier: AGPL-3.0-only
/** Durable per-world WAL, replay, materialized record chains, and transaction boundary. */
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

import { canonicalize } from './canonicalize.js';
import { DurableChainWriter, repairTornTail } from './chain.js';
import type { AppendedEntry, ChainHead } from './chain.js';
import type { ChainDomainTag } from './domain.js';
import {
  applyWorldTransaction,
  cloneWorldState,
  createWorldState,
  type WorldState,
} from './state.js';
import {
  walGenesisHeader,
  walLine,
  walRunHeader,
  walTransaction,
  timestamp as timestampSchema,
  worldId,
  type WalLine,
  type WalOp,
  type WalTransaction,
} from './schemas/index.js';
import { withWorldLock } from './worldLock.js';
import { WriterLease } from './writerLease.js';

export interface WalStoreOptions {
  readonly recordsRoot: string;
  readonly worldId: string;
  readonly runId: string;
  readonly bootId: string;
  readonly policyVersion: string;
  readonly policyContentDigest: string;
  readonly evaluatorBuildDigest: string;
  /** Startup recovery may verify ADR-003 before the new run header is appended. */
  readonly deferRunHeader?: boolean;
  readonly now?: () => string;
  readonly pid?: number;
}

export interface TransactionActor {
  readonly credential:
    | 'role:principal'
    | 'role:case_officer'
    | 'role:applicant'
    | 'proc:orchestrator'
    | 'proc:services_host'
    | 'proc:authz';
  readonly claimed_role: 'principal' | 'case_officer' | 'applicant' | null;
}

export interface TransactionBuild<T> {
  readonly ops: readonly WalOp[];
  readonly result: T;
}

export interface TransactionResult<T> {
  /** Null when a state-dependent transaction found no transition to record. */
  readonly appended: AppendedEntry | null;
  readonly result: T;
}

export interface WalStoreChainHeads {
  readonly wal: ChainHead;
  readonly action: ChainHead;
  readonly access: ChainHead;
}

export class WalStoreError extends Error {
  constructor(
    readonly code:
      | 'malformed-wal'
      | 'clock-regression'
      | 'poisoned'
      | 'closed'
      | 'projection-diverged'
      | 'run-not-started',
    message: string,
  ) {
    super(message);
    this.name = 'WalStoreError';
  }
}

interface StoredEnvelope extends Record<string, unknown> {
  seq: number;
  prev_hash: string;
  entry_hash: string;
}

function authoredBody(envelope: StoredEnvelope): Record<string, unknown> {
  const { seq: ignoredSeq, prev_hash: ignoredPrev, entry_hash: ignoredHash, ...body } = envelope;
  void ignoredSeq;
  void ignoredPrev;
  void ignoredHash;
  return body;
}

function readStoredBodies(file: string): Record<string, unknown>[] {
  if (!existsSync(file)) return [];
  const raw = readFileSync(file, 'utf8');
  if (raw.length === 0) return [];
  return raw
    .split('\n')
    .slice(0, -1)
    .map((line) => authoredBody(JSON.parse(line) as StoredEnvelope));
}

function parseWal(file: string, worldId: string): { lines: WalLine[]; lastTimestamp: string | undefined } {
  const bodies = readStoredBodies(file);
  const lines: WalLine[] = [];
  let lastTimestamp: string | undefined;
  for (const [index, body] of bodies.entries()) {
    const parsed = walLine.safeParse(body);
    if (!parsed.success) {
      throw new WalStoreError('malformed-wal', `WAL line ${index} is not a valid v2 line: ${parsed.error.message}`);
    }
    if (parsed.data.world_id !== worldId) {
      throw new WalStoreError('malformed-wal', `WAL line ${index} belongs to ${parsed.data.world_id}`);
    }
    const timestamp = parsed.data.kind === 'genesis' ? parsed.data.created_at : parsed.data.ts;
    if (lastTimestamp !== undefined && timestamp < lastTimestamp) {
      throw new WalStoreError('clock-regression', `WAL line ${index} moves backwards from ${lastTimestamp} to ${timestamp}`);
    }
    lastTimestamp = timestamp;
    lines.push(parsed.data);
  }
  if (lines.length > 0 && lines[0]?.kind !== 'genesis') {
    throw new WalStoreError('malformed-wal', 'WAL line 0 must be the genesis header');
  }
  if (lines.slice(1).some((line) => line.kind === 'genesis')) {
    throw new WalStoreError('malformed-wal', 'WAL contains more than one genesis header');
  }
  return { lines, lastTimestamp };
}

function replay(lines: readonly WalLine[], worldId: string): WorldState {
  const state = createWorldState(worldId);
  for (const line of lines) {
    if (line.kind === 'transaction') applyWorldTransaction(state, line.ops, line.ts);
  }
  return state;
}

function assertProjectionPrefix(
  file: string,
  expected: readonly Record<string, unknown>[],
): number {
  const existing = readStoredBodies(file);
  if (existing.length > expected.length) {
    throw new WalStoreError('projection-diverged', `${file} is longer than its authoritative WAL projection`);
  }
  for (let index = 0; index < existing.length; index += 1) {
    if (canonicalize(existing[index]) !== canonicalize(expected[index])) {
      throw new WalStoreError('projection-diverged', `${file} diverges from the WAL at entry ${index}`);
    }
  }
  return existing.length;
}

function materializeProjection(
  file: string,
  domain: ChainDomainTag,
  expected: readonly Record<string, unknown>[],
): DurableChainWriter {
  repairTornTail(file, domain);
  const existingLength = assertProjectionPrefix(file, expected);
  const writer = new DurableChainWriter(file, domain);
  for (let index = existingLength; index < expected.length; index += 1) {
    writer.append(expected[index] as Record<string, unknown>);
  }
  return writer;
}

export class WalStore {
  readonly #options: Required<Pick<WalStoreOptions, 'now' | 'pid'>> & WalStoreOptions;
  readonly #lease: WriterLease;
  readonly #walWriter: DurableChainWriter;
  readonly #actionWriter: DurableChainWriter;
  readonly #accessWriter: DurableChainWriter;
  #state: WorldState;
  #lastWalTimestamp: string;
  readonly #genesisTimestamp: string | null;
  #runStarted: boolean;
  #closed = false;
  #poisoned = false;

  private constructor(
    options: Required<Pick<WalStoreOptions, 'now' | 'pid'>> & WalStoreOptions,
    lease: WriterLease,
    walWriter: DurableChainWriter,
    actionWriter: DurableChainWriter,
    accessWriter: DurableChainWriter,
    state: WorldState,
    lastWalTimestamp: string,
    genesisTimestamp: string | null,
    runStarted: boolean,
  ) {
    this.#options = options;
    this.#lease = lease;
    this.#walWriter = walWriter;
    this.#actionWriter = actionWriter;
    this.#accessWriter = accessWriter;
    this.#state = state;
    this.#lastWalTimestamp = lastWalTimestamp;
    this.#genesisTimestamp = genesisTimestamp;
    this.#runStarted = runStarted;
  }

  static open(input: WalStoreOptions): WalStore {
    // Validate the directory key before it reaches `join`; a malformed world id must not
    // escape the configured records root even transiently through a lock-file create.
    const options = {
      ...input,
      worldId: worldId.parse(input.worldId),
      now: input.now ?? (() => new Date().toISOString()),
      pid: input.pid ?? process.pid,
    };
    const worldDir = join(options.recordsRoot, options.worldId);
    const lease = new WriterLease(join(worldDir, '.writer.lock'), options.pid, options.bootId);
    let walWriter: DurableChainWriter | undefined;
    let actionWriter: DurableChainWriter | undefined;
    let accessWriter: DurableChainWriter | undefined;
    try {
      const walFile = join(worldDir, 'wal.jsonl');
      repairTornTail(walFile, 'wal-entry');
      const parsed = parseWal(walFile, options.worldId);
      const state = replay(parsed.lines, options.worldId);
      const now = timestampSchema.parse(options.now());
      if (parsed.lastTimestamp !== undefined && now < parsed.lastTimestamp) {
        throw new WalStoreError('clock-regression', `wall clock ${now} precedes WAL time ${parsed.lastTimestamp}`);
      }

      const actionExpected = state.actionRecords as unknown as Record<string, unknown>[];
      const accessExpected = state.accessRecords as unknown as Record<string, unknown>[];
      actionWriter = materializeProjection(join(worldDir, 'action.jsonl'), 'record-entry', actionExpected);
      accessWriter = materializeProjection(join(worldDir, 'access.jsonl'), 'access-entry', accessExpected);
      walWriter = new DurableChainWriter(walFile, 'wal-entry');

      const lastWalTimestamp = parsed.lastTimestamp ?? now;
      const store = new WalStore(
        options,
        lease,
        walWriter,
        actionWriter,
        accessWriter,
        state,
        lastWalTimestamp,
        parsed.lines.length === 0 ? now : null,
        false,
      );
      if (options.deferRunHeader !== true) store.beginRun();
      return store;
    } catch (error) {
      try {
        accessWriter?.close();
      } catch {}
      try {
        actionWriter?.close();
      } catch {}
      try {
        walWriter?.close();
      } catch {}
      lease.close();
      throw error;
    }
  }

  snapshot(): WorldState {
    return cloneWorldState(this.#state);
  }

  /** In-memory durable heads used to detect a same-boot valid-prefix rollback. */
  chainHeads(): WalStoreChainHeads {
    return {
      wal: this.#walWriter.head,
      action: this.#actionWriter.head,
      access: this.#accessWriter.head,
    };
  }

  /** Append genesis if needed and the new run header only after startup verification succeeds. */
  beginRun(): void {
    if (this.#closed) throw new WalStoreError('closed', 'WAL store is closed');
    if (this.#poisoned) throw new WalStoreError('poisoned', 'WAL store requires restart after a failed append');
    if (this.#runStarted) return;
    try {
      if (this.#genesisTimestamp !== null) {
        this.#walWriter.append(
          walGenesisHeader.parse({
            kind: 'genesis',
            wal_version: 2,
            world_id: this.#options.worldId,
            created_at: this.#genesisTimestamp,
          }),
        );
      }
      const runTimestamp = timestampSchema.parse(this.#options.now());
      if (runTimestamp < this.#lastWalTimestamp) {
        throw new WalStoreError(
          'clock-regression',
          `run timestamp ${runTimestamp} precedes ${this.#lastWalTimestamp}`,
        );
      }
      this.#walWriter.append(
        walRunHeader.parse({
          kind: 'run',
          world_id: this.#options.worldId,
          ts: runTimestamp,
          run_id: this.#options.runId,
          boot_id: this.#options.bootId,
          policy_version: this.#options.policyVersion,
          policy_content_digest: this.#options.policyContentDigest,
          evaluator_build_digest: this.#options.evaluatorBuildDigest,
        }),
      );
      this.#lastWalTimestamp = runTimestamp;
      this.#runStarted = true;
    } catch (error) {
      this.#poisoned = true;
      throw error;
    }
  }

  async transact(
    name: string,
    actor: TransactionActor,
    ops: readonly WalOp[],
    timestamp?: string,
  ): Promise<AppendedEntry> {
    const completed = await this.transactWithState(name, actor, () => ({ ops, result: undefined }), timestamp);
    if (completed.appended === null) throw new RangeError('a WAL transaction must contain at least one operation');
    return completed.appended;
  }

  /**
   * Build an operation list from current replay state while holding the world's mutex.
   * Policy selection, counter checks, and invalidation scans must use this path so two
   * callers cannot both decide from the same pre-reservation snapshot.
   */
  async transactWithState<T>(
    name: string,
    actor: TransactionActor,
    build: (state: WorldState, timestamp: string) => TransactionBuild<T>,
    timestamp?: string,
  ): Promise<TransactionResult<T>> {
    return withWorldLock(this.#options.worldId, () => {
      if (this.#closed) throw new WalStoreError('closed', 'WAL store is closed');
      if (this.#poisoned) throw new WalStoreError('poisoned', 'WAL store requires restart after a post-durability failure');
      if (!this.#runStarted) {
        throw new WalStoreError('run-not-started', 'WAL run header must be appended before transactions');
      }
      const transactionTimestamp = timestampSchema.parse(timestamp ?? this.#options.now());
      if (transactionTimestamp < this.#lastWalTimestamp) {
        throw new WalStoreError('clock-regression', `transaction ${transactionTimestamp} precedes ${this.#lastWalTimestamp}`);
      }
      const built = build(cloneWorldState(this.#state), transactionTimestamp);
      if (built.ops.length === 0) return { appended: null, result: built.result };
      const transaction: WalTransaction = walTransaction.parse({
        kind: 'transaction',
        world_id: this.#options.worldId,
        ts: transactionTimestamp,
        txn: name,
        run_id: this.#options.runId,
        actor,
        ops: built.ops,
      });
      const preview = cloneWorldState(this.#state);
      applyWorldTransaction(preview, transaction.ops, transaction.ts);

      let appended: AppendedEntry;
      try {
        appended = this.#walWriter.append(transaction);
      } catch (error) {
        this.#poisoned = true;
        throw new WalStoreError('poisoned', `WAL append failed; restart for verification (${String(error)})`);
      }
      this.#state = preview;
      this.#lastWalTimestamp = transactionTimestamp;
      try {
        for (const op of transaction.ops) {
          if (op.op === 'record.action.append') this.#actionWriter.append(op.entry);
          if (op.op === 'record.access.append') this.#accessWriter.append(op.entry);
        }
      } catch (error) {
        this.#poisoned = true;
        throw new WalStoreError(
          'poisoned',
          `WAL is durable but a materialized chain append failed; restart for repair (${String(error)})`,
        );
      }
      return { appended, result: built.result };
    });
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    this.#accessWriter.close();
    this.#actionWriter.close();
    this.#walWriter.close();
    this.#lease.close();
  }
}
