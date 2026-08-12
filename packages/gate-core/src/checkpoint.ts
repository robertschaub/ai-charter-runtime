// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-003 composite checkpoints, local record verification, and receipt references. */
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import {
  closeSync,
  existsSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeSync,
} from 'node:fs';
import { basename, dirname, join, relative, resolve } from 'node:path';

import { z } from 'zod';

import { canonicalize } from './canonicalize.js';
import { readVerifiedChainEntries, verifyChain } from './chain.js';
import type { ChainDomainTag } from './domain.js';
import { digestFor, isHexDigest, verifyDigest } from './hash.js';
import {
  accessEntry,
  anchorEvent,
  anchorFailedEvent,
  hexDigest,
  id,
  integer,
  timestamp,
  worldId,
} from './schemas/index.js';
import type { WalStore } from './walStore.js';

const streamName = z.enum(['access', 'action', 'wal']);
const gitCommitSha = z.string().regex(/^[0-9a-f]{40,64}$/, 'expected a lowercase git commit sha');
const checkpointFileName = z.string().regex(/^\d{4,}-\d{8}T\d{6}Z\.json$/);

export const checkpointStreamHead = z
  .object({
    world: worldId,
    stream: streamName,
    length: integer.min(0),
    head_hash: hexDigest,
  })
  .strict();

export const checkpointArtifact = z
  .object({
    schema: z.literal('ai-charter-runtime/checkpoint/v1'),
    seq: integer.min(1),
    checkpoint_id: id,
    created_at: timestamp,
    reason: z.string().min(1),
    run_id: id,
    hash_alg: z.literal('sha256'),
    policy_content_digest: hexDigest,
    evaluator_build_id: z.string().min(1),
    prev_checkpoint_id: id.nullable(),
    prev_checkpoint_digest: hexDigest.nullable(),
    streams: z.array(checkpointStreamHead),
    composite_digest: hexDigest,
  })
  .strict();

export const checkpointPointer = z
  .object({
    seq: integer.min(1),
    file: checkpointFileName,
    checkpoint_id: id,
    composite_digest: hexDigest,
  })
  .strict();

export type CheckpointStreamHead = z.infer<typeof checkpointStreamHead>;
export type CheckpointArtifact = z.infer<typeof checkpointArtifact>;
export type CheckpointPointer = z.infer<typeof checkpointPointer>;

const STREAMS = [
  { stream: 'access', file: 'access.jsonl', domain: 'access-entry' },
  { stream: 'action', file: 'action.jsonl', domain: 'record-entry' },
  { stream: 'wal', file: 'wal.jsonl', domain: 'wal-entry' },
] as const satisfies readonly {
  readonly stream: CheckpointStreamHead['stream'];
  readonly file: string;
  readonly domain: ChainDomainTag;
}[];

export type RecordVerificationErrorCode =
  | 'checkpoint-invalid'
  | 'checkpoint-sequence'
  | 'checkpoint-pointer'
  | 'checkpoint-composite'
  | 'chain-tamper'
  | 'missing-stream'
  | 'rollback'
  | 'remote-rollback'
  | 'remote-acknowledgment-ambiguous';

export class RecordVerificationError extends Error {
  constructor(
    readonly code: RecordVerificationErrorCode,
    message: string,
    readonly world?: string,
    readonly stream?: CheckpointStreamHead['stream'],
    readonly divergenceIndex?: number,
  ) {
    super(message);
    this.name = 'RecordVerificationError';
  }
}

export type LocalCheckpointCommitEvidence =
  | { readonly status: 'committed'; readonly commitSha: string }
  | { readonly status: 'uncommitted' };

export interface LocalCheckpointCommitContext {
  readonly artifact: CheckpointArtifact;
  readonly file: string;
  readonly latest: boolean;
  readonly checkpointsRoot: string;
  readonly repoRoot: string;
  readonly gitRunner?: CheckpointGitRunner;
}

export type LocalCheckpointCommitResolver = (
  context: LocalCheckpointCommitContext,
) => Promise<LocalCheckpointCommitEvidence>;

export type RemoteCheckpointObservation =
  | { readonly status: 'unavailable'; readonly reason: string }
  | { readonly status: 'ref_absent'; readonly repoUrl: string; readonly branch: string }
  | {
      readonly status: 'ref_present';
      readonly remoteHeadSha: string;
      readonly repoUrl: string;
      readonly branch: string;
      readonly contains: Readonly<Record<string, boolean>>;
    };

export interface RemoteCheckpointObservationContext {
  readonly repoRoot: string;
  readonly commitShas: readonly string[];
  readonly branch?: string;
  readonly repoUrl?: string;
  readonly gitRunner?: CheckpointGitRunner;
}

export type RemoteCheckpointObserver = (
  context: RemoteCheckpointObservationContext,
) => Promise<RemoteCheckpointObservation>;

export type CheckpointGitRunner = (
  cwd: string,
  args: readonly string[],
  allowExitOne?: boolean,
) => Promise<{ readonly stdout: string; readonly exitCode: 0 | 1 }>;

export interface LatestPushedCheckpoint {
  readonly artifact: CheckpointArtifact;
  readonly commitSha: string;
  readonly remoteHeadSha: string;
  readonly repoUrl: string;
  readonly branch: string;
  readonly observedAt: string;
}

export interface RemotelyAcknowledgedCheckpoint {
  readonly checkpoint_id: string;
  readonly composite_digest: string;
  readonly checkpoint_commit_sha: string;
  readonly remote_head_sha: string;
  readonly repo_url: string;
  readonly branch: string;
  readonly observed_at: string;
}

export interface RecordsVerificationReport {
  readonly mode: 'local' | 'remote';
  readonly remoteStatus: 'not_checked' | 'acknowledged' | 'unanchored_local_candidate' | 'unavailable';
  readonly checkpoint: CheckpointArtifact | null;
  readonly latestPushedCheckpoint: LatestPushedCheckpoint | null;
  readonly remotelyAcknowledged: RemotelyAcknowledgedCheckpoint | null;
  readonly readLengths: Readonly<Record<string, number>>;
  readonly unanchoredWindowEntries: number;
  readonly unanchoredWindowMinutes: number | null;
  readonly warnings: readonly string[];
  readonly message: string;
}

export interface VerifyRecordsOptions {
  readonly recordsRoot: string;
  readonly checkpointsRoot: string;
  readonly worldId?: string;
  readonly local: boolean;
  readonly repoRoot?: string;
  readonly branch?: string;
  readonly repoUrl?: string;
  readonly now?: () => string;
  readonly localCommitResolver?: LocalCheckpointCommitResolver;
  readonly remoteObserver?: RemoteCheckpointObserver;
  readonly recordVerification?: (readLengths: Readonly<Record<string, number>>) => Promise<void>;
}

export interface WriteCheckpointOptions {
  readonly recordsRoot: string;
  readonly checkpointsRoot: string;
  readonly reason: string;
  readonly runId: string;
  readonly policyContentDigest: string;
  readonly evaluatorBuildId: string;
  readonly now?: () => string;
  /** The M4 deterministic writer never invokes git, commit, or push. */
  readonly mode: 'write-only';
}

interface CheckpointSet {
  readonly artifacts: readonly { readonly file: string; readonly artifact: CheckpointArtifact }[];
  readonly pointer: CheckpointPointer | null;
}

interface LocalChains {
  readonly heads: readonly CheckpointStreamHead[];
  readonly files: ReadonlyMap<string, string>;
  readonly readLengths: Readonly<Record<string, number>>;
}

type AnchorAttempt =
  | { readonly kind: 'anchor'; readonly value: z.infer<typeof anchorEvent> }
  | {
      readonly kind: 'anchor_failed';
      readonly failureClass: 'pre_remote_failure' | 'remote_definite_absence' | 'acknowledgment_unknown';
      readonly value: z.infer<typeof anchorFailedEvent>;
    };

interface CheckpointEvidence {
  readonly file: string;
  readonly artifact: CheckpointArtifact;
  readonly commit: LocalCheckpointCommitEvidence;
  readonly attempt: AnchorAttempt | null;
}

type RemoteAcknowledgmentDecision =
  | {
      readonly status: 'acknowledged';
      readonly checkpoint: CheckpointEvidence;
      readonly observation: Extract<RemoteCheckpointObservation, { readonly status: 'ref_present' }>;
    }
  | {
      readonly status: 'unanchored_local_candidate';
      readonly priorAcknowledged: CheckpointEvidence | null;
      readonly observation: Exclude<RemoteCheckpointObservation, { readonly status: 'unavailable' }>;
    }
  | { readonly status: 'unavailable'; readonly reason: string }
  | { readonly status: 'remote_rollback'; readonly reason: string }
  | { readonly status: 'remote_acknowledgment_ambiguous'; readonly reason: string };

function compareText(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function sortedHeads(heads: readonly CheckpointStreamHead[]): CheckpointStreamHead[] {
  return [...heads].sort((left, right) => compareText(left.world, right.world) || compareText(left.stream, right.stream));
}

function checkpointNumber(seq: number): string {
  return String(seq).padStart(4, '0');
}

function checkpointId(seq: number): string {
  return `cp-${checkpointNumber(seq)}`;
}

function compactTimestamp(value: string): string {
  return value.replaceAll('-', '').replaceAll(':', '').replace(/\.\d{3}Z$/, 'Z');
}

function expectedCheckpointFile(artifact: CheckpointArtifact): string {
  return `${checkpointNumber(artifact.seq)}-${compactTimestamp(artifact.created_at)}.json`;
}

function pointerForArtifact(file: string, artifact: CheckpointArtifact): CheckpointPointer {
  return checkpointPointer.parse({
    seq: artifact.seq,
    file,
    checkpoint_id: artifact.checkpoint_id,
    composite_digest: artifact.composite_digest,
  });
}

function decodeUtf8(bytes: Buffer, label: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new RecordVerificationError('checkpoint-invalid', `${label} is not valid UTF-8`);
  }
}

function readJson(path: string, label: string): unknown {
  try {
    return JSON.parse(decodeUtf8(readFileSync(path), label)) as unknown;
  } catch (error) {
    if (error instanceof RecordVerificationError) throw error;
    throw new RecordVerificationError('checkpoint-invalid', `${label} is not valid JSON`);
  }
}

function compositeDigest(heads: readonly CheckpointStreamHead[]): string {
  return digestFor('checkpoint-composite', sortedHeads(heads));
}

function checkpointDigest(artifact: CheckpointArtifact): string {
  return digestFor('checkpoint', artifact);
}

function assertArtifactSemantics(artifact: CheckpointArtifact, file: string): void {
  if (artifact.checkpoint_id !== checkpointId(artifact.seq)) {
    throw new RecordVerificationError(
      'checkpoint-sequence',
      `checkpoint ${file} id does not match sequence ${artifact.seq}`,
    );
  }
  if (file !== expectedCheckpointFile(artifact)) {
    throw new RecordVerificationError('checkpoint-sequence', `checkpoint ${file} does not match its sequence and time`);
  }
  const sorted = sortedHeads(artifact.streams);
  if (canonicalize(sorted) !== canonicalize(artifact.streams)) {
    throw new RecordVerificationError('checkpoint-composite', `checkpoint ${file} stream rows are not sorted`);
  }
  for (let index = 1; index < sorted.length; index += 1) {
    const previous = sorted[index - 1];
    const current = sorted[index];
    if (previous !== undefined && current !== undefined && previous.world === current.world && previous.stream === current.stream) {
      throw new RecordVerificationError(
        'checkpoint-composite',
        `checkpoint ${file} repeats ${current.world}/${current.stream}`,
      );
    }
  }
  if (!verifyDigest(artifact.composite_digest, compositeDigest(artifact.streams))) {
    throw new RecordVerificationError('checkpoint-composite', `checkpoint ${file} composite digest does not verify`);
  }
}

function readCheckpointSet(checkpointsRoot: string): CheckpointSet {
  const latestPath = join(checkpointsRoot, 'latest.json');
  if (!existsSync(checkpointsRoot)) {
    return { artifacts: [], pointer: null };
  }
  const files = readdirSync(checkpointsRoot, { withFileTypes: true });
  const artifactFiles: string[] = [];
  for (const entry of files) {
    if (!entry.isFile() || !entry.name.endsWith('.json') || entry.name === 'latest.json') continue;
    if (!checkpointFileName.safeParse(entry.name).success) {
      throw new RecordVerificationError('checkpoint-invalid', `unexpected checkpoint JSON file ${entry.name}`);
    }
    artifactFiles.push(entry.name);
  }
  artifactFiles.sort(compareText);
  const artifacts = artifactFiles.map((file) => {
    const parsed = checkpointArtifact.safeParse(readJson(join(checkpointsRoot, file), `checkpoint ${file}`));
    if (!parsed.success) {
      throw new RecordVerificationError('checkpoint-invalid', `checkpoint ${file} does not match checkpoint/v1`);
    }
    assertArtifactSemantics(parsed.data, file);
    return { file, artifact: parsed.data };
  });
  for (let index = 0; index < artifacts.length; index += 1) {
    const current = artifacts[index];
    if (current === undefined) continue;
    const expectedSeq = index + 1;
    if (current.artifact.seq !== expectedSeq) {
      throw new RecordVerificationError(
        'checkpoint-sequence',
        `checkpoint sequence is not contiguous at ${current.artifact.seq}; expected ${expectedSeq}`,
      );
    }
    const previous = artifacts[index - 1]?.artifact;
    if (previous === undefined) {
      if (current.artifact.prev_checkpoint_id !== null || current.artifact.prev_checkpoint_digest !== null) {
        throw new RecordVerificationError('checkpoint-sequence', 'first checkpoint must have a null predecessor');
      }
    } else if (
      current.artifact.prev_checkpoint_id !== previous.checkpoint_id ||
      !verifyDigest(current.artifact.prev_checkpoint_digest ?? '', checkpointDigest(previous))
    ) {
      throw new RecordVerificationError(
        'checkpoint-sequence',
        `checkpoint ${current.artifact.checkpoint_id} does not bind its predecessor`,
      );
    }
  }

  if (artifacts.length === 0) {
    if (existsSync(latestPath)) {
      throw new RecordVerificationError('checkpoint-pointer', 'latest.json exists without a checkpoint artifact');
    }
    return { artifacts, pointer: null };
  }
  if (!existsSync(latestPath)) {
    throw new RecordVerificationError('checkpoint-pointer', 'checkpoint artifacts exist without latest.json');
  }
  const parsedPointer = checkpointPointer.safeParse(readJson(latestPath, 'checkpoint latest.json'));
  if (!parsedPointer.success) {
    throw new RecordVerificationError('checkpoint-pointer', 'latest.json does not match the checkpoint pointer schema');
  }
  const highest = artifacts.at(-1);
  if (
    highest === undefined ||
    parsedPointer.data.seq !== highest.artifact.seq ||
    parsedPointer.data.file !== highest.file ||
    parsedPointer.data.checkpoint_id !== highest.artifact.checkpoint_id ||
    !verifyDigest(parsedPointer.data.composite_digest, highest.artifact.composite_digest)
  ) {
    throw new RecordVerificationError('checkpoint-pointer', 'latest.json does not identify the highest checkpoint');
  }
  return { artifacts, pointer: parsedPointer.data };
}

function localWorlds(recordsRoot: string): string[] {
  if (!existsSync(recordsRoot)) return [];
  const worlds: string[] = [];
  for (const entry of readdirSync(recordsRoot, { withFileTypes: true })) {
    if (!entry.isDirectory()) continue;
    const parsed = worldId.safeParse(entry.name);
    if (!parsed.success) {
      throw new RecordVerificationError('chain-tamper', `records contain an invalid world directory ${entry.name}`);
    }
    worlds.push(parsed.data);
  }
  return worlds.sort(compareText);
}

function localChainKey(world: string, stream: CheckpointStreamHead['stream']): string {
  return `${world}/${stream}`;
}

function verifyLocalChains(recordsRoot: string): LocalChains {
  const heads: CheckpointStreamHead[] = [];
  const files = new Map<string, string>();
  const readLengths: Record<string, number> = {};
  for (const world of localWorlds(recordsRoot)) {
    for (const definition of STREAMS) {
      const file = join(recordsRoot, world, definition.file);
      if (!existsSync(file)) {
        throw new RecordVerificationError(
          'missing-stream',
          `record stream ${world}/${definition.stream} is missing`,
          world,
          definition.stream,
          0,
        );
      }
      const verified = verifyChain(file, definition.domain);
      if (!verified.ok) {
        throw new RecordVerificationError(
          'chain-tamper',
          `record stream ${world}/${definition.stream} fails at index ${verified.index} (${verified.reason})`,
          world,
          definition.stream,
          verified.index,
        );
      }
      const key = localChainKey(world, definition.stream);
      heads.push({ world, stream: definition.stream, length: verified.length, head_hash: verified.head_hash });
      files.set(key, file);
      readLengths[key] = verified.length;
    }
  }
  return { heads: sortedHeads(heads), files, readLengths };
}

function acknowledgmentAmbiguous(message: string): RecordVerificationError {
  return new RecordVerificationError('remote-acknowledgment-ambiguous', message);
}

function anchorFailureClass(
  value: string,
): 'pre_remote_failure' | 'remote_definite_absence' | 'acknowledgment_unknown' {
  if (value === 'pre_remote_failure' || value === 'remote_definite_absence') return value;
  return 'acknowledgment_unknown';
}

function readAnchorAttempts(
  recordsRoot: string,
  configuredWorldId: string,
  checkpoints: CheckpointSet,
): ReadonlyMap<string, AnchorAttempt> {
  const world = worldId.parse(configuredWorldId);
  const known = new Map(checkpoints.artifacts.map((item) => [item.artifact.checkpoint_id, item.artifact]));
  const attempts = new Map<string, AnchorAttempt>();
  const accessFile = join(recordsRoot, world, 'access.jsonl');
  if (!existsSync(accessFile)) return attempts;
  const entries = readVerifiedChainEntries(accessFile, 'access-entry');
  for (const envelope of entries) {
    const { seq: _seq, prev_hash: _prevHash, entry_hash: _entryHash, ...payload } = envelope;
    if (payload['event'] !== 'anchor' && payload['event'] !== 'anchor_failed') continue;
    const parsed = payload['event'] === 'anchor' ? anchorEvent.safeParse(payload) : anchorFailedEvent.safeParse(payload);
    if (!parsed.success) throw acknowledgmentAmbiguous('anchor attempt evidence is malformed');
    const checkpoint = known.get(parsed.data.checkpoint_id);
    if (checkpoint === undefined) {
      throw acknowledgmentAmbiguous(`anchor attempt names unknown checkpoint ${parsed.data.checkpoint_id}`);
    }
    if (parsed.data.world_id !== world) {
      throw acknowledgmentAmbiguous(`anchor attempt for ${parsed.data.checkpoint_id} names another world`);
    }
    if (attempts.has(parsed.data.checkpoint_id)) {
      throw acknowledgmentAmbiguous(`checkpoint ${parsed.data.checkpoint_id} has multiple terminal anchor attempts`);
    }
    if (parsed.data.event === 'anchor') {
      if (!verifyDigest(parsed.data.composite_digest, checkpoint.composite_digest)) {
        throw acknowledgmentAmbiguous(`anchor for ${parsed.data.checkpoint_id} does not bind its composite digest`);
      }
      if (!gitCommitSha.safeParse(parsed.data.remote_sha).success) {
        throw acknowledgmentAmbiguous(`anchor for ${parsed.data.checkpoint_id} has an invalid commit sha`);
      }
      attempts.set(parsed.data.checkpoint_id, { kind: 'anchor', value: parsed.data });
    } else {
      attempts.set(parsed.data.checkpoint_id, {
        kind: 'anchor_failed',
        failureClass: anchorFailureClass(parsed.data.error_class),
        value: parsed.data,
      });
    }
  }
  return attempts;
}

function entryHashAt(file: string, index: number): string {
  const lines = decodeUtf8(readFileSync(file), basename(file)).split('\n');
  const line = lines[index];
  if (line === undefined || line.length === 0) {
    throw new RecordVerificationError('rollback', `record stream has no entry at index ${index}`);
  }
  try {
    const parsed = JSON.parse(line) as { entry_hash?: unknown };
    if (!isHexDigest(parsed.entry_hash)) throw new Error('missing hash');
    return parsed.entry_hash;
  } catch {
    throw new RecordVerificationError('chain-tamper', `record stream entry ${index} is not readable`);
  }
}

function assertExtendsCheckpoint(
  artifact: CheckpointArtifact,
  local: LocalChains,
): number {
  const localByKey = new Map(local.heads.map((head) => [localChainKey(head.world, head.stream), head]));
  let openEntries = 0;
  const anchoredKeys = new Set<string>();
  for (const anchored of artifact.streams) {
    const key = localChainKey(anchored.world, anchored.stream);
    anchoredKeys.add(key);
    const current = localByKey.get(key);
    const file = local.files.get(key);
    if (current === undefined || file === undefined) {
      throw new RecordVerificationError(
        'missing-stream',
        `anchored stream ${key} is missing`,
        anchored.world,
        anchored.stream,
        0,
      );
    }
    if (current.length < anchored.length) {
      throw new RecordVerificationError(
        'rollback',
        `rollback alarm for ${key}: local length ${current.length} is below anchored length ${anchored.length}`,
        anchored.world,
        anchored.stream,
        current.length,
      );
    }
    if (anchored.length > 0) {
      const boundaryIndex = anchored.length - 1;
      const boundaryHash = entryHashAt(file, boundaryIndex);
      if (!verifyDigest(anchored.head_hash, boundaryHash)) {
        throw new RecordVerificationError(
          'rollback',
          `rollback alarm for ${key}: anchored boundary differs at index ${boundaryIndex}`,
          anchored.world,
          anchored.stream,
          boundaryIndex,
        );
      }
    }
    openEntries += current.length - anchored.length;
  }
  for (const current of local.heads) {
    if (!anchoredKeys.has(localChainKey(current.world, current.stream))) openEntries += current.length;
  }
  return openEntries;
}

function writeAll(fd: number, value: string): void {
  const bytes = Buffer.from(value, 'utf8');
  let offset = 0;
  while (offset < bytes.length) {
    const written = writeSync(fd, bytes, offset, bytes.length - offset, null);
    if (written <= 0) throw new Error('checkpoint write made no progress');
    offset += written;
  }
}

function durableWriteExclusive(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const fd = openSync(path, 'wx');
  try {
    writeAll(fd, `${canonicalize(value)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}

function durableReplace(path: string, value: unknown): void {
  mkdirSync(dirname(path), { recursive: true });
  const temporary = `${path}.tmp-${process.pid}-${randomUUID()}`;
  try {
    durableWriteExclusive(temporary, value);
    renameSync(temporary, path);
  } finally {
    rmSync(temporary, { force: true });
  }
}

export async function writeCheckpoint(options: WriteCheckpointOptions): Promise<CheckpointArtifact> {
  if (options.mode !== 'write-only') throw new Error('only write-only checkpoint mode is implemented in M4');
  const existing = readCheckpointSet(options.checkpointsRoot);
  const local = verifyLocalChains(options.recordsRoot);
  const previous = existing.artifacts.at(-1)?.artifact;
  if (previous !== undefined) assertExtendsCheckpoint(previous, local);
  const createdAt = timestamp.parse((options.now ?? (() => new Date().toISOString()))());
  const seq = (previous?.seq ?? 0) + 1;
  const artifact = checkpointArtifact.parse({
    schema: 'ai-charter-runtime/checkpoint/v1',
    seq,
    checkpoint_id: checkpointId(seq),
    created_at: createdAt,
    reason: options.reason,
    run_id: id.parse(options.runId),
    hash_alg: 'sha256',
    policy_content_digest: hexDigest.parse(options.policyContentDigest),
    evaluator_build_id: options.evaluatorBuildId,
    prev_checkpoint_id: previous?.checkpoint_id ?? null,
    prev_checkpoint_digest: previous === undefined ? null : checkpointDigest(previous),
    streams: local.heads,
    composite_digest: compositeDigest(local.heads),
  });
  const file = expectedCheckpointFile(artifact);
  const pointer = checkpointPointer.parse({
    seq,
    file,
    checkpoint_id: artifact.checkpoint_id,
    composite_digest: artifact.composite_digest,
  });
  durableWriteExclusive(join(options.checkpointsRoot, file), artifact);
  durableReplace(join(options.checkpointsRoot, 'latest.json'), pointer);
  return artifact;
}

function safeRepoUrl(value: string): string | null {
  try {
    const parsed = new URL(value);
    if (!['http:', 'https:'].includes(parsed.protocol) || parsed.username !== '' || parsed.password !== '') return null;
    return value.endsWith('.git') ? value.slice(0, -4) : value;
  } catch {
    return null;
  }
}

function validBranch(value: string): boolean {
  return (
    /^[A-Za-z0-9][A-Za-z0-9._/-]*$/.test(value) &&
    !value.includes('..') &&
    !value.includes('//') &&
    !value.endsWith('/')
  );
}

function runGit(
  cwd: string,
  args: readonly string[],
  allowExitOne = false,
): Promise<{ readonly stdout: string; readonly exitCode: 0 | 1 }> {
  const inheritedNames = [
    'SystemRoot',
    'TEMP',
    'TMP',
    'ComSpec',
    'PATHEXT',
    'Path',
    'PATH',
  ];
  const inherited = Object.fromEntries(
    inheritedNames.flatMap((name) => (process.env[name] === undefined ? [] : [[name, process.env[name]]])),
  );
  return new Promise((resolveResult, reject) => {
    execFile(
      'git',
      [...args],
      {
        cwd,
        env: { ...inherited, GIT_TERMINAL_PROMPT: '0', GCM_INTERACTIVE: 'Never' },
        timeout: 10_000,
        windowsHide: true,
        maxBuffer: 1024 * 1024,
      },
      (error, stdout) => {
        if (error === null) {
          resolveResult({ stdout, exitCode: 0 });
          return;
        }
        if (allowExitOne && typeof error === 'object' && error !== null && 'code' in error && error.code === 1) {
          resolveResult({ stdout, exitCode: 1 });
          return;
        }
        reject(error);
      },
    );
  });
}

export async function resolveCheckpointCommit(
  context: LocalCheckpointCommitContext,
): Promise<LocalCheckpointCommitEvidence> {
  const executeGit = context.gitRunner ?? runGit;
  const repoRoot = resolve(context.repoRoot);
  const artifactPath = resolve(context.checkpointsRoot, context.file);
  const relativeArtifact = relative(repoRoot, artifactPath).replaceAll('\\', '/');
  const relativePointer = relative(repoRoot, resolve(context.checkpointsRoot, 'latest.json')).replaceAll('\\', '/');
  if (
    relativeArtifact.startsWith('../') ||
    relativeArtifact === '' ||
    relativePointer.startsWith('../') ||
    relativePointer === ''
  ) {
    throw acknowledgmentAmbiguous('checkpoint artifact or pointer is outside the configured repository');
  }
  try {
    const history = (await executeGit(repoRoot, ['log', '--format=%H', '--', relativeArtifact])).stdout
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    for (const commitSha of history) {
      if (!gitCommitSha.safeParse(commitSha).success) {
        throw acknowledgmentAmbiguous(`checkpoint ${context.artifact.checkpoint_id} has an invalid local commit sha`);
      }
    }
    const localArtifact = decodeUtf8(readFileSync(artifactPath), context.file);
    const expectedPointer = `${canonicalize(pointerForArtifact(context.file, context.artifact))}\n`;
    for (const commitSha of history) {
      let committedArtifact: string;
      let committedPointer: string;
      try {
        committedArtifact = (await executeGit(repoRoot, ['show', `${commitSha}:${relativeArtifact}`])).stdout;
        committedPointer = (await executeGit(repoRoot, ['show', `${commitSha}:${relativePointer}`])).stdout;
      } catch {
        continue;
      }
      if (committedPointer !== expectedPointer) continue;
      if (committedArtifact !== localArtifact) {
        throw acknowledgmentAmbiguous(`checkpoint commit ${commitSha} differs from the exact artifact bytes`);
      }
      return { status: 'committed', commitSha };
    }
    if (context.latest && history.length > 0) {
      throw acknowledgmentAmbiguous(
        `latest checkpoint ${context.artifact.checkpoint_id} is committed without its exact matching pointer`,
      );
    }
    return { status: 'uncommitted' };
  } catch (error) {
    if (error instanceof RecordVerificationError) throw error;
    throw acknowledgmentAmbiguous(`local commit evidence for ${context.artifact.checkpoint_id} is unavailable`);
  }
}

export async function observeCheckpointRemote(
  context: RemoteCheckpointObservationContext,
): Promise<RemoteCheckpointObservation> {
  if (context.branch !== undefined && !validBranch(context.branch)) {
    throw acknowledgmentAmbiguous('configured checkpoint branch is invalid');
  }
  const requestedUrl = context.repoUrl === undefined ? undefined : safeRepoUrl(context.repoUrl);
  if (context.repoUrl !== undefined && requestedUrl === null) {
    throw acknowledgmentAmbiguous('configured checkpoint repository is not a public HTTP URL');
  }
  try {
    const executeGit = context.gitRunner ?? runGit;
    const repoRoot = resolve(context.repoRoot);
    const branchResult = context.branch === undefined
      ? await executeGit(repoRoot, ['symbolic-ref', '--short', 'HEAD'])
      : { stdout: context.branch, exitCode: 0 as const };
    const branch = branchResult.stdout.trim();
    if (!validBranch(branch)) return { status: 'unavailable', reason: 'repository has no verifiable branch' };
    const originUrl = safeRepoUrl((await executeGit(repoRoot, ['remote', 'get-url', 'origin'])).stdout.trim());
    if (originUrl === null) throw acknowledgmentAmbiguous('origin is not a public HTTP repository URL');
    if (requestedUrl !== undefined && requestedUrl !== originUrl) {
      throw acknowledgmentAmbiguous('configured checkpoint repository does not match origin');
    }
    const repoUrl = requestedUrl ?? originUrl;
    const ref = `refs/heads/${branch}`;
    const remoteOutput = (await executeGit(repoRoot, ['ls-remote', '--heads', 'origin', ref])).stdout.trim();
    const remoteLine = remoteOutput
      .split(/\r?\n/)
      .filter((line) => line.length > 0)
      .map((line) => line.trim().split(/\s+/))
      .find((parts) => parts[1] === ref);
    if (remoteLine === undefined) return { status: 'ref_absent', repoUrl, branch };
    const remoteHeadSha = remoteLine[0] ?? '';
    if (!gitCommitSha.safeParse(remoteHeadSha).success) {
      throw acknowledgmentAmbiguous(`remote branch ${branch} returned an invalid commit sha`);
    }
    const contains: Record<string, boolean> = {};
    for (const commitSha of [...new Set(context.commitShas)]) {
      if (!gitCommitSha.safeParse(commitSha).success) {
        throw acknowledgmentAmbiguous('remote observation received an invalid local checkpoint commit sha');
      }
      if (commitSha === remoteHeadSha) {
        contains[commitSha] = true;
        continue;
      }
      const ancestor = await executeGit(repoRoot, ['merge-base', '--is-ancestor', commitSha, remoteHeadSha], true);
      contains[commitSha] = ancestor.exitCode === 0;
    }
    return { status: 'ref_present', remoteHeadSha, repoUrl, branch, contains };
  } catch (error) {
    if (error instanceof RecordVerificationError) throw error;
    return { status: 'unavailable', reason: 'remote checkpoint observation is unavailable' };
  }
}

function containsCommit(
  observation: Extract<RemoteCheckpointObservation, { readonly status: 'ref_present' }>,
  commitSha: string,
): boolean | undefined {
  return Object.prototype.hasOwnProperty.call(observation.contains, commitSha)
    ? observation.contains[commitSha]
    : undefined;
}

function validateRemoteObservation(
  observation: RemoteCheckpointObservation,
  options: VerifyRecordsOptions,
): RemoteCheckpointObservation {
  if (observation.status === 'unavailable') {
    if (observation.reason.length === 0) throw acknowledgmentAmbiguous('remote unavailability has no reason');
    return observation;
  }
  const observedUrl = safeRepoUrl(observation.repoUrl);
  if (observedUrl === null || observedUrl !== observation.repoUrl || !validBranch(observation.branch)) {
    throw acknowledgmentAmbiguous('remote observation has an invalid repository or branch binding');
  }
  const configuredUrl = options.repoUrl === undefined ? undefined : safeRepoUrl(options.repoUrl);
  if (options.repoUrl !== undefined && configuredUrl === null) {
    throw acknowledgmentAmbiguous('configured checkpoint repository is not a public HTTP URL');
  }
  if (
    (options.branch !== undefined && options.branch !== observation.branch) ||
    (configuredUrl !== undefined && configuredUrl !== observedUrl)
  ) {
    throw acknowledgmentAmbiguous('remote observation does not match the configured repository and branch');
  }
  if (observation.status === 'ref_present') {
    if (!gitCommitSha.safeParse(observation.remoteHeadSha).success) {
      throw acknowledgmentAmbiguous('remote observation has an invalid head commit sha');
    }
    for (const [commitSha, contained] of Object.entries(observation.contains)) {
      if (!gitCommitSha.safeParse(commitSha).success || typeof contained !== 'boolean') {
        throw acknowledgmentAmbiguous('remote observation has an invalid containment result');
      }
    }
  }
  return observation;
}

function definitelyUnacknowledged(candidate: CheckpointEvidence): boolean {
  if (candidate.attempt?.kind !== 'anchor_failed') return false;
  if (candidate.attempt.failureClass === 'pre_remote_failure') return true;
  return candidate.attempt.failureClass === 'remote_definite_absence' && candidate.commit.status === 'committed';
}

/**
 * Trust boundary: classification trusts the verified-local terminal attempt evidence. An operator able to forge
 * that chain and also roll back the force-push-protected remote defeats this single-custodian POC; ADR-003's
 * no-independent-custody limit bounds that combined attack out of scope rather than presenting false assurance.
 */
function classifyRemoteAcknowledgment(
  evidence: readonly CheckpointEvidence[],
  observation: RemoteCheckpointObservation,
): RemoteAcknowledgmentDecision {
  const candidate = evidence.at(-1);
  if (candidate === undefined) {
    return { status: 'remote_acknowledgment_ambiguous', reason: 'no checkpoint candidate exists' };
  }
  if (observation.status === 'unavailable') return observation;
  const priorAcknowledged = [...evidence]
    .slice(0, -1)
    .reverse()
    .find((item) => item.attempt?.kind === 'anchor') ?? null;
  if (observation.status === 'ref_present' && priorAcknowledged?.commit.status === 'committed') {
    const priorContained = containsCommit(observation, priorAcknowledged.commit.commitSha);
    if (priorContained === undefined) {
      return {
        status: 'remote_acknowledgment_ambiguous',
        reason: 'remote observation omitted the prior acknowledged checkpoint containment result',
      };
    }
    if (!priorContained) {
      return { status: 'remote_rollback', reason: 'remote dropped the most recent prior acknowledged checkpoint' };
    }
  } else if (priorAcknowledged !== null) {
    return { status: 'remote_rollback', reason: 'remote branch is absent after a prior acknowledgment' };
  }
  if (observation.status === 'ref_present' && candidate.commit.status === 'committed') {
    const candidateContained = containsCommit(observation, candidate.commit.commitSha);
    if (candidateContained === undefined) {
      return {
        status: 'remote_acknowledgment_ambiguous',
        reason: 'remote observation omitted the latest checkpoint containment result',
      };
    }
    if (candidateContained) return { status: 'acknowledged', checkpoint: candidate, observation };
  }
  if (candidate.attempt?.kind === 'anchor') {
    return { status: 'remote_rollback', reason: 'remote dropped the latest acknowledged checkpoint' };
  }
  if (definitelyUnacknowledged(candidate)) {
    return { status: 'unanchored_local_candidate', priorAcknowledged, observation };
  }
  return {
    status: 'remote_acknowledgment_ambiguous',
    reason: 'latest checkpoint lacks affirmative definite-failure evidence',
  };
}

async function resolveCheckpointEvidence(
  checkpoints: CheckpointSet,
  attempts: ReadonlyMap<string, AnchorAttempt>,
  options: VerifyRecordsOptions,
): Promise<readonly CheckpointEvidence[]> {
  const resolver = options.localCommitResolver ?? resolveCheckpointCommit;
  const evidence = await Promise.all(
    checkpoints.artifacts.map(async (item, index): Promise<CheckpointEvidence> => ({
      ...item,
      commit: await resolver({
        artifact: item.artifact,
        file: item.file,
        latest: index === checkpoints.artifacts.length - 1,
        checkpointsRoot: options.checkpointsRoot,
        repoRoot: options.repoRoot ?? process.cwd(),
      }),
      attempt: attempts.get(item.artifact.checkpoint_id) ?? null,
    })),
  );
  for (const item of evidence) {
    if (item.commit.status === 'committed' && !gitCommitSha.safeParse(item.commit.commitSha).success) {
      throw acknowledgmentAmbiguous(`local commit evidence for ${item.artifact.checkpoint_id} has an invalid sha`);
    }
    if (item.attempt?.kind === 'anchor') {
      if (item.commit.status !== 'committed' || item.attempt.value.remote_sha !== item.commit.commitSha) {
        throw acknowledgmentAmbiguous(`anchor for ${item.artifact.checkpoint_id} does not bind its exact commit`);
      }
    }
    if (
      item.attempt?.kind === 'anchor_failed' &&
      item.attempt.failureClass === 'remote_definite_absence' &&
      item.commit.status !== 'committed'
    ) {
      throw acknowledgmentAmbiguous(
        `remote definite-absence evidence for ${item.artifact.checkpoint_id} has no exact local commit`,
      );
    }
  }
  return evidence;
}

function allLocalEntries(local: LocalChains): number {
  return local.heads.reduce((total, head) => total + head.length, 0);
}

function openWindow(
  anchor: CheckpointArtifact | null,
  local: LocalChains,
  now: string,
): { readonly entries: number; readonly minutes: number | null } {
  if (anchor === null) return { entries: allLocalEntries(local), minutes: null };
  return {
    entries: assertExtendsCheckpoint(anchor, local),
    minutes: Math.max(0, Math.floor((Date.parse(now) - Date.parse(anchor.created_at)) / 60_000)),
  };
}

export async function verifyRecords(options: VerifyRecordsOptions): Promise<RecordsVerificationReport> {
  const checkpoints = readCheckpointSet(options.checkpointsRoot);
  const local = verifyLocalChains(options.recordsRoot);
  const latest = checkpoints.artifacts.at(-1)?.artifact ?? null;
  if (latest !== null) assertExtendsCheckpoint(latest, local);
  const attempts = readAnchorAttempts(options.recordsRoot, options.worldId ?? 'w-demo', checkpoints);
  const now = timestamp.parse((options.now ?? (() => new Date().toISOString()))());
  const warnings: string[] = [];
  let latestPushedCheckpoint: LatestPushedCheckpoint | null = null;
  let remotelyAcknowledged: RemotelyAcknowledgedCheckpoint | null = null;
  let remoteStatus: RecordsVerificationReport['remoteStatus'] = 'not_checked';
  if (options.local) {
    warnings.push('local mode: remote checkpoint presence was not checked');
  } else if (latest !== null && checkpoints.pointer !== null) {
    const evidence = await resolveCheckpointEvidence(checkpoints, attempts, options);
    const commits = evidence.flatMap((item) => item.commit.status === 'committed' ? [item.commit.commitSha] : []);
    const observation = validateRemoteObservation(
      await (options.remoteObserver ?? observeCheckpointRemote)({
        repoRoot: options.repoRoot ?? process.cwd(),
        commitShas: commits,
        ...(options.branch === undefined ? {} : { branch: options.branch }),
        ...(options.repoUrl === undefined ? {} : { repoUrl: options.repoUrl }),
      }),
      options,
    );
    const decision = classifyRemoteAcknowledgment(evidence, observation);
    if (decision.status === 'remote_rollback') {
      throw new RecordVerificationError('remote-rollback', `remote checkpoint rollback: ${decision.reason}`);
    }
    if (decision.status === 'remote_acknowledgment_ambiguous') {
      throw acknowledgmentAmbiguous(`remote checkpoint acknowledgment is ambiguous: ${decision.reason}`);
    }
    remoteStatus = decision.status;
    if (decision.status === 'unavailable') {
      warnings.push(decision.reason);
    } else if (decision.status === 'unanchored_local_candidate') {
      warnings.push(`latest local checkpoint ${latest.checkpoint_id} is definitely unacknowledged`);
      if (decision.priorAcknowledged?.commit.status === 'committed' && observation.status === 'ref_present') {
        latestPushedCheckpoint = {
          artifact: decision.priorAcknowledged.artifact,
          commitSha: decision.priorAcknowledged.commit.commitSha,
          remoteHeadSha: observation.remoteHeadSha,
          repoUrl: observation.repoUrl,
          branch: observation.branch,
          observedAt: now,
        };
      }
    } else {
      if (decision.checkpoint.commit.status !== 'committed') {
        throw acknowledgmentAmbiguous('acknowledged checkpoint has no exact local commit');
      }
      latestPushedCheckpoint = {
        artifact: decision.checkpoint.artifact,
        commitSha: decision.checkpoint.commit.commitSha,
        remoteHeadSha: decision.observation.remoteHeadSha,
        repoUrl: decision.observation.repoUrl,
        branch: decision.observation.branch,
        observedAt: now,
      };
      remotelyAcknowledged = {
        checkpoint_id: decision.checkpoint.artifact.checkpoint_id,
        composite_digest: decision.checkpoint.artifact.composite_digest,
        checkpoint_commit_sha: decision.checkpoint.commit.commitSha,
        remote_head_sha: decision.observation.remoteHeadSha,
        repo_url: decision.observation.repoUrl,
        branch: decision.observation.branch,
        observed_at: now,
      };
    }
  }
  const window = openWindow(latestPushedCheckpoint?.artifact ?? null, local, now);
  const checkpointLabel = latest === null
    ? 'no local checkpoint'
    : `no local divergence detected as of checkpoint ${checkpointNumber(latest.seq)}`;
  const anchorLabel = latestPushedCheckpoint === null
    ? 'no prior acknowledged checkpoint'
    : `remote acknowledgment ${checkpointNumber(latestPushedCheckpoint.artifact.seq)}`;
  const windowLabel = window.minutes === null
    ? `${window.entries} entries are unanchored`
    : `un-anchored window ${window.minutes} min / ${window.entries} entries`;
  const modeLabel = options.local ? 'local mode; remote presence not checked' : 'remote mode';
  const message = `${checkpointLabel}; ${anchorLabel}; ${windowLabel}; ${modeLabel}`;
  await options.recordVerification?.(local.readLengths);
  return {
    mode: options.local ? 'local' : 'remote',
    remoteStatus,
    checkpoint: latest,
    latestPushedCheckpoint,
    remotelyAcknowledged,
    readLengths: local.readLengths,
    unanchoredWindowEntries: window.entries,
    unanchoredWindowMinutes: window.minutes,
    warnings,
    message,
  };
}

export async function recordVerificationAccess(
  store: WalStore,
  readLengths: Readonly<Record<string, number>>,
): Promise<void> {
  const entryId = `acc_verify_${randomUUID().replaceAll('-', '')}`;
  await store.transactWithState('record_verification', { credential: 'proc:authz', claimed_role: null }, (state, at) => ({
    ops: [
      {
        op: 'record.access.append' as const,
        entry: accessEntry.parse({
          world_id: state.worldId,
          entry_id: entryId,
          at,
          route: 'VERIFY records',
          authenticated_actor: 'proc:authz',
          claimed_actor: null,
          outcome: 'served',
          http_status: 200,
          read_lengths: readLengths,
        }),
      },
    ],
    result: undefined,
  }));
}

export interface CheckpointReceiptReference {
  readonly checkpoint_id: string;
  readonly composite_digest: string;
  readonly remote_commit_sha: string;
  readonly repo_url: string;
  readonly world_action_chain_length_at_anchor: number;
  readonly action_entry_index: number;
  readonly action_inside_anchored_prefix: boolean;
}

export function checkpointReceiptReference(
  report: RecordsVerificationReport | undefined,
  world: string,
  actionEntryIndex: number,
): CheckpointReceiptReference | null {
  if (!Number.isSafeInteger(actionEntryIndex) || actionEntryIndex < 0) {
    throw new RangeError('actionEntryIndex must be a non-negative safe integer');
  }
  const pushed = report?.latestPushedCheckpoint;
  if (pushed === undefined || pushed === null) return null;
  const actionHead = pushed.artifact.streams.find((head) => head.world === world && head.stream === 'action');
  if (actionHead === undefined) return null;
  return {
    checkpoint_id: pushed.artifact.checkpoint_id,
    composite_digest: pushed.artifact.composite_digest,
    remote_commit_sha: pushed.commitSha,
    repo_url: pushed.repoUrl,
    world_action_chain_length_at_anchor: actionHead.length,
    action_entry_index: actionEntryIndex,
    action_inside_anchored_prefix: actionEntryIndex < actionHead.length,
  };
}
