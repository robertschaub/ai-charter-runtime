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
import { verifyChain } from './chain.js';
import type { ChainDomainTag } from './domain.js';
import { digestFor, isHexDigest, verifyDigest } from './hash.js';
import { accessEntry, hexDigest, id, integer, timestamp, worldId } from './schemas/index.js';
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
  | 'remote-mismatch';

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

export type RemoteCheckpointStatus =
  | {
      readonly status: 'confirmed';
      readonly commitSha: string;
      readonly remoteHeadSha: string;
      readonly repoUrl: string;
      readonly branch: string;
    }
  | { readonly status: 'unavailable'; readonly reason: string }
  | { readonly status: 'mismatch'; readonly reason: string };

export interface RemoteCheckpointContext {
  readonly artifact: CheckpointArtifact;
  readonly pointer: CheckpointPointer;
  readonly checkpointsRoot: string;
  readonly repoRoot: string;
  readonly branch?: string;
  readonly repoUrl?: string;
  readonly gitRunner?: CheckpointGitRunner;
}

export type RemoteCheckpointVerifier = (
  context: RemoteCheckpointContext,
) => Promise<RemoteCheckpointStatus>;

export type CheckpointGitRunner = (
  cwd: string,
  args: readonly string[],
  allowExitOne?: boolean,
) => Promise<{ readonly stdout: string; readonly exitCode: 0 | 1 }>;

export interface LatestPushedCheckpoint {
  readonly artifact: CheckpointArtifact;
  readonly commitSha: string;
  readonly repoUrl: string;
}

export interface RecordsVerificationReport {
  readonly mode: 'local' | 'remote';
  readonly checkpoint: CheckpointArtifact | null;
  readonly latestPushedCheckpoint: LatestPushedCheckpoint | null;
  readonly readLengths: Readonly<Record<string, number>>;
  readonly unanchoredWindowEntries: number;
  readonly unanchoredWindowMinutes: number | null;
  readonly warnings: readonly string[];
  readonly message: string;
}

export interface VerifyRecordsOptions {
  readonly recordsRoot: string;
  readonly checkpointsRoot: string;
  readonly local: boolean;
  readonly repoRoot?: string;
  readonly branch?: string;
  readonly repoUrl?: string;
  readonly now?: () => string;
  readonly remoteVerifier?: RemoteCheckpointVerifier;
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

export async function verifyCheckpointRemote(
  context: RemoteCheckpointContext,
): Promise<RemoteCheckpointStatus> {
  try {
    const executeGit = context.gitRunner ?? runGit;
    const repoRoot = resolve(context.repoRoot);
    const artifactPath = resolve(context.checkpointsRoot, context.pointer.file);
    const relativeArtifact = relative(repoRoot, artifactPath).replaceAll('\\', '/');
    if (relativeArtifact.startsWith('../') || relativeArtifact === '') {
      return { status: 'mismatch', reason: 'checkpoint artifact is outside the repository' };
    }
    const branchResult = context.branch === undefined
      ? await executeGit(repoRoot, ['symbolic-ref', '--short', 'HEAD'])
      : { stdout: context.branch, exitCode: 0 as const };
    const branch = branchResult.stdout.trim();
    if (!validBranch(branch)) return { status: 'unavailable', reason: 'repository has no verifiable branch' };
    const commitResult = await executeGit(repoRoot, ['log', '-n', '1', '--format=%H', '--', relativeArtifact]);
    const commitSha = commitResult.stdout.trim();
    if (!gitCommitSha.safeParse(commitSha).success) {
      return { status: 'mismatch', reason: 'latest checkpoint is not contained in a local commit' };
    }
    const relativePointer = relative(repoRoot, resolve(context.checkpointsRoot, 'latest.json')).replaceAll('\\', '/');
    if (relativePointer.startsWith('../') || relativePointer === '') {
      return { status: 'mismatch', reason: 'checkpoint pointer is outside the repository' };
    }
    let committedArtifact: string;
    let committedPointer: string;
    try {
      committedArtifact = (await executeGit(repoRoot, ['show', `${commitSha}:${relativeArtifact}`])).stdout;
      committedPointer = (await executeGit(repoRoot, ['show', `${commitSha}:${relativePointer}`])).stdout;
    } catch {
      return { status: 'mismatch', reason: 'checkpoint commit does not contain the artifact and pointer' };
    }
    const localArtifact = decodeUtf8(readFileSync(artifactPath), context.pointer.file);
    const localPointer = decodeUtf8(readFileSync(resolve(context.checkpointsRoot, 'latest.json')), 'latest.json');
    if (committedArtifact !== localArtifact || committedPointer !== localPointer) {
      return { status: 'mismatch', reason: 'local checkpoint bytes differ from the committed checkpoint' };
    }
    const originUrl = safeRepoUrl((await executeGit(repoRoot, ['remote', 'get-url', 'origin'])).stdout.trim());
    if (originUrl === null) return { status: 'unavailable', reason: 'origin is not a public HTTP repository URL' };
    const configuredUrl = context.repoUrl === undefined ? originUrl : safeRepoUrl(context.repoUrl);
    if (configuredUrl === null || configuredUrl !== originUrl) {
      return { status: 'mismatch', reason: 'configured checkpoint repository does not match origin' };
    }
    const repoUrl = configuredUrl;
    const ref = `refs/heads/${branch}`;
    const remoteOutput = (await executeGit(repoRoot, ['ls-remote', '--heads', 'origin', ref])).stdout.trim();
    const remoteLine = remoteOutput
      .split(/\r?\n/)
      .map((line) => line.trim().split(/\s+/))
      .find((parts) => parts[1] === ref);
    const remoteHeadSha = remoteLine?.[0] ?? '';
    if (!gitCommitSha.safeParse(remoteHeadSha).success) {
      return { status: 'mismatch', reason: `remote branch ${branch} does not resolve` };
    }
    if (remoteHeadSha !== commitSha) {
      const ancestor = await executeGit(repoRoot, ['merge-base', '--is-ancestor', commitSha, remoteHeadSha], true);
      if (ancestor.exitCode === 1) {
        return { status: 'mismatch', reason: 'remote branch does not contain the checkpoint commit' };
      }
    }
    return { status: 'confirmed', commitSha, remoteHeadSha, repoUrl, branch };
  } catch {
    return { status: 'unavailable', reason: 'remote checkpoint verification is unavailable' };
  }
}

export async function verifyRecords(options: VerifyRecordsOptions): Promise<RecordsVerificationReport> {
  const checkpoints = readCheckpointSet(options.checkpointsRoot);
  const local = verifyLocalChains(options.recordsRoot);
  const latest = checkpoints.artifacts.at(-1)?.artifact ?? null;
  const pointer = checkpoints.pointer;
  const unanchoredWindowEntries = latest === null
    ? local.heads.reduce((total, head) => total + head.length, 0)
    : assertExtendsCheckpoint(latest, local);
  const now = timestamp.parse((options.now ?? (() => new Date().toISOString()))());
  const unanchoredWindowMinutes = latest === null
    ? null
    : Math.max(0, Math.floor((Date.parse(now) - Date.parse(latest.created_at)) / 60_000));
  const warnings: string[] = [];
  let latestPushedCheckpoint: LatestPushedCheckpoint | null = null;
  if (latest !== null && pointer !== null) {
    if (options.local) {
      warnings.push('local mode: remote checkpoint presence was not checked');
    } else {
      const remote = await (options.remoteVerifier ?? verifyCheckpointRemote)({
        artifact: latest,
        pointer,
        checkpointsRoot: options.checkpointsRoot,
        repoRoot: options.repoRoot ?? process.cwd(),
        ...(options.branch === undefined ? {} : { branch: options.branch }),
        ...(options.repoUrl === undefined ? {} : { repoUrl: options.repoUrl }),
      });
      if (remote.status === 'mismatch') {
        throw new RecordVerificationError('remote-mismatch', `remote checkpoint mismatch: ${remote.reason}`);
      }
      if (remote.status === 'unavailable') warnings.push(remote.reason);
      else {
        latestPushedCheckpoint = {
          artifact: latest,
          commitSha: remote.commitSha,
          repoUrl: remote.repoUrl,
        };
      }
    }
  } else if (options.local) {
    warnings.push('local mode: remote checkpoint presence was not checked');
  }
  const checkpointLabel = latest === null
    ? 'no prior anchor'
    : `no divergence detected as of checkpoint ${checkpointNumber(latest.seq)}`;
  const windowLabel = latest === null
    ? `${unanchoredWindowEntries} entries are unanchored`
    : `un-anchored window ${unanchoredWindowMinutes} min / ${unanchoredWindowEntries} entries`;
  const modeLabel = options.local ? 'local mode; remote presence not checked' : 'remote mode';
  const message = `${checkpointLabel}; ${windowLabel}; ${modeLabel}`;
  await options.recordVerification?.(local.readLengths);
  return {
    mode: options.local ? 'local' : 'remote',
    checkpoint: latest,
    latestPushedCheckpoint,
    readLengths: local.readLengths,
    unanchoredWindowEntries,
    unanchoredWindowMinutes,
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
