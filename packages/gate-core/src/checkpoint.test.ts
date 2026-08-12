// SPDX-License-Identifier: AGPL-3.0-only
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { appendEntry, verifyChain } from './chain.js';
import {
  checkpointReceiptReference,
  resolveCheckpointCommit,
  verifyRecords,
  writeCheckpoint,
} from './checkpoint.js';
import { WalStore } from './walStore.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const roots: string[] = [];
const DIGEST = 'a'.repeat(64);
const COMMIT_1 = 'b'.repeat(40);
const COMMIT_2 = 'c'.repeat(40);
const REMOTE_HEAD = 'd'.repeat(40);
const REPO_URL = 'https://github.com/example/runtime';

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function temporaryRoots(label: string): { recordsRoot: string; checkpointsRoot: string } {
  const root = mkdtempSync(join(tmpdir(), `checkpoint-${label}-`));
  roots.push(root);
  return { recordsRoot: join(root, 'records'), checkpointsRoot: join(root, 'checkpoints') };
}

const streamDefinitions = [
  { stream: 'access', file: 'access.jsonl', domain: 'access-entry' },
  { stream: 'action', file: 'action.jsonl', domain: 'record-entry' },
  { stream: 'wal', file: 'wal.jsonl', domain: 'wal-entry' },
] as const;

function createSyntheticStreams(recordsRoot: string, entriesPerStream = 1): void {
  const worldRoot = join(recordsRoot, 'w-demo');
  mkdirSync(worldRoot, { recursive: true });
  for (const definition of streamDefinitions) {
    const file = join(worldRoot, definition.file);
    writeFileSync(file, '', 'utf8');
    for (let index = 0; index < entriesPerStream; index += 1) {
      appendEntry(file, definition.domain, { kind: 'synthetic', stream: definition.stream, value: index });
    }
  }
}

function appendSynthetic(recordsRoot: string, stream: (typeof streamDefinitions)[number]['stream'], value: number): void {
  const definition = streamDefinitions.find((candidate) => candidate.stream === stream);
  if (definition === undefined) throw new Error(`unknown stream ${stream}`);
  appendEntry(join(recordsRoot, 'w-demo', definition.file), definition.domain, {
    kind: 'synthetic',
    stream,
    value,
  });
}

function appendAnchorAttempt(
  recordsRoot: string,
  value:
    | {
        readonly event: 'anchor';
        readonly checkpoint_id: string;
        readonly composite_digest: string;
        readonly remote_sha: string;
      }
    | { readonly event: 'anchor_failed'; readonly checkpoint_id: string; readonly error_class: string },
): void {
  appendEntry(join(recordsRoot, 'w-demo', 'access.jsonl'), 'access-entry', {
    ...value,
    world_id: 'w-demo',
    at: '2026-08-02T14:00:30.000Z',
  });
}

function localCommits(values: Readonly<Record<string, string | null>>) {
  return async ({ artifact }: { readonly artifact: { readonly checkpoint_id: string } }) => {
    const commitSha = values[artifact.checkpoint_id];
    if (commitSha === undefined) throw new Error(`missing synthetic local evidence for ${artifact.checkpoint_id}`);
    return commitSha === null
      ? { status: 'uncommitted' as const }
      : { status: 'committed' as const, commitSha };
  };
}

function remoteRef(contains: Readonly<Record<string, boolean>>) {
  return async () => ({
    status: 'ref_present' as const,
    remoteHeadSha: REMOTE_HEAD,
    repoUrl: REPO_URL,
    branch: 'main',
    contains,
  });
}

async function checkpoint(
  recordsRoot: string,
  checkpointsRoot: string,
  createdAt: string,
  reason = 'run-end',
) {
  return writeCheckpoint({
    recordsRoot,
    checkpointsRoot,
    reason,
    runId: 'run_checkpoint_test',
    policyContentDigest: DIGEST,
    evaluatorBuildId: 'gate-core@test',
    now: () => createdAt,
    mode: 'write-only',
  });
}

async function pairedCheckpoints(label: string) {
  const rootsForCase = temporaryRoots(label);
  createSyntheticStreams(rootsForCase.recordsRoot);
  const first = await checkpoint(rootsForCase.recordsRoot, rootsForCase.checkpointsRoot, '2026-08-02T14:00:00.000Z');
  appendAnchorAttempt(rootsForCase.recordsRoot, {
    event: 'anchor',
    checkpoint_id: first.checkpoint_id,
    composite_digest: first.composite_digest,
    remote_sha: COMMIT_1,
  });
  appendSynthetic(rootsForCase.recordsRoot, 'action', 2);
  const second = await checkpoint(rootsForCase.recordsRoot, rootsForCase.checkpointsRoot, '2026-08-02T14:05:00.000Z');
  return { ...rootsForCase, first, second };
}

function systemEnvironment(): NodeJS.ProcessEnv {
  const names = ['SystemRoot', 'TEMP', 'TMP', 'ComSpec', 'PATHEXT', 'Path', 'PATH'];
  return Object.fromEntries(names.flatMap((name) => (process.env[name] === undefined ? [] : [[name, process.env[name]]])));
}

describe('ADR-003 local checkpoint detector', () => {
  it('writes sorted composite checkpoints, chains them, and accepts legitimate extensions', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('writer');
    createSyntheticStreams(recordsRoot);
    const first = await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T10:00:00.000Z');

    expect(first).toMatchObject({
      seq: 1,
      checkpoint_id: 'cp-0001',
      prev_checkpoint_id: null,
      prev_checkpoint_digest: null,
    });
    expect(first.streams.map(({ world, stream }) => `${world}/${stream}`)).toEqual([
      'w-demo/access',
      'w-demo/action',
      'w-demo/wal',
    ]);

    for (const definition of streamDefinitions) appendSynthetic(recordsRoot, definition.stream, 2);
    let recordedLengths: Readonly<Record<string, number>> | undefined;
    const extended = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: true,
      now: () => '2026-08-02T10:05:00.000Z',
      recordVerification: async (readLengths) => {
        recordedLengths = readLengths;
        appendSynthetic(recordsRoot, 'access', 3);
      },
    });
    expect(extended.unanchoredWindowEntries).toBe(6);
    expect(extended.unanchoredWindowMinutes).toBeNull();
    expect(extended.latestPushedCheckpoint).toBeNull();
    expect(extended.message).toContain('local mode; remote presence not checked');
    expect(recordedLengths).toEqual({ 'w-demo/access': 2, 'w-demo/action': 2, 'w-demo/wal': 2 });
    expect(verifyChain(join(recordsRoot, 'w-demo', 'access.jsonl'), 'access-entry')).toMatchObject({
      ok: true,
      length: 3,
    });

    const second = await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T10:06:00.000Z');
    expect(second.seq).toBe(2);
    expect(second.prev_checkpoint_id).toBe(first.checkpoint_id);
    expect(second.prev_checkpoint_digest).toMatch(/^[0-9a-f]{64}$/);
    const verified = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: true,
      now: () => '2026-08-02T10:06:00.000Z',
    });
    expect(verified.unanchoredWindowEntries).toBe(7);
  });

  it('detects in-line chain tampering at the first changed index', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('tamper');
    createSyntheticStreams(recordsRoot);
    await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T11:00:00.000Z');
    const actionFile = join(recordsRoot, 'w-demo', 'action.jsonl');
    const raw = readFileSync(actionFile, 'utf8');
    writeFileSync(actionFile, raw.replace('"value":0', '"value":9'), 'utf8');

    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: true,
        now: () => '2026-08-02T11:01:00.000Z',
      }),
    ).rejects.toMatchObject({ code: 'chain-tamper', world: 'w-demo', stream: 'action', divergenceIndex: 0 });
  });

  it('raises a rollback alarm when a locally valid prefix is shorter than its anchor', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('rollback');
    createSyntheticStreams(recordsRoot, 2);
    await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T12:00:00.000Z');
    const actionFile = join(recordsRoot, 'w-demo', 'action.jsonl');
    const firstLine = readFileSync(actionFile, 'utf8').split('\n')[0];
    writeFileSync(actionFile, `${firstLine}\n`, 'utf8');
    expect(verifyChain(actionFile, 'record-entry')).toMatchObject({ ok: true, length: 1 });

    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: true,
        now: () => '2026-08-02T12:01:00.000Z',
      }),
    ).rejects.toMatchObject({ code: 'rollback', world: 'w-demo', stream: 'action', divergenceIndex: 1 });
  });

  it('detects a rolled-back latest pointer and a hand-edited composite', async () => {
    const pointerRoots = temporaryRoots('pointer');
    createSyntheticStreams(pointerRoots.recordsRoot);
    await checkpoint(pointerRoots.recordsRoot, pointerRoots.checkpointsRoot, '2026-08-02T13:00:00.000Z');
    const firstPointer = readFileSync(join(pointerRoots.checkpointsRoot, 'latest.json'), 'utf8');
    appendSynthetic(pointerRoots.recordsRoot, 'wal', 2);
    await checkpoint(pointerRoots.recordsRoot, pointerRoots.checkpointsRoot, '2026-08-02T13:01:00.000Z');
    writeFileSync(join(pointerRoots.checkpointsRoot, 'latest.json'), firstPointer, 'utf8');
    await expect(
      verifyRecords({
        ...pointerRoots,
        local: true,
        now: () => '2026-08-02T13:02:00.000Z',
      }),
    ).rejects.toMatchObject({ code: 'checkpoint-pointer' });

    const compositeRoots = temporaryRoots('composite');
    createSyntheticStreams(compositeRoots.recordsRoot);
    const artifact = await checkpoint(
      compositeRoots.recordsRoot,
      compositeRoots.checkpointsRoot,
      '2026-08-02T13:03:00.000Z',
    );
    const file = join(compositeRoots.checkpointsRoot, '0001-20260802T130300Z.json');
    writeFileSync(file, `${JSON.stringify({ ...artifact, composite_digest: 'f'.repeat(64) })}\n`, 'utf8');
    await expect(
      verifyRecords({
        ...compositeRoots,
        local: true,
        now: () => '2026-08-02T13:04:00.000Z',
      }),
    ).rejects.toMatchObject({ code: 'checkpoint-composite' });
  });

  it('builds receipt references only from a remotely confirmed checkpoint', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('receipt');
    createSyntheticStreams(recordsRoot);
    await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T14:00:00.000Z');
    const report = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: false,
      now: () => '2026-08-02T14:01:00.000Z',
      localCommitResolver: localCommits({ 'cp-0001': COMMIT_1 }),
      remoteObserver: remoteRef({ [COMMIT_1]: true }),
    });
    expect(report.remoteStatus).toBe('acknowledged');
    expect(report.remotelyAcknowledged).toEqual({
      checkpoint_id: 'cp-0001',
      composite_digest: report.checkpoint?.composite_digest,
      checkpoint_commit_sha: COMMIT_1,
      remote_head_sha: REMOTE_HEAD,
      repo_url: REPO_URL,
      branch: 'main',
      observed_at: '2026-08-02T14:01:00.000Z',
    });
    expect(checkpointReceiptReference(report, 'w-demo', 0)).toEqual({
      checkpoint_id: 'cp-0001',
      composite_digest: report.checkpoint?.composite_digest,
      remote_commit_sha: COMMIT_1,
      repo_url: REPO_URL,
      world_action_chain_length_at_anchor: 1,
      action_entry_index: 0,
      action_inside_anchored_prefix: true,
    });
    expect(checkpointReceiptReference(report, 'w-demo', 1)).toMatchObject({
      action_entry_index: 1,
      action_inside_anchored_prefix: false,
    });
    const local = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: true,
      now: () => '2026-08-02T14:01:00.000Z',
    });
    expect(checkpointReceiptReference(local, 'w-demo', 0)).toBeNull();
    expect(local.remotelyAcknowledged).toBeNull();
  });

  it('reports remote unavailability but halts when a previously acknowledged checkpoint disappears', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('remote-asymmetry');
    createSyntheticStreams(recordsRoot);
    const artifact = await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T15:00:00.000Z');
    appendAnchorAttempt(recordsRoot, {
      event: 'anchor',
      checkpoint_id: artifact.checkpoint_id,
      composite_digest: artifact.composite_digest,
      remote_sha: COMMIT_1,
    });

    const unavailable = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: false,
      now: () => '2026-08-02T15:01:00.000Z',
      localCommitResolver: localCommits({ 'cp-0001': COMMIT_1 }),
      remoteObserver: async () => ({ status: 'unavailable', reason: 'synthetic remote outage' }),
    });
    expect(unavailable.remoteStatus).toBe('unavailable');
    expect(unavailable.latestPushedCheckpoint).toBeNull();
    expect(unavailable.remotelyAcknowledged).toBeNull();
    expect(unavailable.warnings).toContain('synthetic remote outage');

    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: false,
        now: () => '2026-08-02T15:01:00.000Z',
        localCommitResolver: localCommits({ 'cp-0001': COMMIT_1 }),
        remoteObserver: async () => ({ status: 'ref_absent', repoUrl: REPO_URL, branch: 'main' }),
      }),
    ).rejects.toMatchObject({ code: 'remote-rollback' });
  });

  it('uses the current prior acknowledgment for a definitely unacknowledged latest candidate', async () => {
    const { recordsRoot, checkpointsRoot, second } = await pairedCheckpoints('prior-anchor-window');
    appendAnchorAttempt(recordsRoot, {
      event: 'anchor_failed',
      checkpoint_id: second.checkpoint_id,
      error_class: 'remote_definite_absence',
    });
    const report = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: false,
      now: () => '2026-08-02T14:10:00.000Z',
      localCommitResolver: localCommits({ 'cp-0001': COMMIT_1, 'cp-0002': COMMIT_2 }),
      remoteObserver: remoteRef({ [COMMIT_1]: true, [COMMIT_2]: false }),
    });

    expect(report.remoteStatus).toBe('unanchored_local_candidate');
    expect(report.latestPushedCheckpoint).toMatchObject({
      artifact: { checkpoint_id: 'cp-0001' },
      commitSha: COMMIT_1,
      remoteHeadSha: REMOTE_HEAD,
    });
    expect(report.remotelyAcknowledged).toBeNull();
    expect(report.unanchoredWindowEntries).toBe(3);
    expect(report.unanchoredWindowMinutes).toBe(10);
    expect(checkpointReceiptReference(report, 'w-demo', 0)).toMatchObject({
      checkpoint_id: 'cp-0001',
      remote_commit_sha: COMMIT_1,
    });
  });

  it('accepts current positive presence after an ambiguous push without synthesizing recovery evidence', async () => {
    const { recordsRoot, checkpointsRoot, second } = await pairedCheckpoints('positive-after-ambiguous');
    appendAnchorAttempt(recordsRoot, {
      event: 'anchor_failed',
      checkpoint_id: second.checkpoint_id,
      error_class: 'acknowledgment_unknown',
    });
    const report = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: false,
      now: () => '2026-08-02T14:06:00.000Z',
      localCommitResolver: localCommits({ 'cp-0001': COMMIT_1, 'cp-0002': COMMIT_2 }),
      remoteObserver: remoteRef({ [COMMIT_1]: true, [COMMIT_2]: true }),
    });

    expect(report.remoteStatus).toBe('acknowledged');
    expect(report.remotelyAcknowledged).toMatchObject({
      checkpoint_id: 'cp-0002',
      checkpoint_commit_sha: COMMIT_2,
      remote_head_sha: REMOTE_HEAD,
      observed_at: '2026-08-02T14:06:00.000Z',
    });
    expect(report.unanchoredWindowEntries).toBe(1);
    expect(report.unanchoredWindowMinutes).toBe(1);
  });

  it('checks prior-anchor containment before candidate presence', async () => {
    const { recordsRoot, checkpointsRoot, second } = await pairedCheckpoints('dropped-prior');
    appendAnchorAttempt(recordsRoot, {
      event: 'anchor_failed',
      checkpoint_id: second.checkpoint_id,
      error_class: 'acknowledgment_unknown',
    });
    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: false,
        localCommitResolver: localCommits({ 'cp-0001': COMMIT_1, 'cp-0002': COMMIT_2 }),
        remoteObserver: remoteRef({ [COMMIT_1]: false, [COMMIT_2]: true }),
      }),
    ).rejects.toMatchObject({ code: 'remote-rollback' });
  });

  it('classifies a definitely failed uncommitted first checkpoint without claiming remote acknowledgment', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('uncommitted-first');
    createSyntheticStreams(recordsRoot);
    const artifact = await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T14:00:00.000Z');
    appendAnchorAttempt(recordsRoot, {
      event: 'anchor_failed',
      checkpoint_id: artifact.checkpoint_id,
      error_class: 'pre_remote_failure',
    });
    const report = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: false,
      localCommitResolver: localCommits({ 'cp-0001': null }),
      remoteObserver: async () => ({ status: 'ref_absent', repoUrl: REPO_URL, branch: 'main' }),
    });
    expect(report.remoteStatus).toBe('unanchored_local_candidate');
    expect(report.latestPushedCheckpoint).toBeNull();
    expect(report.remotelyAcknowledged).toBeNull();
    expect(report.unanchoredWindowEntries).toBe(4);
    expect(report.unanchoredWindowMinutes).toBeNull();
  });

  it('does not infer honest-unpushed from remote absence when no prior acknowledgment or terminal evidence exists', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('no-prior-ambiguous');
    createSyntheticStreams(recordsRoot);
    await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T14:00:00.000Z');
    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: false,
        localCommitResolver: localCommits({ 'cp-0001': COMMIT_1 }),
        remoteObserver: async () => ({ status: 'ref_absent', repoUrl: REPO_URL, branch: 'main' }),
      }),
    ).rejects.toMatchObject({ code: 'remote-acknowledgment-ambiguous' });
  });

  it.each([
    ['missing terminal evidence', (_recordsRoot: string, _second: Awaited<ReturnType<typeof checkpoint>>) => undefined],
    ['unknown failure class', (recordsRoot: string, second: Awaited<ReturnType<typeof checkpoint>>) => {
      appendAnchorAttempt(recordsRoot, {
        event: 'anchor_failed',
        checkpoint_id: second.checkpoint_id,
        error_class: 'synthetic_unknown',
      });
    }],
    ['duplicate terminal evidence', (recordsRoot: string, second: Awaited<ReturnType<typeof checkpoint>>) => {
      for (let index = 0; index < 2; index += 1) {
        appendAnchorAttempt(recordsRoot, {
          event: 'anchor_failed',
          checkpoint_id: second.checkpoint_id,
          error_class: 'remote_definite_absence',
        });
      }
    }],
    ['contradictory terminal evidence', (recordsRoot: string, second: Awaited<ReturnType<typeof checkpoint>>) => {
      appendAnchorAttempt(recordsRoot, {
        event: 'anchor',
        checkpoint_id: second.checkpoint_id,
        composite_digest: second.composite_digest,
        remote_sha: COMMIT_2,
      });
      appendAnchorAttempt(recordsRoot, {
        event: 'anchor_failed',
        checkpoint_id: second.checkpoint_id,
        error_class: 'remote_definite_absence',
      });
    }],
    ['mis-bound terminal evidence', (recordsRoot: string, second: Awaited<ReturnType<typeof checkpoint>>) => {
      appendAnchorAttempt(recordsRoot, {
        event: 'anchor',
        checkpoint_id: second.checkpoint_id,
        composite_digest: 'f'.repeat(64),
        remote_sha: COMMIT_2,
      });
    }],
  ])('halts on %s with a reachable remote', async (label, appendAttempt) => {
    const { recordsRoot, checkpointsRoot, second } = await pairedCheckpoints(`ambiguous-${label.replaceAll(' ', '-')}`);
    appendAttempt(recordsRoot, second);
    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: false,
        localCommitResolver: localCommits({ 'cp-0001': COMMIT_1, 'cp-0002': COMMIT_2 }),
        remoteObserver: remoteRef({ [COMMIT_1]: true, [COMMIT_2]: false }),
      }),
    ).rejects.toMatchObject({ code: 'remote-acknowledgment-ambiguous' });
  });

  it('halts when the observer omits a required containment result', async () => {
    const { recordsRoot, checkpointsRoot, second } = await pairedCheckpoints('missing-containment');
    appendAnchorAttempt(recordsRoot, {
      event: 'anchor_failed',
      checkpoint_id: second.checkpoint_id,
      error_class: 'remote_definite_absence',
    });
    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: false,
        localCommitResolver: localCommits({ 'cp-0001': COMMIT_1, 'cp-0002': COMMIT_2 }),
        remoteObserver: remoteRef({ [COMMIT_1]: true }),
      }),
    ).rejects.toMatchObject({ code: 'remote-acknowledgment-ambiguous' });
  });

  it('rejects definite remote-absence evidence for an uncommitted checkpoint before observing the remote', async () => {
    const { recordsRoot, checkpointsRoot, second } = await pairedCheckpoints('uncommitted-definite-absence');
    appendAnchorAttempt(recordsRoot, {
      event: 'anchor_failed',
      checkpoint_id: second.checkpoint_id,
      error_class: 'remote_definite_absence',
    });
    let observed = false;
    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: false,
        localCommitResolver: localCommits({ 'cp-0001': COMMIT_1, 'cp-0002': null }),
        remoteObserver: async () => {
          observed = true;
          return { status: 'ref_absent', repoUrl: REPO_URL, branch: 'main' };
        },
      }),
    ).rejects.toMatchObject({ code: 'remote-acknowledgment-ambiguous' });
    expect(observed).toBe(false);
  });

  it('binds local commit evidence to the exact checkpoint artifact and matching pointer bytes', async () => {
    const root = mkdtempSync(join(tmpdir(), 'checkpoint-commit-bytes-'));
    roots.push(root);
    const recordsRoot = join(root, 'records');
    const checkpointsRoot = join(root, 'docs', 'checkpoints');
    createSyntheticStreams(recordsRoot);
    const artifact = await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T16:00:00.000Z');
    const file = '0001-20260802T160000Z.json';
    const artifactFile = join(checkpointsRoot, file);
    const committedArtifact = readFileSync(artifactFile, 'utf8');
    const committedPointer = readFileSync(join(checkpointsRoot, 'latest.json'), 'utf8');
    const gitRunner = async (_cwd: string, args: readonly string[]) => {
      const command = args.join(' ');
      if (command.startsWith('log --format=%H -- ')) return { stdout: `${COMMIT_1}\n`, exitCode: 0 as const };
      if (command === `show ${COMMIT_1}:docs/checkpoints/${file}`) {
        return { stdout: committedArtifact, exitCode: 0 as const };
      }
      if (command === `show ${COMMIT_1}:docs/checkpoints/latest.json`) {
        return { stdout: committedPointer, exitCode: 0 as const };
      }
      throw new Error(`unexpected git command ${command}`);
    };

    await expect(
      resolveCheckpointCommit({ artifact, file, latest: true, checkpointsRoot, repoRoot: root, gitRunner }),
    ).resolves.toEqual({ status: 'committed', commitSha: COMMIT_1 });

    const supportOnlyRunner = async (cwd: string, args: readonly string[]) => {
      const command = args.join(' ');
      if (command === `show ${COMMIT_1}:docs/checkpoints/latest.json`) {
        return { stdout: '{"checkpoint_id":"cp-0002"}\n', exitCode: 0 as const };
      }
      return gitRunner(cwd, args);
    };
    await expect(
      resolveCheckpointCommit({
        artifact,
        file,
        latest: false,
        checkpointsRoot,
        repoRoot: root,
        gitRunner: supportOnlyRunner,
      }),
    ).resolves.toEqual({ status: 'uncommitted' });
    await expect(
      resolveCheckpointCommit({
        artifact,
        file,
        latest: true,
        checkpointsRoot,
        repoRoot: root,
        gitRunner: supportOnlyRunner,
      }),
    ).rejects.toMatchObject({ code: 'remote-acknowledgment-ambiguous' });

    writeFileSync(artifactFile, `${committedArtifact.trim()} \n`, 'utf8');
    await expect(
      resolveCheckpointCommit({ artifact, file, latest: true, checkpointsRoot, repoRoot: root, gitRunner }),
    ).rejects.toMatchObject({ code: 'remote-acknowledgment-ambiguous' });
  });

  it('runs verify:records --local and records the lengths only after reading', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('cli');
    const store = WalStore.open({
      recordsRoot,
      worldId: 'w-demo',
      runId: 'run_before_cli',
      bootId: 'authz_boot_before_cli',
      policyVersion: 'policy-test',
      policyContentDigest: DIGEST,
      evaluatorBuildDigest: DIGEST,
      now: () => '2026-08-02T00:00:00.000Z',
    });
    store.close();
    await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T00:01:00.000Z');

    const result = spawnSync(process.execPath, [join(ROOT, 'tooling', 'verify-records.mjs'), '--local'], {
      cwd: ROOT,
      env: {
        ...systemEnvironment(),
        RUNTIME_RECORDS_ROOT: recordsRoot,
        RUNTIME_CHECKPOINTS_ROOT: checkpointsRoot,
        DEMO_WORLD_ID: 'w-demo',
      },
      encoding: 'utf8',
      windowsHide: true,
      timeout: 20_000,
    });

    expect(result.status).toBe(0);
    expect(result.stdout).toContain('no local divergence detected as of checkpoint 0001');
    expect(result.stdout).toContain('local mode; remote presence not checked');
    expect(result.stderr).toContain('remote checkpoint presence was not checked');
    expect(verifyChain(join(recordsRoot, 'w-demo', 'wal.jsonl'), 'wal-entry').ok).toBe(true);
    expect(verifyChain(join(recordsRoot, 'w-demo', 'access.jsonl'), 'access-entry')).toMatchObject({
      ok: true,
      length: 1,
    });
    const access = JSON.parse(readFileSync(join(recordsRoot, 'w-demo', 'access.jsonl'), 'utf8').trim()) as {
      read_lengths?: unknown;
    };
    expect(access.read_lengths).toEqual({ 'w-demo/access': 0, 'w-demo/action': 0, 'w-demo/wal': 2 });
  });
});
