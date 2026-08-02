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
  checkpointPointer,
  verifyCheckpointRemote,
  verifyRecords,
  writeCheckpoint,
} from './checkpoint.js';
import { WalStore } from './walStore.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const roots: string[] = [];
const DIGEST = 'a'.repeat(64);

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
    expect(extended.unanchoredWindowEntries).toBe(3);
    expect(extended.unanchoredWindowMinutes).toBe(5);
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
    expect(verified.unanchoredWindowEntries).toBe(0);
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
      remoteVerifier: async () => ({
        status: 'confirmed',
        commitSha: 'b'.repeat(40),
        remoteHeadSha: 'c'.repeat(40),
        repoUrl: 'https://github.com/example/runtime',
        branch: 'main',
      }),
    });
    expect(checkpointReceiptReference(report, 'w-demo', 0)).toEqual({
      checkpoint_id: 'cp-0001',
      composite_digest: report.checkpoint?.composite_digest,
      remote_commit_sha: 'b'.repeat(40),
      repo_url: 'https://github.com/example/runtime',
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
  });

  it('reports remote unavailability but fails on a confirmed remote mismatch', async () => {
    const { recordsRoot, checkpointsRoot } = temporaryRoots('remote-asymmetry');
    createSyntheticStreams(recordsRoot);
    await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T15:00:00.000Z');

    const unavailable = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local: false,
      now: () => '2026-08-02T15:01:00.000Z',
      remoteVerifier: async () => ({ status: 'unavailable', reason: 'synthetic remote outage' }),
    });
    expect(unavailable.latestPushedCheckpoint).toBeNull();
    expect(unavailable.warnings).toContain('synthetic remote outage');

    await expect(
      verifyRecords({
        recordsRoot,
        checkpointsRoot,
        local: false,
        now: () => '2026-08-02T15:01:00.000Z',
        remoteVerifier: async () => ({ status: 'mismatch', reason: 'synthetic remote rollback' }),
      }),
    ).rejects.toMatchObject({ code: 'remote-mismatch' });
  });

  it('binds remote confirmation to the exact committed artifact and pointer bytes', async () => {
    const root = mkdtempSync(join(tmpdir(), 'checkpoint-remote-bytes-'));
    roots.push(root);
    const recordsRoot = join(root, 'records');
    const checkpointsRoot = join(root, 'docs', 'checkpoints');
    createSyntheticStreams(recordsRoot);
    const artifact = await checkpoint(recordsRoot, checkpointsRoot, '2026-08-02T16:00:00.000Z');
    const pointer = checkpointPointer.parse(
      JSON.parse(readFileSync(join(checkpointsRoot, 'latest.json'), 'utf8')) as unknown,
    );
    const artifactFile = join(checkpointsRoot, pointer.file);
    const committedArtifact = readFileSync(artifactFile, 'utf8');
    const committedPointer = readFileSync(join(checkpointsRoot, 'latest.json'), 'utf8');
    const commitSha = 'b'.repeat(40);
    const remoteHeadSha = 'c'.repeat(40);
    const gitRunner = async (_cwd: string, args: readonly string[]) => {
      const command = args.join(' ');
      if (command === 'symbolic-ref --short HEAD') return { stdout: 'main\n', exitCode: 0 as const };
      if (command.startsWith('log -n 1 --format=%H -- ')) return { stdout: `${commitSha}\n`, exitCode: 0 as const };
      if (command === `show ${commitSha}:docs/checkpoints/${pointer.file}`) {
        return { stdout: committedArtifact, exitCode: 0 as const };
      }
      if (command === `show ${commitSha}:docs/checkpoints/latest.json`) {
        return { stdout: committedPointer, exitCode: 0 as const };
      }
      if (command === 'remote get-url origin') {
        return { stdout: 'https://github.com/example/runtime.git\n', exitCode: 0 as const };
      }
      if (command === 'ls-remote --heads origin refs/heads/main') {
        return { stdout: `${remoteHeadSha}\trefs/heads/main\n`, exitCode: 0 as const };
      }
      if (command === `merge-base --is-ancestor ${commitSha} ${remoteHeadSha}`) {
        return { stdout: '', exitCode: 0 as const };
      }
      throw new Error(`unexpected git command ${command}`);
    };

    await expect(
      verifyCheckpointRemote({ artifact, pointer, checkpointsRoot, repoRoot: root, gitRunner }),
    ).resolves.toMatchObject({
      status: 'confirmed',
      commitSha,
      remoteHeadSha,
      repoUrl: 'https://github.com/example/runtime',
      branch: 'main',
    });

    writeFileSync(artifactFile, `${committedArtifact.trim()} \n`, 'utf8');
    await expect(
      verifyCheckpointRemote({ artifact, pointer, checkpointsRoot, repoRoot: root, gitRunner }),
    ).resolves.toMatchObject({ status: 'mismatch', reason: 'local checkpoint bytes differ from the committed checkpoint' });
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
    expect(result.stdout).toContain('no divergence detected as of checkpoint 0001');
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
