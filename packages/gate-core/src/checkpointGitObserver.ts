// SPDX-License-Identifier: AGPL-3.0-only
/** Git-backed checkpoint observations. Kept outside the offline-safe local verifier. */
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';

import { canonicalize } from './canonicalize.js';
import {
  checkpointPointer,
  RecordVerificationError,
  type CheckpointGitRunner,
  type LocalCheckpointCommitContext,
  type LocalCheckpointCommitEvidence,
  type RemoteCheckpointObservation,
  type RemoteCheckpointObservationContext,
} from './checkpoint.js';

const gitCommitSha = /^[0-9a-f]{40,64}$/;

function acknowledgmentAmbiguous(message: string): RecordVerificationError {
  return new RecordVerificationError('remote-acknowledgment-ambiguous', message);
}

function decodeUtf8(bytes: Buffer, label: string): string {
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    throw new RecordVerificationError('checkpoint-invalid', `${label} is not valid UTF-8`);
  }
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
  const inheritedNames = ['SystemRoot', 'TEMP', 'TMP', 'ComSpec', 'PATHEXT', 'Path', 'PATH'];
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
  const executeGit: CheckpointGitRunner = context.gitRunner ?? runGit;
  const repoRoot = resolve(context.repoRoot);
  const artifactPath = resolve(context.checkpointsRoot, context.file);
  const pointerPath = resolve(context.checkpointsRoot, 'latest.json');
  const relativeArtifact = relative(repoRoot, artifactPath).replaceAll('\\', '/');
  const relativePointer = relative(repoRoot, pointerPath).replaceAll('\\', '/');
  if (relativeArtifact.startsWith('../') || relativeArtifact === '' || relativePointer.startsWith('../') || relativePointer === '') {
    throw acknowledgmentAmbiguous('checkpoint artifact or pointer is outside the configured repository');
  }
  try {
    const history = (await executeGit(repoRoot, ['log', '--format=%H', '--', relativeArtifact])).stdout
      .split(/\r?\n/)
      .map((value) => value.trim())
      .filter((value) => value.length > 0);
    for (const commitSha of history) {
      if (!gitCommitSha.test(commitSha)) {
        throw acknowledgmentAmbiguous(`checkpoint ${context.artifact.checkpoint_id} has an invalid local commit sha`);
      }
    }
    const localArtifact = decodeUtf8(readFileSync(artifactPath), context.file);
    const expectedPointer = `${canonicalize(checkpointPointer.parse({
      seq: context.artifact.seq,
      file: context.file,
      checkpoint_id: context.artifact.checkpoint_id,
      composite_digest: context.artifact.composite_digest,
    }))}\n`;
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
      throw acknowledgmentAmbiguous(`latest checkpoint ${context.artifact.checkpoint_id} is committed without its exact matching pointer`);
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
    if (!gitCommitSha.test(remoteHeadSha)) throw acknowledgmentAmbiguous(`remote branch ${branch} returned an invalid commit sha`);
    const contains: Record<string, boolean> = {};
    for (const commitSha of [...new Set(context.commitShas)]) {
      if (!gitCommitSha.test(commitSha)) throw acknowledgmentAmbiguous('remote observation received an invalid local checkpoint commit sha');
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
