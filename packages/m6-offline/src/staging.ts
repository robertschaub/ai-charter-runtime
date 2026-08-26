// SPDX-License-Identifier: MIT
import { closeSync, constants, existsSync, lstatSync, mkdirSync, openSync, realpathSync, readdirSync, statSync, writeFileSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';

import { canonicalize } from 'gate-core/offline-safe';

import { REPOSITORY_ROOT } from './repository.js';

const CAPTURE_ID = /^(?!(?:con|prn|aux|nul|com[1-9]|lpt[1-9])$)[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;
const STAGING_ROOT = join(REPOSITORY_ROOT, '.m6-staging');

function assertPlainComponent(path: string): void {
  const info = lstatSync(path);
  if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile())) throw new Error(`m6 staging refused linked/special path ${path}`);
  if (info.isFile() && info.nlink !== 1) throw new Error(`m6 staging refused hard-linked file ${path}`);
}

function assertContained(path: string, root: string): void {
  const rel = relative(root, path);
  if (rel === '') return;
  if (rel.startsWith('..') || resolve(root, rel) !== path) throw new Error('m6 staging path escaped its capture root');
}

export function createCaptureStaging(captureId: string): string {
  if (!CAPTURE_ID.test(captureId)) throw new Error('invalid or reserved M6 capture id');
  mkdirSync(STAGING_ROOT, { recursive: true });
  assertPlainComponent(STAGING_ROOT);
  if (readdirSync(STAGING_ROOT).some((entry) => entry.toLowerCase() === captureId.toLowerCase())) throw new Error('M6 capture id already exists or case-collides');
  const target = join(STAGING_ROOT, captureId);
  mkdirSync(target, { recursive: false });
  assertPlainComponent(target);
  if (realpathSync(target) !== target || relative(realpathSync(STAGING_ROOT), realpathSync(target)).startsWith('..')) throw new Error('M6 capture root failed realpath confinement');
  return target;
}

export function createCaptureDirectory(captureRoot: string, relativeDirectory: string): string {
  if (!/^[a-z0-9][a-z0-9-]*(?:\/[a-z0-9][a-z0-9-]*)*$/.test(relativeDirectory)) throw new Error('invalid M6 staging directory');
  const target = resolve(captureRoot, ...relativeDirectory.split('/'));
  assertContained(target, captureRoot);
  let current = captureRoot;
  for (const component of relativeDirectory.split('/')) {
    assertPlainComponent(current);
    current = join(current, component);
    if (!existsSync(current)) mkdirSync(current);
    assertPlainComponent(current);
  }
  return target;
}

export function writeExclusiveCanonicalJson(captureRoot: string, relativePath: string, value: unknown): { readonly bytes: Buffer; readonly byteLength: number } {
  if (!/^[a-z0-9][a-z0-9._/-]*\.json$/.test(relativePath)) throw new Error('invalid M6 artifact path');
  const target = resolve(captureRoot, ...relativePath.split('/'));
  assertContained(target, captureRoot);
  const parent = dirname(target);
  assertContained(parent, captureRoot);
  assertPlainComponent(captureRoot);
  assertPlainComponent(parent);
  if (existsSync(target)) throw new Error('M6 artifact overwrite refused');
  const bytes = Buffer.from(`${canonicalize(value)}\n`, 'utf8');
  const descriptor = openSync(target, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
  try { writeFileSync(descriptor, bytes); } finally { closeSync(descriptor); }
  const info = statSync(target);
  if (!info.isFile() || info.nlink !== 1) throw new Error('M6 artifact did not materialize as a private regular file');
  return { bytes, byteLength: bytes.length };
}

export class AttemptLifecycle {
  readonly events: { sequence: number; attempt_id: string; layer: 'dry-run' | 'offline-fixture'; state: string; recorded_at: string; failure_class: string | null }[] = [];
  #state: string | null = null;
  constructor(readonly attemptId: string, readonly layer: 'dry-run' | 'offline-fixture', readonly now: string) {}
  transition(state: 'planned' | 'preflighted' | 'running' | 'complete' | 'failed' | 'indeterminate' | 'sanitized', failureClass: string | null = null): void {
    const allowed: Record<string, readonly string[]> = {
      start: ['planned'], planned: ['preflighted'], preflighted: this.layer === 'offline-fixture' ? ['running'] : ['complete', 'failed', 'indeterminate'],
      running: ['complete', 'failed', 'indeterminate'], complete: ['sanitized'], failed: ['sanitized'], indeterminate: ['sanitized'], sanitized: [],
    };
    if (!(allowed[this.#state ?? 'start'] ?? []).includes(state)) throw new Error(`illegal M6 attempt transition ${this.#state ?? 'start'} -> ${state}`);
    if ((state === 'failed' || state === 'indeterminate') !== (failureClass !== null)) throw new Error('M6 terminal failure classification mismatch');
    this.#state = state;
    this.events.push({ sequence: this.events.length, attempt_id: this.attemptId, layer: this.layer, state, recorded_at: this.now, failure_class: failureClass });
  }
}
