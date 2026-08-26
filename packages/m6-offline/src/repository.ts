// SPDX-License-Identifier: MIT
import { lstatSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { dirname, isAbsolute, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REPOSITORY_ROOT = realpathSync.native(fileURLToPath(new URL('../../..', import.meta.url)));

const DRIVE_OR_DEVICE = /^(?:[a-zA-Z]:|\\\\|\\\\\?\\|\\\.\\|\\\?\?\\|file:)/i;

export class M6PathError extends Error {
  constructor(readonly code: string, message: string) {
    super(message);
    this.name = 'M6PathError';
  }
}

function inside(root: string, candidate: string): boolean {
  const rel = relative(root, candidate);
  return rel === '' || (!rel.startsWith(`..${sep}`) && rel !== '..' && !isAbsolute(rel));
}

function assertExistingComponentsSafe(root: string, target: string): void {
  let current = target;
  const pending: string[] = [];
  while (inside(root, current) && current !== root) {
    pending.push(current);
    current = dirname(current);
  }
  if (current !== root) throw new M6PathError('path-outside-repository', 'path escapes the repository root');
  for (const path of pending.reverse()) {
    const info = lstatSync(path);
    if (info.isSymbolicLink()) throw new M6PathError('path-link-refused', 'symbolic links and junctions are refused');
  }
}

export function resolveSafeRepositoryFile(relativePath: string): string {
  if (
    relativePath.length === 0 ||
    relativePath.includes('\0') ||
    DRIVE_OR_DEVICE.test(relativePath) ||
    isAbsolute(relativePath) ||
    relativePath.includes('\\')
  ) {
    throw new M6PathError('path-form-refused', 'plan and fixture paths must be normalized repository-relative POSIX paths');
  }
  const normalized = relativePath.split('/');
  if (normalized.some((part) => part === '' || part === '.' || part === '..')) {
    throw new M6PathError('path-form-refused', 'empty, dot, and parent path segments are refused');
  }
  const resolved = resolve(REPOSITORY_ROOT, ...normalized);
  if (!inside(REPOSITORY_ROOT, resolved)) throw new M6PathError('path-outside-repository', 'path escapes the repository root');
  assertExistingComponentsSafe(REPOSITORY_ROOT, resolved);
  const info = lstatSync(resolved);
  if (!info.isFile() || info.isSymbolicLink()) throw new M6PathError('path-not-regular-file', 'path must name a regular file');
  const stat = statSync(resolved);
  if (stat.nlink !== 1) throw new M6PathError('path-hardlink-refused', 'hard-linked input files are refused');
  const real = realpathSync.native(resolved);
  if (!inside(REPOSITORY_ROOT, real)) throw new M6PathError('path-outside-repository', 'real path escapes the repository root');
  return real;
}

export function readSafeRepositoryFile(relativePath: string): Buffer {
  return readFileSync(resolveSafeRepositoryFile(relativePath));
}

export function toRepositoryRelative(path: string): string {
  if (!inside(REPOSITORY_ROOT, path)) throw new M6PathError('path-outside-repository', 'path escapes the repository root');
  return relative(REPOSITORY_ROOT, path).split(sep).join('/');
}
