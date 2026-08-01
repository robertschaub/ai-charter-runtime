// SPDX-License-Identifier: AGPL-3.0-only
/** Crash-visible single-writer lease for one world's record directory. */
import { closeSync, fsyncSync, mkdirSync, openSync, unlinkSync, writeSync } from 'node:fs';
import { dirname } from 'node:path';

import { canonicalize } from './canonicalize.js';

export class WriterLeaseError extends Error {
  constructor(
    readonly code: 'already-held' | 'closed',
    message: string,
  ) {
    super(message);
    this.name = 'WriterLeaseError';
  }
}

export class WriterLease {
  readonly #path: string;
  readonly #fd: number;
  #closed = false;

  constructor(path: string, pid: number, bootId: string) {
    mkdirSync(dirname(path), { recursive: true });
    this.#path = path;
    let fd: number;
    try {
      fd = openSync(path, 'wx', 0o600);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (code === 'EEXIST') {
        throw new WriterLeaseError(
          'already-held',
          `writer lease ${path} already exists; confirm no writer is running, then clear it manually`,
        );
      }
      throw error;
    }
    try {
      const bytes = Buffer.from(`${canonicalize({ boot_id: bootId, pid })}\n`, 'utf8');
      let offset = 0;
      while (offset < bytes.length) {
        const written = writeSync(fd, bytes, offset, bytes.length - offset, null);
        if (written <= 0) throw new Error(`writer lease ${path}: write made no progress`);
        offset += written;
      }
      fsyncSync(fd);
      this.#fd = fd;
    } catch (error) {
      try {
        closeSync(fd);
      } finally {
        try {
          unlinkSync(path);
        } catch {
          // Preserve the construction failure; a surviving lease remains fail closed.
        }
      }
      throw error;
    }
  }

  close(): void {
    if (this.#closed) return;
    this.#closed = true;
    closeSync(this.#fd);
    unlinkSync(this.#path);
  }
}
