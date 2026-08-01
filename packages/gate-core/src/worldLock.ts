// SPDX-License-Identifier: AGPL-3.0-only
/** Per-world FIFO serialization for authority-changing transactions. */

export class WorldLock {
  readonly #tails = new Map<string, Promise<void>>();

  async withLock<T>(worldId: string, fn: () => Promise<T> | T): Promise<T> {
    const previous = this.#tails.get(worldId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    this.#tails.set(worldId, current);

    await previous;
    try {
      return await fn();
    } finally {
      release();
      if (this.#tails.get(worldId) === current) this.#tails.delete(worldId);
    }
  }

  get queuedWorlds(): number {
    return this.#tails.size;
  }
}

export const worldLock = new WorldLock();

export function withWorldLock<T>(worldId: string, fn: () => Promise<T> | T): Promise<T> {
  return worldLock.withLock(worldId, fn);
}
