// SPDX-License-Identifier: MIT
/** Explicit capability trap: ordinary M6.3 executors get none; infrastructure gets loopback sockets only. */
export class M6CapabilityTrap {
  constructor(private readonly infrastructure = false) {}

  assertSocket(origin: string): void {
    const parsed = new URL(origin);
    if (!this.infrastructure || parsed.protocol !== 'http:' || parsed.hostname !== '127.0.0.1' || parsed.username !== '' || parsed.password !== '') {
      throw new Error('M6 capability trap refused socket access');
    }
  }

  assertListen(host: string): void {
    if (!this.infrastructure || host !== '127.0.0.1') throw new Error('M6 capability trap refused listener access');
  }

  assertWorker(): never {
    throw new Error('M6 capability trap refused worker creation');
  }
}
