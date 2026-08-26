// SPDX-License-Identifier: MIT
/** Transport-neutral dependency refusal type shared with offline coordination. */
export class RuntimeDependencyError extends Error {
  constructor(
    readonly httpStatus: number,
    readonly responseCode: string | null,
  ) {
    super(`runtime dependency rejected transport request with HTTP ${httpStatus}`);
    this.name = 'RuntimeDependencyError';
  }
}
