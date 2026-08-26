// SPDX-License-Identifier: MIT
/** Transport error shared without importing the network-capable authorization client. */
export class ServicesAuthorizationHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string | null,
  ) {
    super(`authorization service rejected transport request with HTTP ${status}`);
    this.name = 'ServicesAuthorizationHttpError';
  }
}
