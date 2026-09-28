// SPDX-License-Identifier: AGPL-3.0-only
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
