// SPDX-License-Identifier: AGPL-3.0-only
/** Audience-scoped derivation for credentials passed to the three runtime processes. */
import { sha256Hex } from './hash.js';

const TOKEN = /^[0-9a-fA-F]{64,}$/;
const AUDIENCE = /^[a-z][a-z0-9.-]*$/;

/**
 * Derive a one-way audience token from a high-entropy demo credential. The supervisor
 * passes only the derived token to the narrower audience, so that process cannot replay
 * it against the authorization service.
 */
export function deriveAudienceToken(sourceToken: string, audience: string): string {
  if (!TOKEN.test(sourceToken)) throw new TypeError('source credential is not valid hex');
  if (!AUDIENCE.test(audience)) throw new TypeError('credential audience is not a valid token');
  return sha256Hex(`ai-charter-runtime/v1/credential-audience/${audience}\n${sourceToken.toLowerCase()}`);
}
