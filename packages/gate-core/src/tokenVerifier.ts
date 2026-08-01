// SPDX-License-Identifier: AGPL-3.0-only
/** Pure executing-service verification performed again after authorization commit-verify. */
import { digestFor, verifyDigest } from './hash.js';
import { verifyEmbeddedMac, type Keyring } from './keyring.js';
import { commitToken, effectIntent, timestamp, type CommitToken, type EffectIntent } from './schemas/index.js';

export type CommitTokenVerification =
  | { readonly valid: true; readonly token: CommitToken; readonly intent: EffectIntent }
  | {
      readonly valid: false;
      readonly reason: 'malformed' | 'invalid-mac' | 'expired' | 'binding-mismatch';
    };

/**
 * Verify the token's authenticity and exact request binding without applying its TTL.
 *
 * The services host uses this narrower check only when an idempotency-ledger entry already
 * exists. Possession of the exact expired token may retrieve the outcome it created, but
 * can never create a new effect. Fresh execution must call `verifyCommitTokenForIntent`.
 */
export function verifyCommitTokenBinding(
  keyring: Keyring,
  tokenInput: unknown,
  intentInput: unknown,
): CommitTokenVerification {
  const parsedToken = commitToken.safeParse(tokenInput);
  const parsedIntent = effectIntent.safeParse(intentInput);
  if (!parsedToken.success || !parsedIntent.success) {
    return { valid: false, reason: 'malformed' };
  }
  const token = parsedToken.data;
  const intent = parsedIntent.data;
  if (
    verifyEmbeddedMac(keyring, 'commit-token', token as unknown as Record<string, unknown>, 'mac') !== 'valid'
  ) {
    return { valid: false, reason: 'invalid-mac' };
  }
  if (
    token.world_id !== intent.world_id ||
    token.ruling_id !== intent.ruling_id ||
    token.frozen_proposal_hash !== intent.frozen_proposal_hash ||
    token.service !== intent.service ||
    token.action_class !== intent.action_class ||
    !verifyDigest(token.effect_request_digest, digestFor('effect-intent', intent))
  ) {
    return { valid: false, reason: 'binding-mismatch' };
  }
  return { valid: true, token, intent };
}

export function verifyCommitTokenForIntent(
  keyring: Keyring,
  tokenInput: unknown,
  intentInput: unknown,
  nowInput: string,
): CommitTokenVerification {
  const binding = verifyCommitTokenBinding(keyring, tokenInput, intentInput);
  const parsedNow = timestamp.safeParse(nowInput);
  if (!binding.valid || !parsedNow.success) {
    if (!binding.valid) return binding;
    return { valid: false, reason: 'malformed' };
  }
  if (parsedNow.data >= binding.token.expires_at) return { valid: false, reason: 'expired' };
  return binding;
}
