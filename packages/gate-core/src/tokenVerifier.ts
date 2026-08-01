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

export function verifyCommitTokenForIntent(
  keyring: Keyring,
  tokenInput: unknown,
  intentInput: unknown,
  nowInput: string,
): CommitTokenVerification {
  const parsedToken = commitToken.safeParse(tokenInput);
  const parsedIntent = effectIntent.safeParse(intentInput);
  const parsedNow = timestamp.safeParse(nowInput);
  if (!parsedToken.success || !parsedIntent.success || !parsedNow.success) {
    return { valid: false, reason: 'malformed' };
  }
  const token = parsedToken.data;
  const intent = parsedIntent.data;
  if (
    verifyEmbeddedMac(keyring, 'commit-token', token as unknown as Record<string, unknown>, 'mac') !== 'valid'
  ) {
    return { valid: false, reason: 'invalid-mac' };
  }
  if (parsedNow.data >= token.expires_at) return { valid: false, reason: 'expired' };
  if (
    token.world_id !== intent.world_id ||
    token.ruling_id !== intent.ruling_id ||
    token.frozen_proposal_hash !== intent.frozen_proposal_hash ||
    token.service !== intent.service ||
    token.action_class !== intent.action_class ||
    !verifyDigest(token.effect_request_digest, digestFor('proposal', intent))
  ) {
    return { valid: false, reason: 'binding-mismatch' };
  }
  return { valid: true, token, intent };
}
