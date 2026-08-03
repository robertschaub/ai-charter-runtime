// SPDX-License-Identifier: AGPL-3.0-only
/** Server-owned ADR-006 card verification and served-model evidence lookup. */
import { createPublicKey, verify as ed25519Verify } from 'node:crypto';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { basename, join } from 'node:path';

import { digestFor } from './hash.js';
import { compareServedId } from './servedModel.js';
import {
  cardRevocation,
  cardSlug,
  modelCard,
  signingKeys,
  type FrozenProposal,
  type ModelCard,
  type SigningKeyEntry,
} from './schemas/index.js';
import { taggedBytes } from './domain.js';
import type { ModelEvidence } from './authorizationCore.js';

const ZERO_DIGEST = '0'.repeat(64);

export class CardRegistryError extends Error {
  constructor(
    readonly code: 'invalid-json' | 'invalid-card' | 'invalid-trust-root' | 'duplicate-card' | 'filename-mismatch',
    message: string,
  ) {
    super(message);
    this.name = 'CardRegistryError';
  }
}

interface VerifiedCard {
  readonly card: ModelCard;
  readonly digest: string;
  readonly keyId: string;
  readonly keyUsable: boolean;
  readonly withdrawn: boolean;
  readonly integrityAlarm: boolean;
}

export interface CardResolution extends ModelEvidence {
  readonly modelResolution: 'exact' | 'benign-resolution' | 'mismatch';
  readonly modelResolutionUnrecorded: boolean;
  readonly integrityAlarm: boolean;
}

export interface CardInspection {
  readonly card: ModelCard;
  readonly digest: string;
  readonly keyId: string;
  readonly signatureValid: boolean;
  readonly withdrawn: boolean;
  readonly integrityAlarm: boolean;
}

function readJson(file: string): unknown {
  try {
    return JSON.parse(readFileSync(file, 'utf8'));
  } catch {
    throw new CardRegistryError('invalid-json', `${basename(file)} is not valid JSON`);
  }
}

function unsigned(value: Record<string, unknown>, field: string): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value)) {
    if (key !== field) result[key] = item;
  }
  return result;
}

function verifySignature(
  value: Record<string, unknown>,
  signature: { readonly key_id: string; readonly signature: string },
  key: SigningKeyEntry | undefined,
  domain: 'model-card' | 'card-revocation',
): boolean {
  if (key === undefined || key.revoked_at !== undefined) return false;
  try {
    const publicKey = createPublicKey({
      key: Buffer.from(key.public_key_b64, 'base64'),
      format: 'der',
      type: 'spki',
    });
    return ed25519Verify(
      null,
      taggedBytes(domain, unsigned(value, 'signature')),
      publicKey,
      Buffer.from(signature.signature, 'base64'),
    );
  } catch {
    return false;
  }
}

export class CardRegistry {
  #cards = new Map<string, VerifiedCard>();
  readonly #cardsDirectory: string;

  private constructor(cardsDirectory: string) {
    this.#cardsDirectory = cardsDirectory;
  }

  static load(cardsDirectory: string): CardRegistry {
    const registry = new CardRegistry(cardsDirectory);
    registry.#reload();
    return registry;
  }

  #reload(): void {
    let keys: SigningKeyEntry[];
    try {
      keys = signingKeys.parse(readJson(join(this.#cardsDirectory, 'signing-keys.json')));
    } catch (error) {
      if (error instanceof CardRegistryError) throw error;
      throw new CardRegistryError('invalid-trust-root', 'signing-keys.json is not a valid trust root');
    }
    const keyById = new Map(keys.map((key) => [key.key_id, key]));
    const cards = new Map<string, VerifiedCard>();
    const names = readdirSync(this.#cardsDirectory).filter(
      (name) => name.endsWith('.json') && name !== 'signing-keys.json' && !name.endsWith('.revocation.json'),
    );
    for (const name of names) {
      let card: ModelCard;
      try {
        card = modelCard.parse(readJson(join(this.#cardsDirectory, name)));
      } catch {
        throw new CardRegistryError('invalid-card', `${name} does not satisfy the model-card schema`);
      }
      if (`${card.card_id}.json` !== name) {
        throw new CardRegistryError('filename-mismatch', `${name} does not match card id ${card.card_id}`);
      }
      if (cards.has(card.card_id)) {
        throw new CardRegistryError('duplicate-card', `duplicate card id ${card.card_id}`);
      }
      const key = keyById.get(card.signature.key_id);
      const signatureValid = verifySignature(
        card as unknown as Record<string, unknown>,
        card.signature,
        key,
        'model-card',
      );
      const revocationPath = join(this.#cardsDirectory, `${card.card_id}.revocation.json`);
      let withdrawn = false;
      let integrityAlarm = false;
      if (existsSync(revocationPath)) {
        withdrawn = true;
        try {
          const revocation = cardRevocation.parse(readJson(revocationPath));
          const revocationValid = verifySignature(
            revocation as unknown as Record<string, unknown>,
            revocation.signature,
            keyById.get(revocation.signature.key_id),
            'card-revocation',
          );
          if (!revocationValid || revocation.card_id !== card.card_id) integrityAlarm = true;
          else if (
            revocation.revokes_versions !== 'all' &&
            !revocation.revokes_versions.includes(card.card_version)
          ) {
            withdrawn = false;
          }
        } catch {
          // An unverifiable withhold signal still suspends; it can never grant authority.
          integrityAlarm = true;
        }
      }
      cards.set(card.card_id, {
        card,
        digest: digestFor('model-card', unsigned(card as unknown as Record<string, unknown>, 'signature')),
        keyId: card.signature.key_id,
        keyUsable: signatureValid && key?.revoked_at === undefined,
        withdrawn,
        integrityAlarm,
      });
    }
    this.#cards = cards;
  }

  resolve(proposal: FrozenProposal): CardResolution {
    // ADR-006 requires withdrawal and supersession to be visible at every gate
    // touch. The card set is deliberately small, so a fail-closed reload is
    // clearer than a cache whose invalidation can miss a security withdrawal.
    this.#reload();
    const cardId = cardSlug.parse(proposal.acting_model.card_id);
    const entry = this.#cards.get(cardId);
    if (entry === undefined) {
      return {
        servedModelAccepted: false,
        cardStatus: 'withdrawn',
        cardKeyId: 'unverified',
        cardDigest: ZERO_DIGEST,
        modelResolution: 'mismatch',
        modelResolutionUnrecorded: false,
        integrityAlarm: true,
      };
    }
    const comparison = compareServedId(
      proposal.acting_model.requested_id,
      entry.card.model.resolution.policy,
      proposal.acting_model.served_id,
    );
    const status =
      !entry.keyUsable || entry.withdrawn || proposal.acting_model.card_version > entry.card.card_version
        ? 'withdrawn'
        : proposal.acting_model.card_version < entry.card.card_version
          ? 'superseded'
          : 'current';
    const observed = entry.card.model.resolution.observed_snapshots.some(
      (value) => value.id === proposal.acting_model.served_id,
    );
    return {
      servedModelAccepted:
        entry.card.model.requested_id === proposal.acting_model.requested_id && comparison !== 'mismatch',
      cardStatus: status,
      cardKeyId: entry.keyId,
      cardDigest: entry.digest,
      modelResolution: comparison,
      modelResolutionUnrecorded: comparison === 'benign-resolution' && !observed,
      integrityAlarm: entry.integrityAlarm || !entry.keyUsable,
    };
  }

  get(cardIdInput: string): CardInspection | undefined {
    this.#reload();
    const entry = this.#cards.get(cardSlug.parse(cardIdInput));
    if (entry === undefined) return undefined;
    return {
      card: entry.card,
      digest: entry.digest,
      keyId: entry.keyId,
      signatureValid: entry.keyUsable,
      withdrawn: entry.withdrawn,
      integrityAlarm: entry.integrityAlarm,
    };
  }
}
