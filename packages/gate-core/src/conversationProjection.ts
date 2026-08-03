// SPDX-License-Identifier: AGPL-3.0-only
/** M5.1 deterministic ADR-005 conversation projection and monotone tag union. */
import { conversationProjection, type ConversationProjection } from './authorizationProjection.js';
import {
  cardSlug,
  conversationStoreEntry,
  id,
  modelRole,
  restrictionTagSet,
  storeItem,
  worldId,
  type ConversationStoreEntry,
  type RestrictionTag,
  type StoreItem,
} from './schemas/index.js';

export class ConversationProjectionError extends Error {
  constructor(
    readonly code: 'invalid-entry' | 'invalid-clearance' | 'invalid-scope',
    message: string,
  ) {
    super(message);
    this.name = 'ConversationProjectionError';
  }
}

function sorted(values: Iterable<string>): string[] {
  return [...new Set(values)].sort();
}

/** ADR-005 §4: derived output receives the union of every projected input's tags. */
export function unionRestrictionTags(itemsInput: readonly StoreItem[]): RestrictionTag[] {
  const items = itemsInput.map((item) => {
    const parsed = storeItem.safeParse(item);
    if (!parsed.success) throw new ConversationProjectionError('invalid-entry', 'conversation item failed validation');
    return parsed.data;
  });
  return restrictionTagSet.parse(sorted(items.flatMap((item) => item.tags)));
}

/** ADR-005 §5 / ADR-006 §4: the card can narrow the mandate and can never widen it. */
export function intersectClearances(
  mandateInput: readonly RestrictionTag[],
  cardInput: readonly RestrictionTag[],
): RestrictionTag[] {
  const mandate = restrictionTagSet.safeParse(mandateInput);
  const card = restrictionTagSet.safeParse(cardInput);
  if (!mandate.success || !card.success) {
    throw new ConversationProjectionError('invalid-clearance', 'provider clearance failed validation');
  }
  const cardSet = new Set(card.data);
  return restrictionTagSet.parse(sorted(mandate.data.filter((tag) => cardSet.has(tag))));
}

export interface ProjectConversationInput {
  readonly worldId: string;
  readonly caseId: string;
  readonly provider: string;
  readonly role: 'acting' | 'screening';
  readonly mandateClearances: readonly RestrictionTag[];
  readonly cardClearances: readonly RestrictionTag[];
  readonly entries: readonly ConversationStoreEntry[];
}

/**
 * Recomputed for every call; conversation items are dropped whole when any required tag
 * is absent. Accepting an already-computed effective set would let a caller widen it, so
 * this boundary always computes the mandate/card intersection itself.
 */
export function projectConversation(input: ProjectConversationInput): ConversationProjection {
  const parsedWorld = worldId.safeParse(input.worldId);
  const parsedCase = id.safeParse(input.caseId);
  const parsedProvider = cardSlug.safeParse(input.provider);
  const parsedRole = modelRole.safeParse(input.role);
  if (
    !parsedWorld.success ||
    !parsedCase.success ||
    !parsedProvider.success ||
    !parsedRole.success
  ) {
    throw new ConversationProjectionError('invalid-scope', 'conversation projection scope failed validation');
  }
  const clearanceSet = new Set(intersectClearances(input.mandateClearances, input.cardClearances));
  const entries = input.entries.map((entry) => {
    const parsed = conversationStoreEntry.safeParse(entry);
    if (!parsed.success) throw new ConversationProjectionError('invalid-entry', 'conversation entry failed validation');
    return parsed.data;
  });
  const scoped = entries
    .filter((entry) => entry.world_id === parsedWorld.data && entry.case_id === parsedCase.data)
    .sort((left, right) => (left.item.id < right.item.id ? -1 : left.item.id > right.item.id ? 1 : 0));
  const included: StoreItem[] = [];
  const dropped: string[] = [];
  const unmet = new Set<string>();
  for (const entry of scoped) {
    const missing = entry.item.tags.filter((tag) => !clearanceSet.has(tag));
    if (missing.length === 0) included.push(entry.item);
    else {
      dropped.push(entry.item.id);
      for (const tag of missing) unmet.add(tag);
    }
  }
  return conversationProjection.parse({
    world_id: parsedWorld.data,
    case_id: parsedCase.data,
    provider: parsedProvider.data,
    role: parsedRole.data,
    items: included,
    summary: {
      included: included.length,
      dropped: dropped.length,
      dropped_item_ids: dropped,
      unmet_tags: sorted(unmet),
    },
  });
}
