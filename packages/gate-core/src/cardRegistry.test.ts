// SPDX-License-Identifier: AGPL-3.0-only
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { afterEach, describe, expect, it } from 'vitest';

import { CardRegistry } from './cardRegistry.js';
import { freezeProposal } from './authorizationCore.js';

const CARDS = fileURLToPath(new URL('../../../docs/cards', import.meta.url));
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

function proposal(cardId: string, requestedId: string, servedId: string) {
  return freezeProposal({
    world_id: 'w-demo',
    proposal_id: 'prp_card_test',
    revision: 1,
    action_id: 'act_card_test',
    created_at: '2026-08-01T09:00:00.000Z',
    declared_objective: 'Test the card registry.',
    proposed_action: 'Read a synthetic registry record.',
    target: { recipient: 'case-officer', resource: 'registry-item-1' },
    exact_parameters: { query: 'synthetic' },
    material_inputs: [],
    derived_claims: [],
    data_to_be_disclosed: [],
    cost_obligation: { amount_minor_units: 0, description: 'No cost.' },
    material_consequences: [],
    reversibility_class: 'reversible',
    commercial_influence: { applicable: false, note: 'n/a' },
    acting_model: { requested_id: requestedId, served_id: servedId, card_id: cardId, card_version: 1 },
    mandate_ref: { mandate_id: 'mdt_demo', version: 1 },
  });
}

function copiedCards(): string {
  const root = mkdtempSync(join(tmpdir(), 'card-registry-m3-'));
  roots.push(root);
  cpSync(CARDS, root, { recursive: true });
  return root;
}

describe('server-owned model-card registry', () => {
  it('verifies both signed M0 cards and applies each lane resolution policy', () => {
    const registry = CardRegistry.load(CARDS);
    expect(registry.get('openai-gpt-5.5')?.digest).toBe(
      '0577111a4a86dd783d0a9aa9138427c534364994368a85e622abcc33a3c7decf',
    );
    expect(registry.get('publicai-apertus-v1.5-70b')?.digest).toBe(
      'bd2cbb6a3fe27ae71d84f132acaee091751e3772e703ef7fb5750bac2201c5ab',
    );
    expect(
      registry.resolve(
        proposal(
          'publicai-apertus-v1.5-70b',
          'swiss-ai/apertus-v1.5-70b',
          'swiss-ai/apertus-v1.5-70b',
        ),
      ),
    ).toMatchObject({ servedModelAccepted: true, cardStatus: 'current', modelResolution: 'exact' });
    expect(registry.resolve(proposal('openai-gpt-5.5', 'gpt-5.5', 'gpt-5.5-2026-04-23'))).toMatchObject({
      servedModelAccepted: true,
      cardStatus: 'current',
      modelResolution: 'benign-resolution',
      modelResolutionUnrecorded: false,
    });
    expect(registry.resolve(proposal('openai-gpt-5.5', 'gpt-5.5', 'different-family'))).toMatchObject({
      servedModelAccepted: false,
      modelResolution: 'mismatch',
    });
  });

  it('makes a schema-valid but signature-tampered card unusable', () => {
    const directory = copiedCards();
    const file = join(directory, 'openai-gpt-5.5.json');
    const raw = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>;
    raw['endpoint'] = { value: 'https://tampered.invalid/v1', provenance: 'probe-tested', date: '2026-08-01' };
    writeFileSync(file, `${JSON.stringify(raw, null, 2)}\n`);

    expect(CardRegistry.load(directory).resolve(proposal('openai-gpt-5.5', 'gpt-5.5', 'gpt-5.5'))).toMatchObject({
      servedModelAccepted: true,
      cardStatus: 'withdrawn',
      integrityAlarm: true,
    });
  });

  it('honours even a malformed local withdrawal signal and raises an integrity alarm', () => {
    const directory = copiedCards();
    writeFileSync(join(directory, 'openai-gpt-5.5.revocation.json'), '{}\n');

    expect(CardRegistry.load(directory).resolve(proposal('openai-gpt-5.5', 'gpt-5.5', 'gpt-5.5'))).toMatchObject({
      cardStatus: 'withdrawn',
      integrityAlarm: true,
    });
  });
});
