// SPDX-License-Identifier: MIT
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CardRegistry, Keyring, verifyChain } from 'gate-core';
import { OpenAiCompatibleAdapter, laneConfigFromEnv, type ModelLane } from 'model-adapters';
import { afterEach, describe, expect, it } from 'vitest';

import { runVerticalSlice } from './verticalSlice.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const POLICY = join(ROOT, 'packages', 'gate-core', 'policy', 'v1.yaml');
const SEED = join(ROOT, 'fixtures', 'demo', 'mandate.json');
const CARDS = join(ROOT, 'docs', 'cards');
const roots: string[] = [];

afterEach(() => {
  for (const root of roots.splice(0)) rmSync(root, { recursive: true, force: true });
});

const draft = {
  declared_objective: 'File the synthetic grant application within the declared limits.',
  proposed_action: 'Submit the synthetic grant filing.',
  target: { recipient: 'grant-office', resource: 'application-42' },
  exact_parameters: { amount_minor_units: 5000, reference: 'case-demo' },
  data_to_be_disclosed: ['applicant_name'],
  cost_obligation: { amount_minor_units: 5000, description: 'Synthetic grant amount.' },
  material_consequences: ['Creates a synthetic public-funds commitment.'],
  reversibility_class: 'partially-reversible',
};

describe('M3 fault-tested vertical slice', () => {
  it.each([
    {
      lane: 'publicai' as ModelLane,
      served: 'swiss-ai/apertus-v1.5-70b',
      card: 'publicai-apertus-v1.5-70b',
    },
    { lane: 'openai' as ModelLane, served: 'gpt-5.5-2026-04-23', card: 'openai-gpt-5.5' },
  ])('runs authorize → propose → rule → commit-verify → effect → receipt on $lane', async ({ lane, served, card }) => {
    const recordsRoot = mkdtempSync(join(tmpdir(), `vertical-${lane}-`));
    roots.push(recordsRoot);
    const adapter = new OpenAiCompatibleAdapter(
      laneConfigFromEnv(lane, {
        PUBLICAI_API_KEY: 'test-publicai-key',
        OPENAI_API_KEY: 'test-openai-key',
      }),
      (async () =>
        new Response(JSON.stringify({ model: served, choices: [{ message: { content: JSON.stringify(draft) } }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })) as typeof fetch,
    );

    const receipt = await runVerticalSlice({
      recordsRoot,
      policyFile: POLICY,
      mandateSeedFile: SEED,
      keyring: new Keyring(new Map([['hmac-test', 'a'.repeat(64)]]), 'hmac-test'),
      cardRegistry: CardRegistry.load(CARDS),
      adapter,
      cardId: card,
      cardVersion: 1,
      caseId: `case_${lane}`,
    });

    expect(receipt).toMatchObject({
      kind: 'local-record-receipt',
      served_model_id: served,
      outcome: 'success',
    });
    expect(receipt).not.toHaveProperty('token');
    expect(verifyChain(join(recordsRoot, 'w-demo', 'wal.jsonl'), 'wal-entry').ok).toBe(true);
    expect(verifyChain(join(recordsRoot, 'w-demo', 'action.jsonl'), 'record-entry').ok).toBe(true);
  });
});
