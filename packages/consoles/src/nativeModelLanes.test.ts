// SPDX-License-Identifier: MIT
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { CardRegistry } from 'gate-core';
import { describe, expect, it, vi } from 'vitest';

import { NativeModelLaneError, nativeModelLaneConfigs } from './nativeModelLanes.js';

const ROOT = fileURLToPath(new URL('../../..', import.meta.url));
const CARDS = join(ROOT, 'docs', 'cards');
const ENV: NodeJS.ProcessEnv = {
  PUBLICAI_API_KEY: 'synthetic-publicai-key',
  OPENAI_API_KEY: 'synthetic-openai-key',
};

function adapters() {
  return {
    publicai: {
      lane: 'publicai' as const,
      requestedId: 'swiss-ai/apertus-v1.5-70b',
      act: vi.fn(),
    },
    openai: {
      lane: 'openai' as const,
      requestedId: 'gpt-5.5',
      act: vi.fn(),
    },
  };
}

describe('M5.9 native signed-card lane configuration', () => {
  it('constructs exactly the two reviewed acting lanes from current signed cards', () => {
    const configured = nativeModelLaneConfigs(CardRegistry.load(CARDS), ENV, { adapters: adapters() });
    expect(configured.map(({ lane, cardId, cardVersion, requestedId }) => ({
      lane,
      cardId,
      cardVersion,
      requestedId,
    }))).toEqual([
      {
        lane: 'publicai',
        cardId: 'publicai-apertus-v1.5-70b',
        cardVersion: 1,
        requestedId: 'swiss-ai/apertus-v1.5-70b',
      },
      { lane: 'openai', cardId: 'openai-gpt-5.5', cardVersion: 1, requestedId: 'gpt-5.5' },
    ]);
  });

  it('fails before adapter use on absent, redirected, relabelled, or injected lane evidence', () => {
    const cards = CardRegistry.load(CARDS);
    expect(() => nativeModelLaneConfigs(cards, { ...ENV, PUBLICAI_BASE_URL: 'https://redirect.invalid/v1' }))
      .toThrowError(NativeModelLaneError);
    expect(() => nativeModelLaneConfigs(cards, { ...ENV, OPENAI_MODEL: 'substitute-model' }))
      .toThrowError(NativeModelLaneError);
    expect(() => nativeModelLaneConfigs(cards, { OPENAI_API_KEY: 'synthetic-openai-key' }))
      .toThrowError(NativeModelLaneError);
    expect(() => nativeModelLaneConfigs(cards, { ...ENV, PUBLICAI_API_KEY: '   ' }))
      .toThrowError(NativeModelLaneError);
    expect(() => nativeModelLaneConfigs({ get: () => undefined }, ENV))
      .toThrowError(NativeModelLaneError);
    expect(() => nativeModelLaneConfigs(cards, ENV, {
      adapters: {
        ...adapters(),
        publicai: { lane: 'openai', requestedId: 'swiss-ai/apertus-v1.5-70b', act: vi.fn() },
      },
    })).toThrowError(NativeModelLaneError);
  });

  it('accepts only normalization-equivalent endpoint overrides', () => {
    expect(() => nativeModelLaneConfigs(CardRegistry.load(CARDS), {
      ...ENV,
      PUBLICAI_BASE_URL: 'https://api.publicai.co/v1/',
      OPENAI_BASE_URL: 'https://api.openai.com/v1///',
    }, { adapters: adapters() })).not.toThrow();
  });
});
