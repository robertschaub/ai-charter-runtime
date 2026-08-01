// SPDX-License-Identifier: MIT
import { describe, expect, it, vi } from 'vitest';

import { ModelAdapterError, OpenAiCompatibleAdapter, laneConfigFromEnv } from './openAiCompatible.js';

describe('OpenAI-compatible acting-model adapters', () => {
  it.each([
    ['publicai' as const, 'max_tokens', 'swiss-ai/apertus-v1.5-70b'],
    ['openai' as const, 'max_completion_tokens', 'gpt-5.5'],
  ])('translates the output-token parameter for the %s lane', async (lane, tokenParameter, requestedModel) => {
    let captured: Record<string, unknown> | undefined;
    let capturedUrl = '';
    const fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      capturedUrl = String(url);
      captured = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(
        JSON.stringify({ model: requestedModel, choices: [{ message: { content: 'ready', tool_calls: [] } }] }),
        { status: 200, headers: { 'content-type': 'application/json' } },
      );
    });
    const config = laneConfigFromEnv(lane, {
      PUBLICAI_API_KEY: 'test-publicai-key',
      OPENAI_API_KEY: 'test-openai-key',
    });
    const adapter = new OpenAiCompatibleAdapter(config, fetchMock as typeof fetch);

    const response = await adapter.act({
      messages: [{ role: 'user', content: 'Return a synthetic proposal.' }],
      maxOutputTokens: 128,
    });

    expect(captured?.[tokenParameter]).toBe(128);
    expect(capturedUrl).toMatch(/\/v1\/chat\/completions$/);
    expect(captured?.[tokenParameter === 'max_tokens' ? 'max_completion_tokens' : 'max_tokens']).toBeUndefined();
    expect(response).toMatchObject({ lane, requestedId: requestedModel, servedId: requestedModel, content: 'ready' });
  });

  it('records a provider-served snapshot separately from the requested alias', async () => {
    const adapter = new OpenAiCompatibleAdapter(
      laneConfigFromEnv('openai', { OPENAI_API_KEY: 'test-openai-key' }),
      (async () =>
        new Response(
          JSON.stringify({ model: 'gpt-5.5-2026-04-23', choices: [{ message: { content: 'proposal' } }] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        )) as typeof fetch,
    );

    expect(
      await adapter.act({ messages: [{ role: 'user', content: 'Synthetic.' }], maxOutputTokens: 64 }),
    ).toMatchObject({ requestedId: 'gpt-5.5', servedId: 'gpt-5.5-2026-04-23' });
  });

  it('fails closed without reflecting a provider error body', async () => {
    const adapter = new OpenAiCompatibleAdapter(
      laneConfigFromEnv('publicai', { PUBLICAI_API_KEY: 'test-publicai-key' }),
      (async () => new Response('sensitive upstream diagnostic', { status: 503 })) as typeof fetch,
    );

    await expect(
      adapter.act({ messages: [{ role: 'user', content: 'Synthetic.' }], maxOutputTokens: 64 }),
    ).rejects.toEqual(
      expect.objectContaining<Partial<ModelAdapterError>>({ code: 'provider-http', httpStatus: 503 }),
    );
    await expect(
      adapter.act({ messages: [{ role: 'user', content: 'Synthetic.' }], maxOutputTokens: 64 }),
    ).rejects.not.toThrow(/sensitive upstream diagnostic/);
  });

  it('fails closed when the provider omits its served-model id', async () => {
    const adapter = new OpenAiCompatibleAdapter(
      laneConfigFromEnv('openai', { OPENAI_API_KEY: 'test-openai-key' }),
      (async () =>
        new Response(JSON.stringify({ choices: [{ message: { content: 'proposal' } }] }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        })) as typeof fetch,
    );

    await expect(
      adapter.act({ messages: [{ role: 'user', content: 'Synthetic.' }], maxOutputTokens: 64 }),
    ).rejects.toEqual(expect.objectContaining<Partial<ModelAdapterError>>({ code: 'malformed-response' }));
  });

  it('stops reading a provider response that exceeds the configured byte limit', async () => {
    const adapter = new OpenAiCompatibleAdapter(
      {
        ...laneConfigFromEnv('openai', { OPENAI_API_KEY: 'test-openai-key' }),
        maxResponseBytes: 64,
      },
      (async () =>
        new Response(
          JSON.stringify({ model: 'gpt-5.5', choices: [{ message: { content: 'x'.repeat(128) } }] }),
          { status: 200, headers: { 'content-type': 'application/json' } },
        )) as typeof fetch,
    );

    await expect(
      adapter.act({ messages: [{ role: 'user', content: 'Synthetic.' }], maxOutputTokens: 64 }),
    ).rejects.toEqual(expect.objectContaining<Partial<ModelAdapterError>>({ code: 'malformed-response' }));
  });
});
