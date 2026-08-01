// SPDX-License-Identifier: MIT
/** Minimal fail-closed adapter shared by the two M0-probed OpenAI-compatible lanes. */
import { z } from 'zod';

export type ModelLane = 'publicai' | 'openai';

export interface ModelLaneConfig {
  readonly lane: ModelLane;
  readonly baseUrl: string;
  readonly requestedModel: string;
  readonly apiKey: string;
  readonly tokenParameter: 'max_tokens' | 'max_completion_tokens';
  readonly timeoutMs?: number;
}

export interface ChatMessage {
  readonly role: 'system' | 'user' | 'assistant';
  readonly content: string;
}

export interface ActingRequest {
  readonly messages: readonly ChatMessage[];
  readonly maxOutputTokens: number;
  readonly tools?: readonly unknown[];
  readonly responseFormat?: unknown;
}

export interface ActingResponse {
  readonly lane: ModelLane;
  readonly requestedId: string;
  readonly servedId: string;
  readonly content: string | null;
  readonly toolCalls: readonly unknown[];
}

export class ModelAdapterError extends Error {
  constructor(
    readonly code: 'invalid-config' | 'timeout' | 'provider-http' | 'malformed-response',
    message: string,
    readonly httpStatus?: number,
  ) {
    super(message);
    this.name = 'ModelAdapterError';
  }
}

const printableModelId = z.string().regex(/^[\x21-\x7e]+$/);
const providerResponse = z
  .object({
    model: printableModelId,
    choices: z
      .array(
        z
          .object({
            message: z
              .object({
                content: z.string().nullable(),
                tool_calls: z.array(z.unknown()).optional(),
              })
              .passthrough(),
          })
          .passthrough(),
      )
      .min(1),
  })
  .passthrough();

function chatUrl(baseUrl: string): string {
  let parsed: URL;
  try {
    parsed = new URL(baseUrl.endsWith('/') ? baseUrl : `${baseUrl}/`);
  } catch {
    throw new ModelAdapterError('invalid-config', 'model base URL is invalid');
  }
  if (parsed.protocol !== 'https:' && parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') {
    throw new ModelAdapterError('invalid-config', 'model base URL must use HTTPS outside loopback');
  }
  return new URL('chat/completions', parsed).toString();
}

export class OpenAiCompatibleAdapter {
  readonly #config: Required<Omit<ModelLaneConfig, 'timeoutMs'>> & { readonly timeoutMs: number };
  readonly #fetch: typeof fetch;

  constructor(config: ModelLaneConfig, fetchImplementation: typeof fetch = fetch) {
    if (config.apiKey.length === 0) throw new ModelAdapterError('invalid-config', 'model API key is absent');
    if (!Number.isSafeInteger(config.timeoutMs ?? 30_000) || (config.timeoutMs ?? 30_000) <= 0) {
      throw new ModelAdapterError('invalid-config', 'model timeout must be a positive safe integer');
    }
    printableModelId.parse(config.requestedModel);
    chatUrl(config.baseUrl);
    this.#config = { ...config, timeoutMs: config.timeoutMs ?? 30_000 };
    this.#fetch = fetchImplementation;
  }

  async act(request: ActingRequest): Promise<ActingResponse> {
    if (!Number.isSafeInteger(request.maxOutputTokens) || request.maxOutputTokens <= 0) {
      throw new ModelAdapterError('invalid-config', 'maxOutputTokens must be a positive safe integer');
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.#config.timeoutMs);
    try {
      const response = await this.#fetch(chatUrl(this.#config.baseUrl), {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.#config.apiKey}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          model: this.#config.requestedModel,
          messages: request.messages,
          [this.#config.tokenParameter]: request.maxOutputTokens,
          ...(request.tools === undefined ? {} : { tools: request.tools }),
          ...(request.responseFormat === undefined ? {} : { response_format: request.responseFormat }),
        }),
        signal: controller.signal,
      });
      if (!response.ok) {
        throw new ModelAdapterError('provider-http', `model provider returned HTTP ${response.status}`, response.status);
      }
      let raw: unknown;
      try {
        raw = await response.json();
      } catch {
        throw new ModelAdapterError('malformed-response', 'model provider response was not JSON');
      }
      const parsed = providerResponse.safeParse(raw);
      if (!parsed.success) throw new ModelAdapterError('malformed-response', 'model provider response was malformed');
      const message = parsed.data.choices[0]?.message;
      if (message === undefined) throw new ModelAdapterError('malformed-response', 'model provider returned no choice');
      return {
        lane: this.#config.lane,
        requestedId: this.#config.requestedModel,
        servedId: parsed.data.model,
        content: message.content,
        toolCalls: message.tool_calls ?? [],
      };
    } catch (error) {
      if (error instanceof ModelAdapterError) throw error;
      if (controller.signal.aborted) throw new ModelAdapterError('timeout', 'model provider request timed out');
      throw new ModelAdapterError('provider-http', 'model provider request failed');
    } finally {
      clearTimeout(timeout);
    }
  }
}

export function laneConfigFromEnv(lane: ModelLane, env: NodeJS.ProcessEnv = process.env): ModelLaneConfig {
  if (lane === 'publicai') {
    return {
      lane,
      baseUrl: env['PUBLICAI_BASE_URL'] ?? 'https://api.publicai.co/v1',
      requestedModel: env['PUBLICAI_MODEL'] ?? 'swiss-ai/apertus-v1.5-70b',
      apiKey: env['PUBLICAI_API_KEY'] ?? '',
      tokenParameter: 'max_tokens',
    };
  }
  return {
    lane,
    baseUrl: env['OPENAI_BASE_URL'] ?? 'https://api.openai.com/v1',
    requestedModel: env['OPENAI_MODEL'] ?? 'gpt-5.5',
    apiKey: env['OPENAI_API_KEY'] ?? '',
    tokenParameter: 'max_completion_tokens',
  };
}
