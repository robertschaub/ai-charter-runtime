// SPDX-License-Identifier: MIT
/** Minimal fail-closed adapter shared by the two M0-probed OpenAI-compatible lanes. */
import { z } from 'zod';
import {
  ModelAdapterError,
  type ActingRequest,
  type ActingResponse,
  type ModelLane,
  type ModelLaneConfig,
} from './contracts.js';
export * from './contracts.js';

const printableModelId = z.string().max(256).regex(/^[\x21-\x7e]+$/);
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
                tool_calls: z.array(z.unknown()).max(128).optional(),
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

async function readBoundedJson(response: Response, maxBytes: number): Promise<unknown> {
  const declaredLength = response.headers.get('content-length');
  if (declaredLength !== null) {
    const parsedLength = Number(declaredLength);
    if (Number.isFinite(parsedLength) && parsedLength > maxBytes) {
      throw new ModelAdapterError('malformed-response', 'model provider response exceeded the byte limit');
    }
  }
  if (response.body === null) throw new ModelAdapterError('malformed-response', 'model provider response was empty');

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const next = await reader.read();
    if (next.done) break;
    total += next.value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new ModelAdapterError('malformed-response', 'model provider response exceeded the byte limit');
    }
    chunks.push(next.value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) as unknown;
  } catch {
    throw new ModelAdapterError('malformed-response', 'model provider response was not JSON');
  }
}

export class OpenAiCompatibleAdapter {
  readonly #config: Required<ModelLaneConfig>;
  readonly #fetch: typeof fetch;

  constructor(config: ModelLaneConfig, fetchImplementation: typeof fetch = fetch) {
    if (config.apiKey.length === 0) throw new ModelAdapterError('invalid-config', 'model API key is absent');
    if (!Number.isSafeInteger(config.timeoutMs ?? 30_000) || (config.timeoutMs ?? 30_000) <= 0) {
      throw new ModelAdapterError('invalid-config', 'model timeout must be a positive safe integer');
    }
    if (
      !Number.isSafeInteger(config.maxResponseBytes ?? 1_048_576) ||
      (config.maxResponseBytes ?? 1_048_576) <= 0
    ) {
      throw new ModelAdapterError('invalid-config', 'model response byte limit must be a positive safe integer');
    }
    printableModelId.parse(config.requestedModel);
    chatUrl(config.baseUrl);
    this.#config = {
      ...config,
      timeoutMs: config.timeoutMs ?? 30_000,
      maxResponseBytes: config.maxResponseBytes ?? 1_048_576,
    };
    this.#fetch = fetchImplementation;
  }

  get lane(): ModelLane {
    return this.#config.lane;
  }

  get requestedId(): string {
    return this.#config.requestedModel;
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
      const raw = await readBoundedJson(response, this.#config.maxResponseBytes);
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
