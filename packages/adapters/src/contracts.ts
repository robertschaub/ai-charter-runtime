// SPDX-License-Identifier: MIT
/** Network-free model lane contracts used by deterministic in-process adapters. */
export type ModelLane = 'publicai' | 'openai';

export interface ModelLaneConfig {
  readonly lane: ModelLane;
  readonly baseUrl: string;
  readonly requestedModel: string;
  readonly apiKey: string;
  readonly tokenParameter: 'max_tokens' | 'max_completion_tokens';
  readonly timeoutMs?: number;
  readonly maxResponseBytes?: number;
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
