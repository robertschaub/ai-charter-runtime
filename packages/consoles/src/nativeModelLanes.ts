// SPDX-License-Identifier: MIT
/** M5.9 native adapter custody and exact signed-card configuration binding. */
import {
  type CardRegistry,
} from 'gate-core';
import {
  OpenAiCompatibleAdapter,
  laneConfigFromEnv,
  type ModelLane,
  type OpenAiCompatibleAdapter as ActingAdapter,
} from 'model-adapters';

import type { ModelTurnLaneConfig } from './modelTurnCoordinator.js';

const REQUIRED_LANES = ['publicai', 'openai'] as const satisfies readonly ModelLane[];
const REQUIRED_CARD_IDS: Readonly<Record<ModelLane, string>> = {
  publicai: 'publicai-apertus-v1.5-70b',
  openai: 'openai-gpt-5.5',
};

export class NativeModelLaneError extends Error {
  constructor(readonly code: 'signed-card-invalid' | 'lane-configuration-invalid') {
    super(code);
    this.name = 'NativeModelLaneError';
  }
}

export interface NativeModelLaneDependencies {
  /** Test-only programmatic seam. The production process entrypoint never supplies it. */
  readonly adapters?: Partial<Record<ModelLane, Pick<ActingAdapter, 'act' | 'lane' | 'requestedId'>>>;
}

function normalizedBaseUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new NativeModelLaneError('lane-configuration-invalid');
  }
  if (
    (parsed.protocol !== 'https:' && parsed.hostname !== '127.0.0.1' && parsed.hostname !== 'localhost') ||
    parsed.username !== '' ||
    parsed.password !== '' ||
    parsed.search !== '' ||
    parsed.hash !== ''
  ) {
    throw new NativeModelLaneError('lane-configuration-invalid');
  }
  const pathname = parsed.pathname.replace(/\/+$/u, '') || '/';
  return `${parsed.origin}${pathname === '/' ? '' : pathname}`;
}

function validApiKey(value: string): boolean {
  return value.length >= 1 && value.length <= 4_096 && /^[\x21-\x7e]+$/.test(value);
}

function laneEvidence(cards: Pick<CardRegistry, 'get'>, lane: ModelLane) {
  const evidence = cards.get(REQUIRED_CARD_IDS[lane]);
  if (
    evidence === undefined ||
    !evidence.signatureValid ||
    evidence.withdrawn ||
    evidence.integrityAlarm ||
    evidence.card.card_id !== REQUIRED_CARD_IDS[lane] ||
    evidence.card.model.resolution.lane !== lane
  ) {
    throw new NativeModelLaneError('signed-card-invalid');
  }
  return evidence;
}

export function nativeModelLaneConfigs(
  cards: Pick<CardRegistry, 'get'>,
  env: NodeJS.ProcessEnv,
  dependencies: NativeModelLaneDependencies = {},
): readonly ModelTurnLaneConfig[] {
  const configs = REQUIRED_LANES.map((lane): ModelTurnLaneConfig => {
    const evidence = laneEvidence(cards, lane);
    const card = evidence.card;
    const config = laneConfigFromEnv(lane, env);
    const signedTokenParameter = card.capabilities.token_parameter.value;
    if (
      !validApiKey(config.apiKey) ||
      config.lane !== lane ||
      config.requestedModel !== card.model.requested_id ||
      config.tokenParameter !== signedTokenParameter ||
      normalizedBaseUrl(config.baseUrl) !== normalizedBaseUrl(card.endpoint.value)
    ) {
      throw new NativeModelLaneError('lane-configuration-invalid');
    }
    const adapter = dependencies.adapters?.[lane] ?? new OpenAiCompatibleAdapter(config);
    if (adapter.lane !== lane || adapter.requestedId !== config.requestedModel) {
      throw new NativeModelLaneError('lane-configuration-invalid');
    }
    return {
      lane,
      cardId: card.card_id,
      cardVersion: card.card_version,
      requestedId: card.model.requested_id,
      adapter,
    };
  });
  if (new Set(configs.map((entry) => `${entry.cardId}@${entry.cardVersion}\n${entry.requestedId}`)).size !== 2) {
    throw new NativeModelLaneError('signed-card-invalid');
  }
  return configs;
}
