// SPDX-License-Identifier: MIT
import { SchemaRegistry, type SchemaName } from './schemas.js';
import type { AttemptEvent } from './types.js';

const FORBIDDEN_KEYS = /^(?:authorization|cookie|set-cookie|credential|token|mac|private_key|api_key|access_token|secret|password|hostname|username|machine_id|environment_variables|raw_body|raw_headers|provider_payload)$/i;
const FORBIDDEN_VALUES = /(?:Bearer\s+[A-Za-z0-9._~-]+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|file:|\\\\|\\\?\?\\|\\\?\\|\\\.\\|\\Windows\\|(?:^|[=\s"'])(?:[A-Za-z]:[\\/]|\/(?:home|Users|root|etc|proc|sys|var|tmp|mnt)(?:\/|$)))/i;

function scan(value: unknown, layer: 'dry-run' | 'offline-fixture', path = '$'): void {
  if (Array.isArray(value)) { value.forEach((entry, index) => scan(entry, layer, `${path}[${index}]`)); return; }
  if (value !== null && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.test(key)) throw new Error(`M6 sanitization refused forbidden key at ${path}.${key}`);
      if (key === 'layer' && entry !== layer) throw new Error(`M6 artifact layer label mismatch at ${path}.${key}`);
      scan(entry, layer, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === 'string' && FORBIDDEN_VALUES.test(value)) throw new Error(`M6 sanitization refused forbidden content at ${path}`);
}

export function sanitizeArtifact(schema: SchemaName, value: unknown, layer: 'dry-run' | 'offline-fixture', registry = new SchemaRegistry()): void {
  registry.validate(schema, value);
  assertNoForbiddenContent(value, layer);
}

export function assertNoForbiddenContent(value: unknown, layer: 'dry-run' | 'offline-fixture'): void {
  scan(value, layer);
}

interface AttemptSummary {
  readonly total: number;
  readonly complete: number;
  readonly failed: number;
  readonly indeterminate: number;
}

interface AttemptEventsArtifact {
  readonly events: readonly AttemptEvent[];
}

interface SanitizationReportArtifact {
  readonly attempt_id: string;
  readonly checks: readonly string[];
  readonly failed_attempt_count: number;
  readonly indeterminate_attempt_count: number;
}

/** Cross-checks the public claims that failed attempts are retained and only complete attempts have result projections. */
export function sanitizeAttemptArtifacts(
  eventsArtifact: AttemptEventsArtifact,
  report: SanitizationReportArtifact,
  summary: AttemptSummary,
  projectedAttemptIds: readonly string[],
  layer: 'dry-run' | 'offline-fixture',
  registry = new SchemaRegistry(),
): void {
  sanitizeArtifact('attemptEvents', eventsArtifact, layer, registry);
  sanitizeArtifact('sanitizationReport', report, layer, registry);
  if (!report.checks.includes('retained-failures') || !report.checks.includes('success-only-omission')) {
    throw new Error('M6 sanitization report omitted its implemented attempt reconciliation checks');
  }
  const attempts = new Map<string, Set<'complete' | 'failed' | 'indeterminate'>>();
  for (const event of eventsArtifact.events) {
    const outcomes = attempts.get(event.attempt_id) ?? new Set<'complete' | 'failed' | 'indeterminate'>();
    if (event.state === 'complete' || event.state === 'failed' || event.state === 'indeterminate') outcomes.add(event.state);
    attempts.set(event.attempt_id, outcomes);
  }
  const outcomeByAttempt = new Map<string, 'complete' | 'failed' | 'indeterminate'>();
  for (const [attemptId, outcomes] of attempts) {
    if (outcomes.size !== 1) throw new Error(`M6 attempt ${attemptId} has no single retained terminal outcome`);
    outcomeByAttempt.set(attemptId, [...outcomes][0]!);
  }
  const computed = {
    total: outcomeByAttempt.size,
    complete: [...outcomeByAttempt.values()].filter((state) => state === 'complete').length,
    failed: [...outcomeByAttempt.values()].filter((state) => state === 'failed').length,
    indeterminate: [...outcomeByAttempt.values()].filter((state) => state === 'indeterminate').length,
  };
  if (JSON.stringify(computed) !== JSON.stringify(summary)) throw new Error('M6 attempt summary does not reconcile with retained attempt events');
  if (report.failed_attempt_count !== computed.failed || report.indeterminate_attempt_count !== computed.indeterminate) {
    throw new Error('M6 sanitization failure counts do not reconcile with retained attempt events');
  }
  if (!outcomeByAttempt.has(report.attempt_id)) throw new Error('M6 sanitization report names an unknown attempt');
  const expectedProjected = [...outcomeByAttempt]
    .filter(([, state]) => state === 'complete')
    .map(([attemptId]) => attemptId)
    .sort();
  const actualProjected = [...new Set(projectedAttemptIds)].sort();
  if (JSON.stringify(actualProjected) !== JSON.stringify(expectedProjected)) {
    throw new Error('M6 result projections must include exactly the complete attempts and omit failed or indeterminate attempts');
  }
}
