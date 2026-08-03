// SPDX-License-Identifier: MIT
/** Immutable synthetic registry evidence for ADR-004's third-party-confirmation path. */
import { canonicalize, registryRecordRef, sha256Hex, timestamp, type RegistryEvidence } from 'gate-core';

const SYNTHETIC_RECORDS = {
  'reg:CH-0042': {
    retrieved_at: '2026-08-01T09:14:02.000Z',
    content: {
      registry_id: 'reg:CH-0042',
      jurisdiction: 'CH',
      registered_on: '2024-03-11',
      status: 'active',
      synthetic: true,
    },
  },
} as const;

export function resolveSyntheticRegistryEvidence(
  recordId: string,
  resolvedAtInput: string = new Date().toISOString(),
): RegistryEvidence | null {
  const record = SYNTHETIC_RECORDS[recordId as keyof typeof SYNTHETIC_RECORDS];
  if (record === undefined) return null;
  return registryRecordRef.parse({
    kind: 'registry_record',
    id: recordId,
    retrieved_at: record.retrieved_at,
    resolved_at: timestamp.parse(resolvedAtInput),
    content_digest: sha256Hex(canonicalize(record.content)),
  });
}
