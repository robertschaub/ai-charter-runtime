// SPDX-License-Identifier: AGPL-3.0-only
/** Test-only helpers shared by cross-package runtime boundary tests. */
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { systemUseDecisionRecord } from './schemas/index.js';
import { systemUseDecisionDigest } from './systemUseDecision.js';

export function writeCurrentTestSystemUseFixture(
  sourceFile: string,
  targetDirectory: string,
  now = Date.now(),
): string {
  const source = systemUseDecisionRecord.parse(JSON.parse(readFileSync(sourceFile, 'utf8')));
  const current = systemUseDecisionRecord.parse({
    ...source,
    validity: {
      ...source.validity,
      effective_at: new Date(now - 60_000).toISOString(),
      expires_at: new Date(now + 3_600_000).toISOString(),
    },
    trace: {
      ...source.trace,
      created_at: new Date(now - 60_000).toISOString(),
    },
  });
  const withDigest = systemUseDecisionRecord.parse({
    ...current,
    trace: {
      ...current.trace,
      record_digest: systemUseDecisionDigest(current),
    },
  });
  const target = join(targetDirectory, 'current-test-system-use-decision.json');
  writeFileSync(target, `${JSON.stringify(withDigest, null, 2)}\n`, 'utf8');
  return target;
}
