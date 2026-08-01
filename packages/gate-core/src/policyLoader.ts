// SPDX-License-Identifier: AGPL-3.0-only
/** Read, validate, and content-address a policy YAML file. */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';

import { digestFor, isHexDigest } from './hash.js';
import { policySet, type PolicySet } from './schemas/index.js';

const require = createRequire(import.meta.url);
const yaml = require('js-yaml') as {
  load(text: string, options: { schema: unknown }): unknown;
  JSON_SCHEMA: unknown;
};

export interface LoadedPolicy {
  readonly policy: PolicySet;
  readonly policyContentDigest: string;
  readonly evaluatorBuildDigest: string;
  readonly evaluatorBuildId: string;
}

export function evaluatorBuildId(fullDigest: string, packageVersion = '0.0.1'): string {
  if (!isHexDigest(fullDigest)) throw new TypeError('evaluator build digest must be 64 lowercase hex characters');
  return `gate-core@${packageVersion}+${fullDigest.slice(0, 16)}`;
}

export function loadPolicyFile(file: string, buildDigest: string, packageVersion = '0.0.1'): LoadedPolicy {
  if (!isHexDigest(buildDigest)) throw new TypeError('evaluator build digest must be 64 lowercase hex characters');
  const text = readFileSync(file, 'utf8');
  const parsedYaml = yaml.load(text, { schema: yaml.JSON_SCHEMA });
  const policy = policySet.parse(parsedYaml);
  return {
    policy,
    policyContentDigest: digestFor('policy-set', policy),
    evaluatorBuildDigest: buildDigest,
    evaluatorBuildId: evaluatorBuildId(buildDigest, packageVersion),
  };
}
