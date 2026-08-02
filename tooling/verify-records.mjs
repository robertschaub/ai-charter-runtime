// SPDX-License-Identifier: MIT
/** ADR-003 record verifier. Local mode skips only the remote-presence step. */
import { randomUUID } from 'node:crypto';
import { resolve } from 'node:path';

import {
  digestFileSet,
  loadPolicyFile,
  recordVerificationAccess,
  verifyRecords,
  WalStore,
} from 'gate-core';

function parseArguments(argv) {
  let local = false;
  for (const argument of argv) {
    if (argument === '--local') local = true;
    else throw new Error(`unknown argument ${argument}`);
  }
  return { local };
}

async function main() {
  const { local } = parseArguments(process.argv.slice(2));
  const recordsRoot = resolve(process.env.RUNTIME_RECORDS_ROOT ?? 'records');
  const checkpointsRoot = resolve(process.env.RUNTIME_CHECKPOINTS_ROOT ?? 'docs/checkpoints');
  const worldId = process.env.DEMO_WORLD_ID ?? 'w-demo';
  const policyFile = resolve(process.env.RUNTIME_POLICY_FILE ?? 'packages/gate-core/policy/v1.yaml');
  const policyRoot = resolve(process.env.RUNTIME_POLICY_ROOT ?? 'packages/gate-core/policy');
  const sourceRoot = resolve(process.env.RUNTIME_GATE_SOURCE_ROOT ?? 'packages/gate-core/src');
  const loadedPolicy = loadPolicyFile(policyFile, digestFileSet(sourceRoot, 'evaluator-build'));
  const policyContentDigest = digestFileSet(policyRoot, 'policy-set');
  const suffix = randomUUID().replaceAll('-', '');
  const store = WalStore.open({
    recordsRoot,
    worldId,
    runId: `verify_${suffix}`,
    bootId: `verify_boot_${suffix}`,
    policyVersion: loadedPolicy.policy.policy_version,
    policyContentDigest,
    evaluatorBuildDigest: loadedPolicy.evaluatorBuildDigest,
    deferRunHeader: true,
  });
  try {
    const report = await verifyRecords({
      recordsRoot,
      checkpointsRoot,
      local,
      repoRoot: process.cwd(),
      ...(process.env.RUNTIME_CHECKPOINT_BRANCH === undefined
        ? {}
        : { branch: process.env.RUNTIME_CHECKPOINT_BRANCH }),
      ...(process.env.RUNTIME_CHECKPOINT_REPO_URL === undefined
        ? {}
        : { repoUrl: process.env.RUNTIME_CHECKPOINT_REPO_URL }),
    });
    store.beginRun();
    await recordVerificationAccess(store, report.readLengths);
    process.stdout.write(`${report.message}\n`);
    for (const warning of report.warnings) process.stderr.write(`record verification warning: ${warning}\n`);
  } finally {
    store.close();
  }
}

main().catch((error) => {
  const message = error instanceof Error ? error.message : 'unknown verification error';
  process.stderr.write(`record verification failed: ${message}\n`);
  process.exitCode = 1;
});
