// SPDX-License-Identifier: AGPL-3.0-only
/** One observable-expiry and commitment-reconciliation maintenance pass. */
import type { AuthorizationCore, CommitmentProbe, ReconcileCommitmentResult } from './authorizationCore.js';
import type { Keyring } from './keyring.js';
import type { LoadedPolicy } from './policyLoader.js';
import { runSweeper, type SweepResult } from './sweeper.js';
import type { SystemUseDecisionService } from './systemUseDecision.js';
import type { WalStore } from './walStore.js';

export interface RuntimeMaintenanceOptions {
  readonly authorization: AuthorizationCore;
  readonly store: WalStore;
  readonly keyring: Keyring;
  readonly policy: LoadedPolicy;
  readonly systemUse: SystemUseDecisionService;
  readonly probe: (idempotencyKey: string) => Promise<CommitmentProbe>;
}

export interface RuntimeMaintenanceResult {
  readonly sweep: SweepResult;
  readonly reconciliations: readonly {
    readonly commitmentId: string;
    readonly result: ReconcileCommitmentResult;
  }[];
}

export async function runRuntimeMaintenance(
  options: RuntimeMaintenanceOptions,
): Promise<RuntimeMaintenanceResult> {
  const sweep = await runSweeper(options.store, options.keyring, options.policy, options.systemUse);
  const pending = [...options.store.snapshot().commitments.values()]
    .filter((commitment) => commitment.state === 'bound' || commitment.state === 'unknown')
    .map((commitment) => commitment.commitment_id)
    .sort();
  const reconciliations: { commitmentId: string; result: ReconcileCommitmentResult }[] = [];
  for (const commitmentId of pending) {
    reconciliations.push({
      commitmentId,
      result: await options.authorization.reconcileCommitment({
        commitmentId,
        probe: options.probe,
      }),
    });
  }
  return { sweep, reconciliations };
}
