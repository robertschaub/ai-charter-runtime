// SPDX-License-Identifier: MIT
import { loadCatalog, loadProviderFixture } from './catalog.js';
import { generateAcceptanceMarkdown } from './acceptance.js';
import { readSafeRepositoryFile } from './repository.js';
import { dryRunPlan, runOfflinePlan } from './runner.js';
import { assertOfflineImportBoundary } from './importBoundary.js';
import { SchemaRegistry } from './schemas.js';

function planArgument(args: readonly string[]): string {
  if (args.length !== 2 || args[0] !== '--plan' || args[1] === undefined) throw new Error('usage requires exactly --plan <repository-relative-json>');
  return args[1];
}

async function main(): Promise<void> {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'schemas') {
    if (args.length !== 0) throw new Error('m6:schemas accepts no arguments');
    const registry = new SchemaRegistry();
    assertOfflineImportBoundary();
    loadCatalog(registry);
    loadProviderFixture(registry);
    const generated = generateAcceptanceMarkdown(loadCatalog(registry).catalog);
    if (readSafeRepositoryFile('docs/m6/acceptance.md').toString('utf8') !== generated) throw new Error('docs/m6/acceptance.md has generated drift');
    process.stdout.write('M6 schemas and committed sources validate.\n');
    return;
  }
  if (command === 'dry-run') {
    const plan = dryRunPlan(planArgument(args));
    process.stdout.write(`M6 dry-run validated ${plan.capture_id}; no scenario or staging writer entered.\n`);
    return;
  }
  if (command === 'offline-fixture') {
    const result = await runOfflinePlan(planArgument(args));
    process.stdout.write(`M6 offline fixture staged at ${result.captureRoot}; not published.\n`);
    return;
  }
  throw new Error('expected schemas, dry-run, or offline-fixture');
}

void main().catch((error: unknown) => {
  const code = typeof error === 'object' && error !== null && 'code' in error ? String(error.code) : 'm6-command-failed';
  process.stderr.write(`${code}: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
