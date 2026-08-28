// SPDX-License-Identifier: MIT
import { readFileSync, readdirSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';

import { REPOSITORY_ROOT } from './repository.js';

const SAFE_BUILTINS = new Set(['node:assert', 'node:buffer', 'node:crypto', 'node:fs', 'node:module', 'node:os', 'node:path', 'node:url', 'node:util']);
const SAFE_PACKAGES = new Set(['ajv', 'ajv/dist/2020.js', 'ajv-formats', 'gate-core/offline-safe', 'model-adapters/offline-safe', 'runtime-consoles/offline-safe', 'services-mock/offline-safe']);
const INFRA_PACKAGES = new Set(['runtime-consoles/m6-infrastructure', 'services-mock/m6-infrastructure']);
const IMPORT = /(?:from\s+|import\s*\(\s*|import\s+)(['"])([^'"]+)\1/g;
const SAFE_ENTRYPOINTS = new Map([
  ['gate-core/offline-safe', join(REPOSITORY_ROOT, 'packages', 'gate-core', 'src', 'offlineSafe.ts')],
  ['model-adapters/offline-safe', join(REPOSITORY_ROOT, 'packages', 'adapters', 'src', 'contracts.ts')],
  ['runtime-consoles/offline-safe', join(REPOSITORY_ROOT, 'packages', 'consoles', 'src', 'offlineSafe.ts')],
  ['services-mock/offline-safe', join(REPOSITORY_ROOT, 'packages', 'services-mock', 'src', 'offlineSafe.ts')],
]);

function resolveRelative(importer: string, specifier: string): string {
  const candidate = resolve(dirname(importer), specifier.replace(/\.js$/u, '.ts'));
  return candidate;
}

function typeOnlyImport(text: string, matchIndex: number): boolean {
  const before = text.slice(0, matchIndex);
  const start = Math.max(before.lastIndexOf('import'), before.lastIndexOf('export'));
  const separator = Math.max(before.lastIndexOf(';'), before.lastIndexOf('\n\n'));
  if (start < separator) return false;
  return /^(?:import|export)\s+type\b/u.test(before.slice(start).trimStart());
}

function scanSafeGraph(entry: string, visited: Set<string>): void {
  if (visited.has(entry)) return;
  visited.add(entry);
  const text = readFileSync(entry, 'utf8');
  if (/\b(?:fetch|WebSocket)\b|process\.env/u.test(text)) throw new Error(`M6 safe import graph reached a network/credential global in ${entry}`);
  for (const match of text.matchAll(IMPORT)) {
    if (typeOnlyImport(text, match.index ?? 0)) continue;
    const specifier = match[2]!;
    if (specifier.startsWith('.')) { scanSafeGraph(resolveRelative(entry, specifier), visited); continue; }
    const mapped = SAFE_ENTRYPOINTS.get(specifier);
    if (mapped !== undefined) { scanSafeGraph(mapped, visited); continue; }
    if (SAFE_BUILTINS.has(specifier)) continue;
    if (specifier.startsWith('node:')) throw new Error(`M6 safe import graph refused ${specifier} in ${entry}`);
    if (['zod', 'js-yaml'].includes(specifier) || SAFE_PACKAGES.has(specifier)) continue;
    throw new Error(`M6 safe import graph reached unlisted package ${specifier} in ${entry}`);
  }
}

export function assertOfflineImportBoundary(): void {
  const sourceRoot = join(REPOSITORY_ROOT, 'packages', 'm6-offline', 'src');
  for (const name of readdirSync(sourceRoot).filter((entry) => entry.endsWith('.ts') && !entry.endsWith('.test.ts')).sort()) {
    const text = readFileSync(join(sourceRoot, name), 'utf8');
    const infrastructure = name === 'infrastructureHarness.ts';
    assertOfflineSourceText(name, text, infrastructure);
  }
  const visited = new Set<string>();
  for (const entry of SAFE_ENTRYPOINTS.values()) scanSafeGraph(entry, visited);
}

/** Testable source-level boundary used by the repository scanner and negative fixtures. */
export function assertOfflineSourceText(name: string, text: string, infrastructure = false): void {
  for (const match of text.matchAll(IMPORT)) {
    if (typeOnlyImport(text, match.index ?? 0)) continue;
    const specifier = match[2]!;
    if (specifier.startsWith('.')) continue;
    if (SAFE_BUILTINS.has(specifier) || SAFE_PACKAGES.has(specifier)) continue;
    if (infrastructure && INFRA_PACKAGES.has(specifier)) continue;
    throw new Error(`M6 offline import boundary refused ${specifier} in ${name}`);
  }
  const globalText = name === 'runtimeEnvironment.ts'
    ? text.replaceAll('process.env.npm_config_user_agent', '')
    : text;
  if (name !== 'importBoundary.ts' && !infrastructure && /\b(?:fetch|WebSocket)\b|process\.env/u.test(globalText)) {
    throw new Error(`M6 offline global boundary refused ${name}`);
  }
  if (infrastructure && /process\.env|WebSocket/u.test(text)) {
    throw new Error('M6 infrastructure harness may not access environment credentials or WebSocket');
  }
}
