// SPDX-License-Identifier: MIT
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  acceptsHandoffReady,
  consoleApiPath,
  parseGovernanceRuntimeConfig,
  parseConsoleDeepLink,
  permittedDialogueDispositions,
  permittedGeneralDispositions,
  validWorldId,
} from './governanceConsole.js';

describe('authorization-origin governance console contract', () => {
  it('builds only validated same-origin API paths', () => {
    expect(consoleApiPath('w-demo', 'mandates', 'mdt_demo', 'approved-models')).toBe(
      '/w/w-demo/mandates/mdt_demo/approved-models',
    );
    expect(consoleApiPath('w-demo', 'mandates', 'mdt:demo')).toBe('/w/w-demo/mandates/mdt:demo');
    expect(validWorldId('w-demo')).toBe(true);
    expect(validWorldId('con')).toBe(false);
    expect(() => consoleApiPath('w-demo', '..', 'mandates')).toThrow(/invalid API path segment/);
    expect(() => consoleApiPath('w/other', 'mandates')).toThrow(/invalid world id/);
  });

  it('accepts token-free dialogue deep links but no query or malformed authority input', () => {
    expect(parseConsoleDeepLink('/console/dialogue/w-demo/esc_123')).toEqual({
      kind: 'dialogue',
      worldId: 'w-demo',
      escalationId: 'esc_123',
    });
    expect(parseConsoleDeepLink('/console/dialogue/w-demo/esc_123?token=secret')).toBeNull();
    expect(parseConsoleDeepLink('/console/dialogue/con/esc_123')).toBeNull();
    expect(parseConsoleDeepLink('/console/dialogue/w-demo/../records')).toBeNull();
  });

  it('renders only open, contract-permitted general dispositions', () => {
    expect(
      permittedGeneralDispositions('open', ['deny', 'confirm', 'route-to-remedy', 'invented']),
    ).toEqual(['deny', 'route-to-remedy']);
    expect(permittedGeneralDispositions('disposed', ['deny'])).toEqual([]);
    expect(permittedGeneralDispositions('open', 'deny')).toEqual([]);
    expect(
      permittedDialogueDispositions('open', ['confirm', 'deny', 'route', 'invented']),
    ).toEqual(['confirm', 'route']);
    expect(permittedDialogueDispositions('disposed', ['confirm'])).toEqual([]);
  });

  it('accepts a handoff readiness message only from the exact opened window and configured origin', () => {
    const child = {} as WindowProxy;
    const other = {} as WindowProxy;
    const ready = { origin: 'http://127.0.0.1:7802', source: child, data: { type: 'runtime.case-handoff.ready' } };
    expect(acceptsHandoffReady(ready, ready.origin, child)).toBe(true);
    expect(acceptsHandoffReady({ ...ready, origin: 'null' }, ready.origin, child)).toBe(false);
    expect(acceptsHandoffReady({ ...ready, source: other }, ready.origin, child)).toBe(false);
    expect(acceptsHandoffReady({ ...ready, data: { type: 'runtime.case-handoff.ready', extra: true } }, ready.origin, child)).toBe(false);
    expect(
      parseGovernanceRuntimeConfig({
        authorization_origin: 'http://127.0.0.1:7801',
        orchestrator_origin: 'http://127.0.0.1:7802',
      }),
    ).not.toBeNull();
  });

  it('keeps the static shell free of inline or third-party executable content', () => {
    const shell = readFileSync(resolve('packages/consoles/assets/governance-console/index.html'), 'utf8');
    expect(shell).toContain('<script type="module" src="/console/app.js"></script>');
    expect(shell).toContain('<link rel="stylesheet" href="/console/styles.css">');
    expect(shell).not.toMatch(/<script(?![^>]*\bsrc=)/i);
    expect(shell).not.toMatch(/<style\b/i);
    expect(shell).not.toMatch(/\son[a-z]+=/i);
    expect(shell).not.toMatch(/https?:\/\//i);
  });
});
