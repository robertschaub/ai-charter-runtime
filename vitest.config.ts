// SPDX-License-Identifier: AGPL-3.0-only
// Test harness configuration (LICENSE.md `tooling/` row: probes, scripts, test harness).
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/src/**/*.test.ts'],
    environment: 'node',
  },
});
