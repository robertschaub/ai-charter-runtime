// SPDX-License-Identifier: MIT
// Test harness configuration (LICENSE.md `tooling/` row: probes, scripts, test harness).
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/src/**/*.test.ts'],
    environment: 'node',
  },
});
