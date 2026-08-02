// SPDX-License-Identifier: AGPL-3.0-only
import { describe, expect, it } from 'vitest';

import { deriveAudienceToken } from './runtimeCredentials.js';

describe('deriveAudienceToken', () => {
  it('is deterministic and separates audiences without returning the source credential', () => {
    const source = 'a'.repeat(64);
    const authorizationAudience = deriveAudienceToken(source, 'authorization-proc-orchestrator');
    const servicesAudience = deriveAudienceToken(source, 'services-proc-orchestrator');

    expect(authorizationAudience).toHaveLength(64);
    expect(authorizationAudience).toBe(deriveAudienceToken(source.toUpperCase(), 'authorization-proc-orchestrator'));
    expect(authorizationAudience).not.toBe(source);
    expect(servicesAudience).not.toBe(authorizationAudience);
  });

  it('rejects low-entropy sources and malformed audiences', () => {
    expect(() => deriveAudienceToken('not-a-runtime-credential', 'services')).toThrow(TypeError);
    expect(() => deriveAudienceToken('a'.repeat(64), '../services')).toThrow(TypeError);
  });
});
