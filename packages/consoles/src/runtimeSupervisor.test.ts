// SPDX-License-Identifier: MIT
import { describe, expect, it } from 'vitest';

import { deriveAudienceToken } from 'gate-core';

import { runtimeChildEnvironments } from './runtimeSupervisor.js';

const baseKeys = [
  'Path',
  'RUNTIME_HOST',
  'AUTHZ_PORT',
  'ORCHESTRATOR_PORT',
  'SERVICES_PORT',
  'DEMO_WORLD_ID',
  'DEMO_CASE_ID',
  'RUNTIME_RECORDS_ROOT',
  'SWEEP_INTERVAL_MS',
];
const checkpointKeys = [
  'RUNTIME_CHECKPOINTS_ROOT',
  'RUNTIME_CHECKPOINT_BRANCH',
  'RUNTIME_CHECKPOINT_REPO_URL',
  'CHECKPOINT_VERIFY_LOCAL',
];

describe('runtime supervisor credential custody', () => {
  it('gives model configuration only to the orchestrator child and never forwards NODE_OPTIONS', () => {
    const env: NodeJS.ProcessEnv = {
      Path: 'synthetic-path',
      NODE_OPTIONS: '--inspect',
      OPENAI_API_KEY: 'must-not-cross',
      PUBLICAI_API_KEY: 'must-not-cross',
      OPENAI_BASE_URL: 'https://api.openai.com/v1',
      OPENAI_MODEL: 'gpt-5.5',
      PUBLICAI_BASE_URL: 'https://api.publicai.co/v1',
      PUBLICAI_MODEL: 'swiss-ai/apertus-v1.5-70b',
      RUNTIME_HOST: '127.0.0.1',
      AUTHZ_PORT: '17801',
      ORCHESTRATOR_PORT: '17802',
      SERVICES_PORT: '17803',
      DEMO_WORLD_ID: 'w-demo',
      DEMO_CASE_ID: 'case_demo',
      RUNTIME_RECORDS_ROOT: 'synthetic-records',
      SWEEP_INTERVAL_MS: '5000',
      RUNTIME_CHECKPOINTS_ROOT: 'synthetic-checkpoints',
      RUNTIME_CHECKPOINT_BRANCH: 'main',
      RUNTIME_CHECKPOINT_REPO_URL: 'https://github.com/example/runtime',
      CHECKPOINT_VERIFY_LOCAL: '1',
      AUTHZ_TOKEN_PRINCIPAL: '1'.repeat(64),
      AUTHZ_TOKEN_CASE_OFFICER: '2'.repeat(64),
      AUTHZ_TOKEN_APPLICANT: '3'.repeat(64),
      AUTHZ_TOKEN_PROC_ORCHESTRATOR: '4'.repeat(64),
      AUTHZ_TOKEN_PROC_SERVICES_HOST: '5'.repeat(64),
      SERVICES_TOKEN_PROC_AUTHZ: '6'.repeat(64),
      GATE_HMAC_KEY: 'a'.repeat(64),
      GATE_HMAC_KEY_ID: 'hmac-test',
    };

    const children = runtimeChildEnvironments(env);
    expect(Object.keys(children.authorization).sort()).toEqual(
      [
        ...baseKeys,
        ...checkpointKeys,
        'GATE_HMAC_KEY',
        'GATE_HMAC_KEY_ID',
        'AUTHZ_TOKEN_PRINCIPAL',
        'AUTHZ_TOKEN_CASE_OFFICER',
        'AUTHZ_TOKEN_APPLICANT',
        'AUTHZ_TOKEN_PROC_ORCHESTRATOR',
        'AUTHZ_TOKEN_PROC_SERVICES_HOST',
        'SERVICES_TOKEN_PROC_AUTHZ',
      ].sort(),
    );
    expect(Object.keys(children.services).sort()).toEqual(
      [
        ...baseKeys,
        'GATE_HMAC_KEY',
        'GATE_HMAC_KEY_ID',
        'AUTHZ_TOKEN_PROC_SERVICES_HOST',
        'SERVICES_TOKEN_PROC_AUTHZ',
        'SERVICES_TOKEN_PROC_ORCHESTRATOR',
      ].sort(),
    );
    expect(Object.keys(children.orchestrator).sort()).toEqual(
      [
        ...baseKeys,
        'AUTHZ_TOKEN_PROC_ORCHESTRATOR',
        'SERVICES_TOKEN_PROC_ORCHESTRATOR',
        'ORCHESTRATOR_TOKEN_CASE_OFFICER',
        'OPENAI_API_KEY',
        'OPENAI_BASE_URL',
        'OPENAI_MODEL',
        'PUBLICAI_API_KEY',
        'PUBLICAI_BASE_URL',
        'PUBLICAI_MODEL',
      ].sort(),
    );

    expect(children.services['SERVICES_TOKEN_PROC_ORCHESTRATOR']).toBe(
      deriveAudienceToken(env['AUTHZ_TOKEN_PROC_ORCHESTRATOR'] ?? '', 'services-proc-orchestrator'),
    );
    expect(children.orchestrator['ORCHESTRATOR_TOKEN_CASE_OFFICER']).toBe(
      deriveAudienceToken(env['AUTHZ_TOKEN_CASE_OFFICER'] ?? '', 'orchestrator-case-officer'),
    );
    for (const child of [children.authorization, children.services]) {
      expect(child).not.toHaveProperty('OPENAI_API_KEY');
      expect(child).not.toHaveProperty('PUBLICAI_API_KEY');
      expect(child).not.toHaveProperty('OPENAI_BASE_URL');
      expect(child).not.toHaveProperty('PUBLICAI_BASE_URL');
    }
    for (const child of Object.values(children)) {
      expect(child).not.toHaveProperty('NODE_OPTIONS');
    }
    expect(children.orchestrator['OPENAI_API_KEY']).toBe('must-not-cross');
    expect(children.orchestrator['PUBLICAI_API_KEY']).toBe('must-not-cross');
    expect(children.services).not.toHaveProperty('RUNTIME_CHECKPOINTS_ROOT');
    expect(children.orchestrator).not.toHaveProperty('CHECKPOINT_VERIFY_LOCAL');
  });
});
