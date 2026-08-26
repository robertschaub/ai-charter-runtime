// SPDX-License-Identifier: MIT
import { Ajv2020, type ErrorObject, type ValidateFunction } from 'ajv/dist/2020.js';
import * as AjvFormatsModule from 'ajv-formats';

import { readSafeRepositoryFile } from './repository.js';

const addFormats = (AjvFormatsModule as unknown as { readonly default: import('ajv-formats').FormatsPlugin }).default;

export const SCHEMA_PATHS = {
  caseCatalog: 'docs/m6/schema/case-catalog.schema.json',
  providerProjectionFixture: 'docs/m6/schema/provider-projection-fixture.schema.json',
  capturePlan: 'docs/m6/schema/capture-plan.schema.json',
  offlineMatrix: 'docs/m6/schema/offline-matrix.schema.json',
  attemptEvents: 'docs/m6/schema/attempt-events.schema.json',
  sanitizationReport: 'docs/m6/schema/sanitization-report.schema.json',
  captureManifest: 'docs/m6/schema/capture-manifest.schema.json',
} as const;

export type SchemaName = keyof typeof SCHEMA_PATHS;

export class M6SchemaError extends Error {
  constructor(readonly code: string, message: string, readonly errors: readonly ErrorObject[] = []) {
    super(message);
    this.name = 'M6SchemaError';
  }
}

function parseSchema(path: string): object {
  return JSON.parse(readSafeRepositoryFile(path).toString('utf8')) as object;
}

export class SchemaRegistry {
  readonly #validators = new Map<SchemaName, ValidateFunction>();

  constructor() {
    const ajv = new Ajv2020({ allErrors: true, strict: true, validateFormats: true });
    addFormats(ajv);
    for (const [name, path] of Object.entries(SCHEMA_PATHS) as [SchemaName, string][]) {
      this.#validators.set(name, ajv.compile(parseSchema(path)));
    }
  }

  validate(name: SchemaName, value: unknown): void {
    const validator = this.#validators.get(name);
    if (validator === undefined) throw new M6SchemaError('m6-schema-missing', `schema ${name} is not registered`);
    if (!validator(value)) {
      const errors = validator.errors ?? [];
      throw new M6SchemaError(
        'm6-schema-invalid',
        `${name} failed validation: ${errors.map((error) => `${error.instancePath || '/'} ${error.message ?? 'invalid'}`).join('; ')}`,
        errors,
      );
    }
  }
}
