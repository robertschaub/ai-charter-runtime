// SPDX-License-Identifier: MIT
import { SchemaRegistry, type SchemaName } from './schemas.js';

const FORBIDDEN_KEYS = /^(?:authorization|cookie|set-cookie|credential|token|mac|private_key|hostname|username|machine_id|environment_variables|raw_body|raw_headers|provider_payload)$/i;
const FORBIDDEN_VALUES = /(?:Bearer\s+[A-Za-z0-9._~-]+|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|file:|\\\\|\\\?\\|\\\.\\|(?:^|[\s"'])(?:[A-Za-z]:[\\/]|\/(?:home|Users|root|etc|proc|sys)\/))/i;

function scan(value: unknown, path = '$'): void {
  if (Array.isArray(value)) { value.forEach((entry, index) => scan(entry, `${path}[${index}]`)); return; }
  if (value !== null && typeof value === 'object') {
    for (const [key, entry] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.test(key)) throw new Error(`M6 sanitization refused forbidden key at ${path}.${key}`);
      scan(entry, `${path}.${key}`);
    }
    return;
  }
  if (typeof value === 'string' && FORBIDDEN_VALUES.test(value)) throw new Error(`M6 sanitization refused forbidden content at ${path}`);
}

export function sanitizeArtifact(schema: SchemaName, value: unknown, layer: 'dry-run' | 'offline-fixture', registry = new SchemaRegistry()): void {
  registry.validate(schema, value);
  scan(value);
  const encoded = JSON.stringify(value);
  if (layer !== 'offline-fixture' && encoded.includes('"layer":"offline-fixture"')) throw new Error('M6 artifact layer label mismatch');
  if (encoded.includes('"layer":"live"')) throw new Error('M6.3 artifact cannot claim live evidence');
}
