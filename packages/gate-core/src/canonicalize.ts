// SPDX-License-Identifier: AGPL-3.0-only
/**
 * ADR-007 — canonical JSON, a JCS-compatible subset.
 *
 * Implements the RFC 8785 rules for the value subset this POC uses:
 *   - objects   — keys sorted with JavaScript's default string sort (UTF-16 code-unit
 *                 order, exactly what JCS specifies); no whitespace; arrays keep order;
 *   - strings   — `JSON.stringify` of the string (Node >= 20 emits JCS's shortest-escape
 *                 form, lowercase `\uXXXX`, for valid Unicode);
 *   - numbers   — safe integers only, serialized with `String(n)`;
 *   - literals  — `true` / `false` / `null`.
 *
 * The subset is enforced by throwing. A value that cannot be canonicalized cannot be
 * hashed, so it can be neither ruled on nor recorded — the gate treats it as ambiguity
 * and fails closed.
 *
 * The claim made here is JCS-compatibility *for this subset*, asserted against the
 * committed vectors in `fixtures/jcs/`. This is not a general RFC 8785 implementation.
 */

/** Every way a value can fall outside the subset. */
export type CanonicalizationErrorCode =
  | 'non-integer-number'
  | 'not-finite'
  | 'unsafe-integer'
  | 'bigint'
  | 'undefined'
  | 'date'
  | 'map-or-set'
  | 'class-instance'
  | 'lone-surrogate'
  | 'function'
  | 'symbol'
  | 'non-json-property'
  | 'cycle';

export class CanonicalizationError extends Error {
  readonly code: CanonicalizationErrorCode;
  /** JSON-Pointer-ish location of the offending value, `""` for the root. */
  readonly path: string;

  constructor(code: CanonicalizationErrorCode, path: string, detail: string) {
    super(`canonicalize: ${detail} at ${path === '' ? '<root>' : path}`);
    this.name = 'CanonicalizationError';
    this.code = code;
    this.path = path;
  }
}

/** True when the string contains an unpaired UTF-16 surrogate code unit. */
function hasLoneSurrogate(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const unit = s.charCodeAt(i);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = i + 1 < s.length ? s.charCodeAt(i + 1) : 0;
      if (next < 0xdc00 || next > 0xdfff) return true;
      i += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function escapePathSegment(segment: string): string {
  return segment.replace(/~/g, '~0').replace(/\//g, '~1');
}

function serializeString(value: string, path: string): string {
  if (hasLoneSurrogate(value)) {
    throw new CanonicalizationError('lone-surrogate', path, 'string contains a lone surrogate');
  }
  return JSON.stringify(value);
}

function serializeNumber(value: number, path: string): string {
  if (!Number.isFinite(value)) {
    throw new CanonicalizationError('not-finite', path, 'NaN and +/-Infinity are outside the subset');
  }
  if (!Number.isInteger(value)) {
    throw new CanonicalizationError('non-integer-number', path, 'only integers are inside the subset');
  }
  if (!Number.isSafeInteger(value)) {
    throw new CanonicalizationError('unsafe-integer', path, 'integer outside the safe range');
  }
  // String(-0) is "0", which is the JCS form.
  return String(value);
}

function serialize(value: unknown, path: string, stack: Set<object>): string {
  switch (typeof value) {
    case 'undefined':
      throw new CanonicalizationError('undefined', path, 'undefined has no canonical form');
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      return serializeNumber(value, path);
    case 'string':
      return serializeString(value, path);
    case 'bigint':
      throw new CanonicalizationError('bigint', path, 'BigInt is outside the subset');
    case 'function':
      throw new CanonicalizationError('function', path, 'functions have no canonical form');
    case 'symbol':
      throw new CanonicalizationError('symbol', path, 'symbols have no canonical form');
    default:
      break;
  }

  if (value === null) return 'null';

  const object = value as object;
  if (value instanceof Date) {
    throw new CanonicalizationError('date', path, 'Date is outside the subset (use an RFC 3339 string)');
  }
  if (value instanceof Map || value instanceof Set) {
    throw new CanonicalizationError('map-or-set', path, 'Map and Set are outside the subset');
  }
  if (stack.has(object)) {
    throw new CanonicalizationError('cycle', path, 'circular reference');
  }

  const prototype = Object.getPrototypeOf(object) as object | null;
  stack.add(object);
  try {
    if (Array.isArray(value)) {
      if (prototype !== Array.prototype) {
        throw new CanonicalizationError('class-instance', path, 'array subclasses are outside the subset');
      }
      for (const key of Reflect.ownKeys(value)) {
        if (typeof key === 'symbol') {
          throw new CanonicalizationError('symbol', path, 'symbol-keyed properties are outside the subset');
        }
        if (key === 'length') continue;
        const index = Number(key);
        if (!Number.isSafeInteger(index) || index < 0 || String(index) !== key || index >= value.length) {
          throw new CanonicalizationError('non-json-property', path, `array property ${key} is outside the subset`);
        }
        const descriptor = Object.getOwnPropertyDescriptor(value, key);
        if (descriptor === undefined || !('value' in descriptor)) {
          throw new CanonicalizationError('non-json-property', `${path}/${key}`, 'accessor properties are outside the subset');
        }
      }
      const parts: string[] = [];
      for (let i = 0; i < value.length; i += 1) {
        parts.push(serialize(value[i], `${path}/${i}`, stack));
      }
      return `[${parts.join(',')}]`;
    }

    if (prototype !== Object.prototype && prototype !== null) {
      throw new CanonicalizationError('class-instance', path, 'class instances are outside the subset');
    }

    const record = value as Record<string, unknown>;
    for (const key of Reflect.ownKeys(record)) {
      if (typeof key === 'symbol') {
        throw new CanonicalizationError('symbol', path, 'symbol-keyed properties are outside the subset');
      }
      const descriptor = Object.getOwnPropertyDescriptor(record, key);
      if (descriptor === undefined || !descriptor.enumerable || !('value' in descriptor)) {
        throw new CanonicalizationError(
          'non-json-property',
          `${path}/${escapePathSegment(key)}`,
          'non-enumerable and accessor properties are outside the subset',
        );
      }
    }
    // Own enumerable string keys only; JCS sorts them by UTF-16 code unit, which is
    // exactly JavaScript's default string sort.
    const keys = Object.keys(record).sort();
    const parts: string[] = [];
    for (const key of keys) {
      const childPath = `${path}/${escapePathSegment(key)}`;
      const serializedValue = serialize(record[key], childPath, stack);
      parts.push(`${serializeString(key, childPath)}:${serializedValue}`);
    }
    return `{${parts.join(',')}}`;
  } finally {
    stack.delete(object);
  }
}

/**
 * Canonical JSON string for `value`, per ADR-007's subset.
 *
 * @throws {CanonicalizationError} when the value falls outside the subset.
 */
export function canonicalize(value: unknown): string {
  return serialize(value, '', new Set<object>());
}
