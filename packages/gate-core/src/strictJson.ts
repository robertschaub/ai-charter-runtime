// SPDX-License-Identifier: AGPL-3.0-only
/** JSON grammar validation that preserves object key sets before JSON.parse collapses them. */

/** Reject duplicate object keys at every nesting level while otherwise validating JSON grammar. */
export function assertNoDuplicateJsonKeys(content: string): void {
  let cursor = 0;
  const whitespace = () => { while (/\s/u.test(content[cursor] ?? '')) cursor += 1; };
  const stringValue = (): string => {
    const start = cursor;
    if (content[cursor] !== '"') throw new Error('expected string');
    cursor += 1;
    while (cursor < content.length) {
      const current = content[cursor];
      if (current === '"') {
        cursor += 1;
        return JSON.parse(content.slice(start, cursor)) as string;
      }
      if (current === '\\') {
        cursor += 1;
        if (content[cursor] === 'u') cursor += 4;
      }
      cursor += 1;
    }
    throw new Error('unterminated string');
  };
  const value = (): void => {
    whitespace();
    const current = content[cursor];
    if (current === '{') {
      cursor += 1;
      whitespace();
      const keys = new Set<string>();
      if (content[cursor] === '}') { cursor += 1; return; }
      while (true) {
        whitespace();
        const key = stringValue();
        if (keys.has(key)) throw new Error('duplicate key');
        keys.add(key);
        whitespace();
        if (content[cursor] !== ':') throw new Error('expected colon');
        cursor += 1;
        value();
        whitespace();
        if (content[cursor] === '}') { cursor += 1; return; }
        if (content[cursor] !== ',') throw new Error('expected comma');
        cursor += 1;
      }
    }
    if (current === '[') {
      cursor += 1;
      whitespace();
      if (content[cursor] === ']') { cursor += 1; return; }
      while (true) {
        value();
        whitespace();
        if (content[cursor] === ']') { cursor += 1; return; }
        if (content[cursor] !== ',') throw new Error('expected comma');
        cursor += 1;
      }
    }
    if (current === '"') { void stringValue(); return; }
    const tail = content.slice(cursor);
    const token = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/u.exec(tail)?.[0];
    if (token === undefined) throw new Error('invalid token');
    cursor += token.length;
  };
  value();
  whitespace();
  if (cursor !== content.length) throw new Error('trailing data');
}
