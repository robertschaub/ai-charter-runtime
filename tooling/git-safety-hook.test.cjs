// SPDX-License-Identifier: MIT

'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const { test } = require('node:test');
const path = require('node:path');
const { findBlockedOperation } = require('./git-safety-hook.cjs');

const HOOK_PATH = path.join(__dirname, 'git-safety-hook.cjs');

const BLOCKED = [
  'git reset --hard',
  'GIT -C C:\\repo RESET --HARD HEAD~1',
  '& "C:\\Program Files\\Git\\cmd\\git.exe" reset HEAD --hard',
  'git push --force origin main',
  'git push -f origin main',
  'git push -uf origin main',
  'git push origin +main',
  'git clean -fd',
  'git clean --force -d',
  'git checkout HEAD -- .',
  'git checkout .',
  'git restore --source=HEAD -- .\\',
  'git switch -f main',
];

const ALLOWED = [
  'git status --short',
  'git diff --check',
  'git push --force-with-lease origin main',
  'git clean -nd',
  "Write-Output 'git reset --hard'",
  'node -e "console.log(\'git push -f\')"',
];

test('classifies destructive Git variants', () => {
  for (const command of BLOCKED) {
    assert.ok(findBlockedOperation(command), `expected blocked: ${command}`);
  }
});

test('allows non-destructive commands and force-with-lease', () => {
  for (const command of ALLOWED) {
    assert.equal(findBlockedOperation(command), null, `expected allowed: ${command}`);
  }
});

test('PreToolUse process exits 2 for a blocked command', () => {
  const result = spawnSync(process.execPath, [HOOK_PATH], {
    encoding: 'utf8',
    input: JSON.stringify({ tool_input: { command: 'git -C C:\\repo push -f origin main' } }),
  });
  assert.equal(result.status, 2);
  assert.match(result.stderr, /BLOCKED by ai-charter-runtime safety hook/);
});

test('PreToolUse process exits 0 for force-with-lease', () => {
  const result = spawnSync(process.execPath, [HOOK_PATH], {
    encoding: 'utf8',
    input: JSON.stringify({ tool_input: { command: 'git push --force-with-lease origin main' } }),
  });
  assert.equal(result.status, 0);
  assert.equal(result.stderr, '');
});
