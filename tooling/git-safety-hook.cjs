// SPDX-License-Identifier: MIT
// Shared PreToolUse safety policy for Claude Code and Codex.

'use strict';

const SEPARATORS = new Set([';', '&', '&&', '|', '||', '(', ')', '\n', '\r\n']);
const GLOBAL_OPTIONS_WITH_VALUE = new Set([
  '-c',
  '-C',
  '--config-env',
  '--git-dir',
  '--namespace',
  '--work-tree',
]);

function unquote(token) {
  if (token.length >= 2) {
    const first = token[0];
    const last = token[token.length - 1];
    if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
      return token.slice(1, -1);
    }
  }
  return token;
}

function tokenize(command) {
  const matches = String(command).match(/"(?:\\.|[^"])*"|'(?:''|[^'])*'|&&|\|\||\r\n|[;&|()\n]|[^\s;&|()]+/g) ?? [];
  return matches.map((raw) => ({
    separator: SEPARATORS.has(raw),
    value: unquote(raw),
  }));
}

function isGitExecutable(value) {
  const basename = value.replaceAll('\\', '/').split('/').pop().toLowerCase();
  return basename === 'git' || basename === 'git.exe';
}

function splitInvocation(tokens, gitIndex) {
  const invocation = [];
  for (let index = gitIndex; index < tokens.length && !tokens[index].separator; index += 1) {
    invocation.push(tokens[index].value);
  }
  return invocation;
}

function splitSubcommand(invocation) {
  let index = 1;
  while (index < invocation.length) {
    const token = invocation[index];
    const lower = token.toLowerCase();

    if (GLOBAL_OPTIONS_WITH_VALUE.has(token) || GLOBAL_OPTIONS_WITH_VALUE.has(lower)) {
      index += 2;
      continue;
    }
    if (/^(?:-c|-C).+/.test(token) || /^--(?:config-env|git-dir|namespace|work-tree)=/i.test(token)) {
      index += 1;
      continue;
    }
    if (token.startsWith('-')) {
      index += 1;
      continue;
    }

    return {
      args: invocation.slice(index + 1),
      subcommand: lower,
    };
  }
  return { args: [], subcommand: '' };
}

function shortOptionContains(argument, option) {
  return /^-[^-]+$/.test(argument) && argument.slice(1).toLowerCase().includes(option);
}

function isBroadWorkingTreePath(argument) {
  const normalized = argument.replaceAll('\\', '/');
  return normalized === '.' || normalized === './';
}

function classifyInvocation(invocation) {
  const { args, subcommand } = splitSubcommand(invocation);
  const lowerArgs = args.map((argument) => argument.toLowerCase());

  if (subcommand === 'reset' && lowerArgs.some((argument) => argument === '--hard' || argument.startsWith('--hard='))) {
    return 'hard reset';
  }

  if (subcommand === 'push') {
    const forced = args.some((argument, index) => {
      const lower = lowerArgs[index];
      return lower === '--force' || lower.startsWith('--force=') || lower === '--mirror' ||
        shortOptionContains(argument, 'f') || argument.startsWith('+');
    });
    if (forced) return 'non-lease forced push';
  }

  if (subcommand === 'clean') {
    const forced = args.some((argument, index) => {
      const lower = lowerArgs[index];
      return lower === '--force' || shortOptionContains(argument, 'f');
    });
    if (forced) return 'forced clean';
  }

  if ((subcommand === 'checkout' || subcommand === 'restore') && args.some(isBroadWorkingTreePath)) {
    return `broad ${subcommand} discard`;
  }

  if (subcommand === 'switch' && args.some((argument, index) => {
    const lower = lowerArgs[index];
    return lower === '--discard-changes' || shortOptionContains(argument, 'f');
  })) {
    return 'forced switch discard';
  }

  return null;
}

function findBlockedOperation(command) {
  const tokens = tokenize(command);
  for (let index = 0; index < tokens.length; index += 1) {
    if (tokens[index].separator || !isGitExecutable(tokens[index].value)) continue;
    const reason = classifyInvocation(splitInvocation(tokens, index));
    if (reason) return reason;
  }
  return null;
}

function run() {
  let input = '';
  process.stdin.setEncoding('utf8');
  process.stdin.on('data', (chunk) => { input += chunk; });
  process.stdin.on('end', () => {
    let payload;
    try {
      payload = JSON.parse(input);
    } catch {
      console.error('BLOCKED by ai-charter-runtime safety hook: invalid hook input');
      process.exitCode = 2;
      return;
    }

    const command = payload?.tool_input?.command;
    if (typeof command !== 'string') return;
    const reason = findBlockedOperation(command);
    if (!reason) return;

    console.error(`BLOCKED by ai-charter-runtime safety hook: ${reason}`);
    process.exitCode = 2;
  });
}

module.exports = { findBlockedOperation, run, tokenize };

if (require.main === module) run();
