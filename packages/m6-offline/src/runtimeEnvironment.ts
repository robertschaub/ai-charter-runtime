// SPDX-License-Identifier: MIT
/** Narrow, non-credential runtime environment observation for an exact capture-plan binding. */
export function currentNpmVersion(): string {
  const userAgent = process.env.npm_config_user_agent;
  const match = userAgent?.match(/(?:^|\s)npm\/([^\s]+)/u);
  if (match?.[1] === undefined) throw new Error('M6 runtime environment cannot verify npm_version');
  return match[1];
}
