<!-- SPDX-License-Identifier: CC-BY-4.0 -->

# Gemini CLI — ai-charter-runtime

@./AGENTS.md

Root AGENTS.md is canonical. Before target work, inspect the active session's loaded context; if the root is not visible, read it explicitly. Read applicable nested AGENTS.md files before touching their paths, including when the session began at the root. Do not assume context.fileName discovery or automatic import deduplication: record effective repository configuration and any unknown higher-scope behavior without inspecting excluded profiles.

Use only the repositories, operations and writable state named in the current task. Additional-directory context is task-scoped; a settings change does not erase context already loaded in an old session. Close affected sessions before changing context/import policy and start fresh after changes. Access does not grant public disclosure authority.

Use the skill authority and discovery paths declared by this repository; do not assume a workflow is installed. Bind workflows to the current task and explicit arguments; skill loading adds no operation authority. Claude and Codex metadata do not establish Gemini controls. Follow canonical ownership, current-authorization and recovery rules; strict read-only reviewers use existing source/output and return findings in chat.
