// SPDX-License-Identifier: MIT
// M0 capability probe — settles the endpoint/model/feature unknowns listed in docs/m0-probe-memo.md.
// Zero dependencies (Node >= 20). Keys load from .env.local and are never printed or written.
//
//   node tooling/probe.mjs --lane all|publicai|openai
//
// Results: console summary + docs/m0-probe-results.json (gitignored).

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const ROOT = path.resolve(new URL('..', import.meta.url).pathname.replace(/^\/([A-Za-z]:)/, '$1'));
const RESULTS_PATH = path.join(ROOT, 'docs', 'm0-probe-results.json');
const TIMEOUT_MS = 60_000;

// --- env ---------------------------------------------------------------
function loadDotEnvLocal() {
  const p = path.join(ROOT, '.env.local');
  if (!fs.existsSync(p)) return;
  for (const line of fs.readFileSync(p, 'utf8').split('\n')) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (m && m[2] && !(m[1] in process.env)) process.env[m[1]] = m[2];
  }
}
loadDotEnvLocal();

// --- lanes -------------------------------------------------------------
const LANES = {
  publicai: {
    label: 'PublicAI (Apertus)',
    keyEnv: 'PUBLICAI_API_KEY',
    baseUrls: process.env.PUBLICAI_BASE_URL
      ? [process.env.PUBLICAI_BASE_URL]
      : ['https://api.publicai.co/v1', 'https://platform.publicai.co/v1'],
    pickModel: (ids) =>
      process.env.PUBLICAI_MODEL ??
      ids.find((id) => /apertus-v1\.5-70b$/i.test(id)) ?? // v1.5, non-thinking (thinking mode lacks tool calling)
      ids.find((id) => /apertus-v1\.5-8b$/i.test(id)) ??
      ids.find((id) => /apertus/i.test(id)),
    headerHints: ['inference-id', 'x-ratelimit-limit', 'x-ratelimit-remaining', 'x-ratelimit-reset', 'retry-after'],
    tokenParam: 'max_tokens',
    maxTokens: 64,
    temperature: 0,
  },
  openai: {
    label: 'OpenAI (GPT)',
    keyEnv: 'OPENAI_API_KEY',
    baseUrls: ['https://api.openai.com/v1'],
    pickModel: (ids) => {
      const want = process.env.OPENAI_MODEL ?? 'gpt-5.5';
      return ids.includes(want) ? want : ids.find((id) => id.startsWith('gpt-5')) ?? want;
    },
    headerHints: ['x-ratelimit-limit-requests', 'x-ratelimit-remaining-requests', 'x-ratelimit-limit-tokens', 'retry-after'],
    tokenParam: 'max_completion_tokens', // gpt-5.x rejects max_tokens (M0 finding)
    maxTokens: 512, // reasoning tokens count against the cap; tiny caps starve output
    temperature: undefined, // gpt-5.x reasoning models accept only the default
  },
};

function chatBody(lane, model, text, extra = {}) {
  return {
    model,
    messages: [{ role: 'user', content: text }],
    [lane.tokenParam]: lane.maxTokens,
    ...(lane.temperature !== undefined ? { temperature: lane.temperature } : {}),
    ...extra,
  };
}

// --- http --------------------------------------------------------------
async function call(baseUrl, key, route, { method = 'GET', body, headerHints = [] } = {}) {
  const started = Date.now();
  try {
    const res = await fetch(baseUrl + route, {
      method,
      headers: { authorization: `Bearer ${key}`, 'content-type': 'application/json' },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    const ms = Date.now() - started;
    const headers = {};
    for (const h of headerHints) if (res.headers.get(h)) headers[h] = res.headers.get(h);
    let json = null;
    try { json = await res.json(); } catch { /* non-JSON body */ }
    return { ok: res.ok, status: res.status, ms, headers, json };
  } catch (e) {
    return { ok: false, status: 0, ms: Date.now() - started, headers: {}, error: String(e?.message ?? e) };
  }
}

const PING_TOOL = {
  type: 'function',
  function: {
    name: 'ping',
    description: 'Reply by calling this tool.',
    parameters: { type: 'object', properties: { ok: { type: 'boolean' } }, required: ['ok'] },
  },
};
const VERDICT_SCHEMA = {
  name: 'verdict',
  schema: {
    type: 'object',
    properties: { decision: { type: 'string', enum: ['allow', 'deny', 'escalate'] }, reason: { type: 'string' } },
    required: ['decision', 'reason'],
    additionalProperties: false,
  },
};

function summarize(r, extra = {}) {
  return { ok: r.ok, status: r.status, ms: r.ms, headers: r.headers, error: r.error ?? r.json?.error?.message ?? null, ...extra };
}

// --- per-lane probe ----------------------------------------------------
async function probeLane(name) {
  const lane = LANES[name];
  const key = process.env[lane.keyEnv];
  const out = { lane: name, label: lane.label, ranAt: new Date().toISOString() };
  if (!key) return { ...out, skipped: `no ${lane.keyEnv} in environment/.env.local` };

  // 1) find a working base URL via /models
  for (const baseUrl of lane.baseUrls) {
    const models = await call(baseUrl, key, '/models', { headerHints: lane.headerHints });
    const ids = (models.json?.data ?? []).map((m) => m.id);
    out.baseUrlCandidates = { ...(out.baseUrlCandidates ?? {}), [baseUrl]: summarize(models, { modelCount: ids.length }) };
    if (!models.ok || ids.length === 0) continue;

    out.baseUrl = baseUrl;
    out.modelIds = ids.filter((id) => name !== 'publicai' || /apertus|swiss/i.test(id));
    const model = lane.pickModel(ids);
    out.model = model;
    if (!model) { out.note = 'no candidate model id found in /models'; break; }

    // 2) plain chat — latency, served-model reporting
    const chat = await call(baseUrl, key, '/chat/completions', {
      method: 'POST', body: chatBody(lane, model, 'Reply with the single word: ready'), headerHints: lane.headerHints,
    });
    out.chat = summarize(chat, {
      servedModel: chat.json?.model ?? null,
      servedMatchesRequested: chat.json?.model ? chat.json.model === model : null,
      content: chat.json?.choices?.[0]?.message?.content?.slice(0, 60) ?? null,
    });

    // 3) response_format: json_schema, then json_object
    const rfSchema = await call(baseUrl, key, '/chat/completions', {
      method: 'POST',
      body: chatBody(lane, model, 'Return a gate verdict allowing a test action.', { response_format: { type: 'json_schema', json_schema: VERDICT_SCHEMA } }),
      headerHints: lane.headerHints,
    });
    let parsed = null;
    try { parsed = JSON.parse(rfSchema.json?.choices?.[0]?.message?.content ?? ''); } catch { /* not JSON */ }
    out.responseFormatJsonSchema = summarize(rfSchema, { parsedValidEnum: parsed ? ['allow', 'deny', 'escalate'].includes(parsed.decision) : false });

    const rfObject = await call(baseUrl, key, '/chat/completions', {
      method: 'POST',
      body: chatBody(lane, model, 'Return JSON: {"decision":"allow","reason":"test"}', { response_format: { type: 'json_object' } }),
      headerHints: lane.headerHints,
    });
    out.responseFormatJsonObject = summarize(rfObject);

    // 4) tools
    const tools = await call(baseUrl, key, '/chat/completions', {
      method: 'POST',
      body: chatBody(lane, model, 'Call the ping tool with ok=true.', { tools: [PING_TOOL] }),
      headerHints: lane.headerHints,
    });
    out.tools = summarize(tools, { toolCalled: Boolean(tools.json?.choices?.[0]?.message?.tool_calls?.length) });

    // 5) tiny latency sample (3 sequential small calls)
    const times = [];
    for (let i = 0; i < 3; i++) {
      const r = await call(baseUrl, key, '/chat/completions', { method: 'POST', body: chatBody(lane, model, 'Reply with the single word: ready') });
      if (r.ok) times.push(r.ms);
    }
    out.latencySampleMs = times;
    break;
  }
  return out;
}

// --- main ---------------------------------------------------------------
const laneArg = (process.argv.find((a) => a.startsWith('--lane')) ?? '--lane=all').split(/[= ]/)[1] ?? process.argv[process.argv.indexOf('--lane') + 1] ?? 'all';
const names = laneArg === 'all' ? Object.keys(LANES) : [laneArg];
if (names.some((n) => !LANES[n])) { console.error(`unknown lane: ${laneArg}`); process.exit(2); }

const results = { probedAt: new Date().toISOString(), lanes: {} };
for (const n of names) {
  console.log(`\n=== probing ${LANES[n].label} ===`);
  results.lanes[n] = await probeLane(n);
  console.log(JSON.stringify(results.lanes[n], null, 2));
}
fs.mkdirSync(path.dirname(RESULTS_PATH), { recursive: true });
fs.writeFileSync(RESULTS_PATH, JSON.stringify(results, null, 2));
console.log(`\nresults written to ${path.relative(ROOT, RESULTS_PATH)} — fill docs/m0-probe-memo.md from them.`);
