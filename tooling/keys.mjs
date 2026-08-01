// SPDX-License-Identifier: MIT
// Key and credential generation for the runtime POC (ADR-002 §2, ADR-007).
// Zero dependencies (Node >= 20).
//
//   node tooling/keys.mjs generate       [--force]   fill .env.local: six credentials + the HMAC pair
//   node tooling/keys.mjs rotate-hmac               retire the current HMAC pair, write a new one
//   node tooling/keys.mjs gen-card-keys  [--force]   new Ed25519 model-card signing key pair
//
// Values are NEVER printed and never leave the gitignored files below. The console gets
// labels only. Existing non-empty values are never overwritten without --force.
//
//   .env.local                             (gitignored)  active credentials + active HMAC pair
//   keys/hmac-keyring.json                 (gitignored)  retired HMAC pairs, still verifiable
//   keys/model-card-signing.ed25519.json   (gitignored)  the private card signing key
//   docs/cards/signing-keys.json           (committed)   public verification keys, the trust root

import { generateKeyPairSync, randomBytes } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ENV_PATH = path.join(ROOT, '.env.local');
const KEYS_DIR = path.join(ROOT, 'keys');
const KEYRING_PATH = path.join(KEYS_DIR, 'hmac-keyring.json');
const CARD_PRIVATE_PATH = path.join(KEYS_DIR, 'model-card-signing.ed25519.json');
const SIGNING_KEYS_PATH = path.join(ROOT, 'docs', 'cards', 'signing-keys.json');

/** ADR-002 §2: two credential families, both 32 random bytes, hex, all mutually distinct. */
const CREDENTIAL_VARS = [
  'AUTHZ_TOKEN_PRINCIPAL',
  'AUTHZ_TOKEN_CASE_OFFICER',
  'AUTHZ_TOKEN_APPLICANT',
  'AUTHZ_TOKEN_PROC_ORCHESTRATOR',
  'AUTHZ_TOKEN_PROC_SERVICES_HOST',
  'SERVICES_TOKEN_PROC_AUTHZ',
];

// --- helpers -----------------------------------------------------------

function fail(message) {
  console.error(`keys: ${message}`);
  process.exit(1);
}

function token32() {
  return randomBytes(32).toString('hex');
}

function today() {
  return new Date().toISOString().slice(0, 10);
}

function readLines(file) {
  if (!fs.existsSync(file)) return [];
  return fs.readFileSync(file, 'utf8').split('\n');
}

/** Current value of `name`, or undefined when the variable is absent. */
function readVar(lines, name) {
  const pattern = new RegExp(`^\\s*${name}\\s*=(.*)$`);
  for (const line of lines) {
    const match = line.match(pattern);
    if (match) return match[1].replace(/\s+#.*$/, '').trim();
  }
  return undefined;
}

/** Set `name` in place when present, append otherwise. Comments are preserved. */
function upsertVar(lines, name, value) {
  const pattern = new RegExp(`^(\\s*${name}\\s*=)(.*)$`);
  for (let i = 0; i < lines.length; i += 1) {
    const match = lines[i].match(pattern);
    if (match) {
      const comment = match[2].match(/\s+(#.*)$/);
      lines[i] = `${match[1]}${value}${comment ? `  ${comment[1]}` : ''}`;
      return lines;
    }
  }
  while (lines.length > 0 && lines[lines.length - 1].trim() === '') lines.pop();
  lines.push(`${name}=${value}`, '');
  return lines;
}

function writeLines(file, lines) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  let text = lines.join('\n');
  if (!text.endsWith('\n')) text += '\n';
  fs.writeFileSync(file, text, { encoding: 'utf8', mode: 0o600 });
}

function writeJson(file, value, mode) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`, { encoding: 'utf8', ...(mode === undefined ? {} : { mode }) });
}

function readJson(file, fallback) {
  if (!fs.existsSync(file)) return fallback;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    fail(`${path.relative(ROOT, file)} is not valid JSON — resolve it by hand before continuing`);
  }
  return fallback;
}

/** Append `-2`, `-3`, ... when a key id for today already exists. */
function uniqueKeyId(prefix, taken) {
  const base = `${prefix}-${today()}`;
  if (!taken.has(base)) return base;
  for (let n = 2; n < 100; n += 1) {
    const candidate = `${base}-${n}`;
    if (!taken.has(candidate)) return candidate;
  }
  fail(`cannot allocate a ${prefix} key id for today`);
  return base;
}

// --- commands ----------------------------------------------------------

function generate(force) {
  const lines = readLines(ENV_PATH);
  const wanted = [...CREDENTIAL_VARS, 'GATE_HMAC_KEY'];

  const occupied = wanted.filter((name) => {
    const current = readVar(lines, name);
    return current !== undefined && current !== '';
  });
  if (occupied.length > 0 && !force) {
    console.error('keys: refusing to overwrite existing values for:');
    for (const name of occupied) console.error(`  ${name}`);
    console.error('keys: re-run with --force to replace them (old values are NOT recoverable).');
    process.exit(1);
  }

  // Six distinct credentials plus the HMAC key, all independently random.
  const issued = new Map();
  while (issued.size < wanted.length) {
    for (const name of wanted) {
      if (!issued.has(name)) issued.set(name, token32());
    }
    const distinct = new Set(issued.values());
    if (distinct.size < issued.size) issued.clear(); // astronomically unlikely; still checked
  }

  let next = lines;
  for (const [name, value] of issued) next = upsertVar(next, name, value);

  const existingKeyId = readVar(next, 'GATE_HMAC_KEY_ID');
  const takenKeyIds = keyringKeyIds();
  if (force && existingKeyId) takenKeyIds.add(existingKeyId);
  const keyId = existingKeyId && !force ? existingKeyId : uniqueKeyId('hmac', takenKeyIds);
  next = upsertVar(next, 'GATE_HMAC_KEY_ID', keyId);

  writeLines(ENV_PATH, next);
  console.log(`keys: wrote ${path.relative(ROOT, ENV_PATH)} (values not shown)`);
  for (const name of wanted) console.log(`  ${name}  set`);
  console.log(`  GATE_HMAC_KEY_ID  ${keyId}`);
}

function keyringKeyIds() {
  const keyring = readJson(KEYRING_PATH, { keys: [] });
  return new Set((keyring.keys ?? []).map((entry) => entry.key_id));
}

/** ADR-007: rotation is a new key id, never a re-signing pass. */
function rotateHmac() {
  const lines = readLines(ENV_PATH);
  const currentKey = readVar(lines, 'GATE_HMAC_KEY');
  const currentId = readVar(lines, 'GATE_HMAC_KEY_ID');

  const keyring = readJson(KEYRING_PATH, { schema: 'ai-charter-runtime/hmac-keyring/v1', keys: [] });
  keyring.schema ??= 'ai-charter-runtime/hmac-keyring/v1';
  keyring.keys ??= [];

  if (currentKey && currentId) {
    if (keyring.keys.some((entry) => entry.key_id === currentId)) {
      fail(`${currentId} is already in the keyring — rotate once per key id`);
    }
    // Older bindings stay verifiable because the verifier resolves key_id against
    // {active} u keyring.
    keyring.keys.push({ key_id: currentId, key: currentKey, retired_at: today() });
    fs.mkdirSync(KEYS_DIR, { recursive: true });
    writeJson(KEYRING_PATH, keyring, 0o600);
    console.log(`keys: retired ${currentId} into ${path.relative(ROOT, KEYRING_PATH)}`);
  } else {
    console.log('keys: no active HMAC pair to retire; writing a fresh one');
  }

  const taken = new Set(keyring.keys.map((entry) => entry.key_id));
  if (currentId) taken.add(currentId);
  const newId = uniqueKeyId('hmac', taken);

  let next = upsertVar(lines, 'GATE_HMAC_KEY', token32());
  next = upsertVar(next, 'GATE_HMAC_KEY_ID', newId);
  writeLines(ENV_PATH, next);
  console.log(`keys: active HMAC key id is now ${newId} (value not shown)`);
}

/** ADR-007: the one asymmetric key. Public half is committed; private half never is. */
function genCardKeys(force) {
  if (fs.existsSync(CARD_PRIVATE_PATH) && !force) {
    fail(
      `${path.relative(ROOT, CARD_PRIVATE_PATH)} already exists — re-run with --force to replace it, ` +
        'or rotate by adding a new key id (retired public keys stay in signing-keys.json)',
    );
  }

  const published = readJson(SIGNING_KEYS_PATH, []);
  if (!Array.isArray(published)) fail(`${path.relative(ROOT, SIGNING_KEYS_PATH)} must be a JSON array`);
  const keyId = uniqueKeyId('card', new Set(published.map((entry) => entry.key_id)));

  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const created = today();

  fs.mkdirSync(KEYS_DIR, { recursive: true });
  fs.writeFileSync(
    CARD_PRIVATE_PATH,
    `${JSON.stringify(
      {
        key_id: keyId,
        alg: 'ed25519',
        created,
        private_key_b64: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64'),
      },
      null,
      2,
    )}\n`,
    { encoding: 'utf8', mode: 0o600 },
  );

  published.push({
    key_id: keyId,
    alg: 'ed25519',
    // SPKI DER, deliberately not a .pem: the repo's gitignore excludes *.pem and *.key,
    // and a committed public key must not depend on an ignore-rule exception.
    public_key_b64: publicKey.export({ type: 'spki', format: 'der' }).toString('base64'),
    created,
  });
  writeJson(SIGNING_KEYS_PATH, published);

  console.log(`keys: card signing key ${keyId}`);
  console.log(`  private  ${path.relative(ROOT, CARD_PRIVATE_PATH)}  (gitignored, value not shown)`);
  console.log(`  public   ${path.relative(ROOT, SIGNING_KEYS_PATH)}  (commit this)`);
}

// --- entry point -------------------------------------------------------

const args = process.argv.slice(2);
const command = args.find((arg) => !arg.startsWith('--'));
const force = args.includes('--force');

switch (command) {
  case 'generate':
    generate(force);
    break;
  case 'rotate-hmac':
    rotateHmac();
    break;
  case 'gen-card-keys':
    genCardKeys(force);
    break;
  default:
    console.error('usage: node tooling/keys.mjs generate|rotate-hmac|gen-card-keys [--force]');
    process.exit(1);
}
