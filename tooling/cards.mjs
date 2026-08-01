// SPDX-License-Identifier: MIT
// Sign, verify, and digest ADR-006 model cards. Private key material is never printed.
import {
  createPrivateKey,
  createPublicKey,
  sign as ed25519Sign,
  verify as ed25519Verify,
} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

import { digestFor, modelCard, signingKeys, taggedBytes } from 'gate-core';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const CARDS_DIR = path.join(ROOT, 'docs', 'cards');
const PRIVATE_PATH = path.join(ROOT, 'keys', 'model-card-signing.ed25519.json');
const PUBLIC_PATH = path.join(CARDS_DIR, 'signing-keys.json');

function fail(message) {
  console.error(`cards: ${message}`);
  process.exit(1);
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    fail(`${path.relative(ROOT, file)} is absent or invalid JSON`);
  }
}

function unsignedCard(raw) {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) fail('card must be a JSON object');
  const { signature: ignored, ...unsigned } = raw;
  void ignored;
  return unsigned;
}

function cardFiles(requested) {
  if (requested.length > 0 && requested[0] !== 'all') {
    return requested.map((value) => path.resolve(ROOT, value));
  }
  return fs
    .readdirSync(CARDS_DIR)
    .filter((name) => name.endsWith('.json') && name !== 'signing-keys.json' && !name.endsWith('.revocation.json'))
    .sort()
    .map((name) => path.join(CARDS_DIR, name));
}

function publicKeys() {
  return signingKeys.parse(readJson(PUBLIC_PATH));
}

function signCard(file) {
  const privateRecord = readJson(PRIVATE_PATH);
  if (
    typeof privateRecord?.key_id !== 'string' ||
    privateRecord.alg !== 'ed25519' ||
    typeof privateRecord.private_key_b64 !== 'string'
  ) {
    fail('private model-card key record is malformed');
  }
  const published = publicKeys();
  const trust = published.find((entry) => entry.key_id === privateRecord.key_id);
  if (trust === undefined || trust.revoked_at !== undefined) fail('private key has no active public trust-root entry');
  const unsigned = unsignedCard(readJson(file));
  const privateKey = createPrivateKey({
    key: Buffer.from(privateRecord.private_key_b64, 'base64'),
    format: 'der',
    type: 'pkcs8',
  });
  const signature = ed25519Sign(null, taggedBytes('model-card', unsigned), privateKey).toString('base64');
  const signed = modelCard.parse({
    ...unsigned,
    signature: { alg: 'ed25519', key_id: privateRecord.key_id, signature },
  });
  fs.writeFileSync(file, `${JSON.stringify(signed, null, 2)}\n`, { encoding: 'utf8' });
  console.log(`cards: signed ${path.relative(ROOT, file)} with ${privateRecord.key_id}`);
}

function verifyCard(file) {
  const card = modelCard.parse(readJson(file));
  const published = publicKeys();
  const trust = published.find((entry) => entry.key_id === card.signature.key_id);
  if (trust === undefined) fail(`${path.relative(ROOT, file)} names an unknown signing key`);
  if (trust.revoked_at !== undefined) fail(`${path.relative(ROOT, file)} uses revoked key ${trust.key_id}`);
  const publicKey = createPublicKey({
    key: Buffer.from(trust.public_key_b64, 'base64'),
    format: 'der',
    type: 'spki',
  });
  const unsigned = unsignedCard(card);
  const valid = ed25519Verify(
    null,
    taggedBytes('model-card', unsigned),
    publicKey,
    Buffer.from(card.signature.signature, 'base64'),
  );
  if (!valid) fail(`${path.relative(ROOT, file)} has an invalid signature`);
  console.log(`cards: verified ${card.card_id}@${card.card_version} ${digestFor('model-card', unsigned)}`);
  return { card, digest: digestFor('model-card', unsigned), keyId: trust.key_id };
}

const [command, ...requested] = process.argv.slice(2);
const files = cardFiles(requested);
if (files.length === 0) fail('no model cards selected');

if (command === 'sign') {
  for (const file of files) signCard(file);
  for (const file of files) verifyCard(file);
} else if (command === 'verify' || command === 'digest') {
  for (const file of files) verifyCard(file);
} else {
  fail('usage: node tooling/cards.mjs sign|verify|digest [all|card paths...]');
}
