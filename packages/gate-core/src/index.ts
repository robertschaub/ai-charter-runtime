// SPDX-License-Identifier: AGPL-3.0-only
/**
 * gate-core — the governance core of the Our AI Charter runtime-gates POC.
 *
 * M1 lands the deterministic layer the rest of the system is built on: ADR-007's
 * canonicalization and digest conventions, ADR-001/ADR-003's append-only hash chains,
 * ADR-007's HMAC keyring, ADR-006 §3's served-model comparison, and the data-contract
 * schemas.
 *
 * This is a maintainer sketch, not a certification artifact.
 */
export * from './canonicalize.js';
export * from './domain.js';
export * from './hash.js';
export * from './chain.js';
export * from './keyring.js';
export * from './servedModel.js';
export * from './schemas/index.js';
