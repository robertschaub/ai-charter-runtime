// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-002's deny-by-default authenticated authorization-service boundary. */
import { timingSafeEqual } from 'node:crypto';

import { id, role, worldId, type CredentialLabel, type ModelCallAccessEvidence } from './schemas/index.js';
import { type AuthorizationCore } from './authorizationCore.js';
import type { TransactionActor } from './walStore.js';

const INBOUND_LABELS = [
  'role:principal',
  'role:case_officer',
  'role:applicant',
  'proc:orchestrator',
  'proc:services_host',
] as const satisfies readonly CredentialLabel[];

type InboundLabel = (typeof INBOUND_LABELS)[number];

export interface CredentialBinding {
  readonly label: InboundLabel;
  readonly token: string;
  readonly worldId: string;
}

interface RouteDefinition {
  readonly id: string;
  readonly method: 'GET' | 'POST';
  readonly template: string;
  readonly allowed: readonly InboundLabel[] | 'open';
  readonly authorityChanging: boolean;
  readonly originGuarded?: boolean;
  readonly accessLoggedOnServe?: boolean;
}

export const AUTHORIZATION_ROUTES = [
  { id: 'health', method: 'GET', template: '/healthz', allowed: 'open', authorityChanging: false },
  { id: 'console.script', method: 'GET', template: '/console/app.js', allowed: 'open', authorityChanging: false },
  { id: 'console.style', method: 'GET', template: '/console/styles.css', allowed: 'open', authorityChanging: false },
  {
    id: 'console.config',
    method: 'GET',
    template: '/console/runtime-config.json',
    allowed: 'open',
    authorityChanging: false,
  },
  { id: 'console.shell', method: 'GET', template: '/console/*', allowed: 'open', authorityChanging: false },
  {
    id: 'case-handoff.mint',
    method: 'POST',
    template: '/w/{world_id}/case-session-handoffs',
    allowed: ['role:case_officer'],
    authorityChanging: true,
    originGuarded: true,
    accessLoggedOnServe: true,
  },
  {
    id: 'case-handoff.redeem',
    method: 'POST',
    template: '/w/{world_id}/case-session-handoffs/{id}/redeem',
    allowed: ['proc:orchestrator'],
    authorityChanging: false,
    originGuarded: true,
    accessLoggedOnServe: true,
  },
  {
    id: 'proposal.submit',
    method: 'POST',
    template: '/w/{world_id}/proposals',
    allowed: ['proc:orchestrator'],
    authorityChanging: true,
  },
  {
    id: 'model-call.begin',
    method: 'POST',
    template: '/w/{world_id}/model-calls/begin',
    allowed: ['proc:orchestrator'],
    authorityChanging: false,
    originGuarded: true,
    accessLoggedOnServe: true,
  },
  {
    id: 'model-call.fail',
    method: 'POST',
    template: '/w/{world_id}/model-calls/failures',
    allowed: ['proc:orchestrator'],
    authorityChanging: false,
    originGuarded: true,
    accessLoggedOnServe: true,
  },
  {
    id: 'conversation.admit-output',
    method: 'POST',
    template: '/w/{world_id}/model-outputs/admit',
    allowed: ['proc:orchestrator'],
    authorityChanging: false,
    originGuarded: true,
    accessLoggedOnServe: true,
  },
  {
    id: 'ruling.read',
    method: 'GET',
    template: '/w/{world_id}/rulings/{id}',
    allowed: ['proc:orchestrator', 'proc:services_host'],
    authorityChanging: false,
  },
  {
    id: 'models.read',
    method: 'GET',
    template: '/w/{world_id}/mandates/{id}/approved-models',
    allowed: ['proc:orchestrator', 'role:principal', 'role:case_officer'],
    authorityChanging: false,
  },
  {
    id: 'commit.verify',
    method: 'POST',
    template: '/w/{world_id}/commit-verify',
    allowed: ['proc:services_host'],
    authorityChanging: true,
  },
  {
    id: 'effect.outcome',
    method: 'POST',
    template: '/w/{world_id}/effects/{id}/outcome',
    allowed: ['proc:services_host'],
    authorityChanging: true,
  },
  {
    // Reporting changes the durable access chain, so the foreign-Origin guard is intentional.
    id: 'access.report',
    method: 'POST',
    template: '/w/{world_id}/access-events',
    allowed: ['proc:services_host'],
    authorityChanging: true,
  },
  {
    id: 'mandate.grant',
    method: 'POST',
    template: '/w/{world_id}/mandates',
    allowed: ['role:principal'],
    authorityChanging: true,
  },
  {
    id: 'mandate.amend',
    method: 'POST',
    template: '/w/{world_id}/mandates/{id}/amend',
    allowed: ['role:principal'],
    authorityChanging: true,
  },
  {
    id: 'mandate.revoke',
    method: 'POST',
    template: '/w/{world_id}/mandates/{id}/revoke',
    allowed: ['role:principal'],
    authorityChanging: true,
  },
  {
    id: 'mandate.list',
    method: 'GET',
    template: '/w/{world_id}/mandates',
    allowed: ['role:principal', 'role:case_officer'],
    authorityChanging: false,
  },
  {
    id: 'escalation.list',
    method: 'GET',
    template: '/w/{world_id}/escalations',
    allowed: ['role:principal', 'role:case_officer'],
    authorityChanging: false,
  },
  {
    id: 'escalation.read',
    method: 'GET',
    template: '/w/{world_id}/escalations/{id}',
    allowed: ['proc:orchestrator', 'role:principal', 'role:case_officer', 'role:applicant'],
    authorityChanging: false,
  },
  {
    id: 'escalation.dispose',
    method: 'POST',
    template: '/w/{world_id}/escalations/{id}/disposition',
    allowed: ['role:principal', 'role:case_officer'],
    authorityChanging: true,
  },
  {
    id: 'escalation.respond',
    method: 'POST',
    template: '/w/{world_id}/escalations/{id}/response',
    allowed: ['role:principal', 'role:case_officer', 'role:applicant'],
    authorityChanging: true,
  },
  {
    id: 'escalation.revise',
    method: 'POST',
    template: '/w/{world_id}/escalations/{id}/revision',
    allowed: ['proc:orchestrator'],
    authorityChanging: true,
  },
  {
    id: 'records.verify',
    method: 'POST',
    template: '/w/{world_id}/records/verify',
    allowed: ['role:principal', 'role:case_officer'],
    authorityChanging: false,
    accessLoggedOnServe: true,
  },
  {
    id: 'records.read',
    method: 'GET',
    template: '/w/{world_id}/records/*',
    allowed: ['role:principal', 'role:case_officer'],
    authorityChanging: false,
    accessLoggedOnServe: true,
  },
  {
    id: 'extract.read',
    method: 'GET',
    template: '/w/{world_id}/extract',
    allowed: ['role:applicant'],
    authorityChanging: false,
    accessLoggedOnServe: true,
  },
  {
    id: 'challenge.submit',
    method: 'POST',
    template: '/w/{world_id}/challenges',
    allowed: ['role:applicant'],
    authorityChanging: true,
  },
] as const satisfies readonly RouteDefinition[];

export interface AuthorizationAdapterRequest {
  readonly method: string;
  readonly pathname: string;
  readonly authorization?: string;
  readonly origin?: string;
  readonly claimedRole?: string;
  readonly sessionId?: string;
}

export interface AuthorizationAdapterContext {
  readonly routeId: string;
  readonly worldId: string | null;
  readonly actor: TransactionActor | null;
  /** Named route parameters, schema-validated by the adapter; wildcard tails are excluded. */
  readonly params: Readonly<Record<string, string>>;
}

export interface AuthorizationOperationResult<T> {
  readonly status: number;
  readonly body: T;
  readonly readLengths?: Readonly<Record<string, number>>;
  readonly accessEvidence?: ModelCallAccessEvidence;
}

export interface AuthorizationAdapterResponse<T> {
  readonly status: number;
  readonly body: T | { readonly error: 'not-found' | 'unauthenticated' | 'forbidden' | 'rate-limited' };
  readonly routeId: string | null;
}

export interface AuthorizationHttpAdapterOptions {
  readonly authorization: AuthorizationCore;
  readonly ownOrigin: string;
  readonly demoWorldId: string;
  readonly credentials: readonly CredentialBinding[];
  readonly registeredRouteIds?: readonly string[];
  readonly unauthenticatedDetailLimit?: number;
  readonly unauthenticatedWindowMs?: number;
  readonly nowMilliseconds?: () => number;
}

interface CompiledRoute {
  readonly definition: RouteDefinition;
  readonly pattern: RegExp;
  readonly captures: readonly { readonly name: 'world_id' | 'id'; readonly index: number }[];
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function compileRoute(definition: RouteDefinition): CompiledRoute {
  const segments = definition.template.split('/').slice(1);
  const wildcard = segments.at(-1) === '*';
  const matchedSegments = wildcard ? segments.slice(0, -1) : segments;
  let capture = 0;
  const captures: { name: 'world_id' | 'id'; index: number }[] = [];
  const parts = matchedSegments.map((segment) => {
    if (segment === '{world_id}') {
      capture += 1;
      captures.push({ name: 'world_id', index: capture });
      return '([^/]+)';
    }
    if (segment === '{id}') {
      capture += 1;
      captures.push({ name: 'id', index: capture });
      return '([^/]+)';
    }
    return escapeRegex(segment);
  });
  const wildcardSuffix = wildcard ? '(?:/.*)?' : '';
  return { definition, pattern: new RegExp(`^/${parts.join('/')}${wildcardSuffix}$`), captures };
}

function bearerToken(value: string | undefined): string | null {
  if (value === undefined) return null;
  const match = /^Bearer ([0-9a-fA-F]{64,})$/.exec(value);
  return match?.[1] ?? null;
}

function equalToken(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  return leftBytes.length === rightBytes.length && timingSafeEqual(leftBytes, rightBytes);
}

function claimFor(request: AuthorizationAdapterRequest, label: InboundLabel): TransactionActor {
  if (label.startsWith('role:')) {
    return { credential: label, claimed_role: role.parse(label.slice('role:'.length)) };
  }
  const claimed = role.safeParse(request.claimedRole);
  return { credential: label, claimed_role: claimed.success ? claimed.data : null };
}

function claimedActor(request: AuthorizationAdapterRequest, actor: TransactionActor | null) {
  if (actor === null) return null;
  const session = id.safeParse(request.sessionId);
  return {
    role: actor.claimed_role,
    ...(session.success ? { session: session.data } : {}),
  };
}

export function assertAuthorizationRouteCoverage(registeredRouteIds: readonly string[]): void {
  const expected = new Set(AUTHORIZATION_ROUTES.map((route) => route.id));
  const registered = new Set(registeredRouteIds);
  if (registered.size !== registeredRouteIds.length) throw new Error('registered authorization routes must be unique');
  const missing = [...registered].filter((routeId) => !expected.has(routeId as (typeof AUTHORIZATION_ROUTES)[number]['id']));
  const unregistered = [...expected].filter((routeId) => !registered.has(routeId));
  if (missing.length > 0 || unregistered.length > 0) {
    throw new Error(`authorization route ACL mismatch: unknown=[${missing.join(',')}], unregistered=[${unregistered.join(',')}]`);
  }
}

export class AuthorizationHttpAdapter {
  readonly #authorization: AuthorizationCore;
  readonly #ownOrigin: string;
  readonly #demoWorldId: string;
  readonly #credentials: readonly CredentialBinding[];
  readonly #routes = AUTHORIZATION_ROUTES.map(compileRoute);
  readonly #unauthenticatedDetailLimit: number;
  readonly #unauthenticatedWindowMs: number;
  readonly #nowMilliseconds: () => number;
  #unauthenticatedWindowStart: number;
  #unauthenticatedDetailedCount = 0;
  #unauthenticatedSuppressionRecorded = false;
  #unauthenticatedSuppressedCount = 0;

  constructor(options: AuthorizationHttpAdapterOptions) {
    this.#authorization = options.authorization;
    this.#ownOrigin = new URL(options.ownOrigin).origin;
    this.#demoWorldId = worldId.parse(options.demoWorldId);
    const byLabel = new Map(options.credentials.map((binding) => [binding.label, binding]));
    for (const label of INBOUND_LABELS) {
      const binding = byLabel.get(label);
      if (binding === undefined) throw new Error(`missing authorization credential binding for ${label}`);
      if (!/^[0-9a-fA-F]{64,}$/.test(binding.token)) throw new Error(`authorization credential for ${label} is not valid hex`);
      worldId.parse(binding.worldId);
    }
    if (byLabel.size !== INBOUND_LABELS.length || options.credentials.length !== INBOUND_LABELS.length) {
      throw new Error('authorization credential labels must be present exactly once');
    }
    const tokens = options.credentials.map((binding) => binding.token.toLowerCase());
    if (new Set(tokens).size !== tokens.length) throw new Error('authorization credentials must be mutually distinct');
    this.#credentials = [...options.credentials];
    this.#unauthenticatedDetailLimit = options.unauthenticatedDetailLimit ?? 8;
    this.#unauthenticatedWindowMs = options.unauthenticatedWindowMs ?? 1_000;
    this.#nowMilliseconds = options.nowMilliseconds ?? Date.now;
    if (!Number.isSafeInteger(this.#unauthenticatedDetailLimit) || this.#unauthenticatedDetailLimit < 1) {
      throw new RangeError('unauthenticatedDetailLimit must be a positive safe integer');
    }
    if (!Number.isSafeInteger(this.#unauthenticatedWindowMs) || this.#unauthenticatedWindowMs < 1) {
      throw new RangeError('unauthenticatedWindowMs must be a positive safe integer');
    }
    this.#unauthenticatedWindowStart = this.#nowMilliseconds();
    if (!Number.isSafeInteger(this.#unauthenticatedWindowStart)) {
      throw new RangeError('nowMilliseconds must return a safe integer');
    }
    assertAuthorizationRouteCoverage(options.registeredRouteIds ?? AUTHORIZATION_ROUTES.map((route) => route.id));
  }

  async #rollUnauthenticatedWindow(now: number): Promise<void> {
    if (
      now >= this.#unauthenticatedWindowStart &&
      now - this.#unauthenticatedWindowStart < this.#unauthenticatedWindowMs
    ) {
      return;
    }
    const suppressedCount = this.#unauthenticatedSuppressedCount;
    this.#unauthenticatedWindowStart = now;
    this.#unauthenticatedDetailedCount = 0;
    this.#unauthenticatedSuppressionRecorded = false;
    this.#unauthenticatedSuppressedCount = 0;
    if (suppressedCount === 0) return;
    await this.#authorization.recordAccess({
      route: 'AUTHZ unauthenticated ingress',
      authenticatedActor: null,
      claimedActor: null,
      outcome: 'rate-limited',
      httpStatus: 429,
      recorder: { credential: 'proc:authz', claimed_role: null },
      suppressedCount,
      suppressionWindowMs: this.#unauthenticatedWindowMs,
      suppressionFinal: true,
    });
  }

  async dispatch<T>(
    request: AuthorizationAdapterRequest,
    operation: (context: AuthorizationAdapterContext) => Promise<AuthorizationOperationResult<T>>,
  ): Promise<AuthorizationAdapterResponse<T>> {
    const method = request.method.toUpperCase();
    const matched = this.#routes
      .map((route) => ({ route, match: route.pattern.exec(request.pathname) }))
      .find((candidate) => candidate.route.definition.method === method && candidate.match !== null);
    if (matched === undefined || matched.match === null) {
      return { status: 404, body: { error: 'not-found' }, routeId: null };
    }
    const route = matched.route.definition;
    const params: Record<string, string> = {};
    for (const capture of matched.route.captures) {
      const value = matched.match[capture.index];
      const schema = capture.name === 'world_id' ? worldId : id;
      const parsed = schema.safeParse(value);
      if (!parsed.success) return { status: 404, body: { error: 'not-found' }, routeId: route.id };
      params[capture.name] = parsed.data;
    }
    const validatedParams = Object.freeze(params);
    const requestedWorld = validatedParams['world_id'] ?? null;
    const routeLabel = `${route.method} ${route.template}`;
    const now = this.#nowMilliseconds();
    if (!Number.isSafeInteger(now)) throw new RangeError('nowMilliseconds must return a safe integer');
    await this.#rollUnauthenticatedWindow(now);

    if (route.allowed === 'open') {
      const result = await operation({ routeId: route.id, worldId: null, actor: null, params: validatedParams });
      return { status: result.status, body: result.body, routeId: route.id };
    }

    const token = bearerToken(request.authorization);
    const binding =
      token === null ? undefined : this.#credentials.find((candidate) => equalToken(token, candidate.token));
    const actor = binding === undefined ? null : claimFor(request, binding.label);
    const claim = claimedActor(request, actor);
    const deny = async (
      status: 401 | 403,
      error: 'unauthenticated' | 'forbidden',
    ): Promise<AuthorizationAdapterResponse<T>> => {
      await this.#authorization.recordAccess({
        route: routeLabel,
        authenticatedActor: actor?.credential ?? null,
        claimedActor: claim,
        outcome: status === 401 ? 'unauthenticated' : 'forbidden',
        httpStatus: status,
        recorder: { credential: 'proc:authz', claimed_role: null },
      });
      return { status, body: { error }, routeId: route.id };
    };

    if (binding === undefined || actor === null) {
      if (this.#unauthenticatedDetailedCount < this.#unauthenticatedDetailLimit) {
        this.#unauthenticatedDetailedCount += 1;
        return deny(401, 'unauthenticated');
      }
      this.#unauthenticatedSuppressedCount += 1;
      if (!this.#unauthenticatedSuppressionRecorded) {
        this.#unauthenticatedSuppressionRecorded = true;
        await this.#authorization.recordAccess({
          route: 'AUTHZ unauthenticated ingress',
          authenticatedActor: null,
          claimedActor: null,
          outcome: 'rate-limited',
          httpStatus: 429,
          recorder: { credential: 'proc:authz', claimed_role: null },
          suppressedCount: 1,
          suppressionWindowMs: this.#unauthenticatedWindowMs,
          suppressionFinal: false,
        });
      }
      return { status: 429, body: { error: 'rate-limited' }, routeId: route.id };
    }
    if (requestedWorld === null || !worldId.safeParse(requestedWorld).success) return deny(403, 'forbidden');
    if (binding.worldId !== requestedWorld || requestedWorld !== this.#demoWorldId) return deny(403, 'forbidden');
    if (!route.allowed.includes(binding.label)) return deny(403, 'forbidden');
    if ((route.authorityChanging || route.originGuarded === true) && request.origin !== undefined && request.origin !== this.#ownOrigin) {
      return deny(403, 'forbidden');
    }

    const result = await operation({ routeId: route.id, worldId: requestedWorld, actor, params: validatedParams });
    if (result.status === 401 || result.status === 403 || result.status === 422 || route.accessLoggedOnServe === true) {
      await this.#authorization.recordAccess({
        route: routeLabel,
        authenticatedActor: actor.credential,
        claimedActor: claim,
        outcome: result.status === 401 ? 'unauthenticated' : result.status === 403 ? 'forbidden' : 'served',
        httpStatus: result.status,
        recorder: { credential: 'proc:authz', claimed_role: null },
        readLengths: result.readLengths,
        operationEvidence: result.accessEvidence,
      });
    }
    return { status: result.status, body: result.body, routeId: route.id };
  }
}
