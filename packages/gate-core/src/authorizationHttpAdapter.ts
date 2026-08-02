// SPDX-License-Identifier: AGPL-3.0-only
/** ADR-002's deny-by-default authenticated authorization-service boundary. */
import { timingSafeEqual } from 'node:crypto';

import { id, role, worldId, type CredentialLabel } from './schemas/index.js';
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
  readonly accessLoggedOnServe?: boolean;
}

export const AUTHORIZATION_ROUTES = [
  { id: 'health', method: 'GET', template: '/healthz', allowed: 'open', authorityChanging: false },
  { id: 'console', method: 'GET', template: '/console/*', allowed: 'open', authorityChanging: false },
  {
    id: 'proposal.submit',
    method: 'POST',
    template: '/w/{world_id}/proposals',
    allowed: ['proc:orchestrator'],
    authorityChanging: true,
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
    allowed: ['proc:orchestrator', 'role:case_officer'],
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
    allowed: ['proc:orchestrator', 'role:principal', 'role:case_officer'],
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
}

export interface AuthorizationOperationResult<T> {
  readonly status: number;
  readonly body: T;
  readonly readLengths?: Readonly<Record<string, number>>;
}

export interface AuthorizationAdapterResponse<T> {
  readonly status: number;
  readonly body: T | { readonly error: 'not-found' | 'unauthenticated' | 'forbidden' };
  readonly routeId: string | null;
}

export interface AuthorizationHttpAdapterOptions {
  readonly authorization: AuthorizationCore;
  readonly ownOrigin: string;
  readonly demoWorldId: string;
  readonly credentials: readonly CredentialBinding[];
  readonly registeredRouteIds?: readonly string[];
}

interface CompiledRoute {
  readonly definition: RouteDefinition;
  readonly pattern: RegExp;
  readonly worldCapture: number | null;
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function compileRoute(definition: RouteDefinition): CompiledRoute {
  const segments = definition.template.split('/').slice(1);
  let capture = 0;
  let worldCapture: number | null = null;
  const parts = segments.map((segment, index) => {
    if (segment === '*' && index === segments.length - 1) return '(?:.*)?';
    if (segment === '{world_id}') {
      capture += 1;
      worldCapture = capture;
      return '([^/]+)';
    }
    if (segment === '{id}') {
      capture += 1;
      return '([^/]+)';
    }
    return escapeRegex(segment);
  });
  return { definition, pattern: new RegExp(`^/${parts.join('/')}$`), worldCapture };
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
    assertAuthorizationRouteCoverage(options.registeredRouteIds ?? AUTHORIZATION_ROUTES.map((route) => route.id));
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
    const requestedWorld =
      matched.route.worldCapture === null ? null : matched.match[matched.route.worldCapture] ?? null;
    const routeLabel = `${route.method} ${route.template}`;

    if (route.allowed === 'open') {
      const result = await operation({ routeId: route.id, worldId: null, actor: null });
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

    if (binding === undefined || actor === null) return deny(401, 'unauthenticated');
    if (requestedWorld === null || !worldId.safeParse(requestedWorld).success) return deny(403, 'forbidden');
    if (binding.worldId !== requestedWorld || requestedWorld !== this.#demoWorldId) return deny(403, 'forbidden');
    if (!route.allowed.includes(binding.label)) return deny(403, 'forbidden');
    if (route.authorityChanging && request.origin !== undefined && request.origin !== this.#ownOrigin) {
      return deny(403, 'forbidden');
    }

    const result = await operation({ routeId: route.id, worldId: requestedWorld, actor });
    if (result.status === 401 || result.status === 403 || result.status === 422 || route.accessLoggedOnServe === true) {
      await this.#authorization.recordAccess({
        route: routeLabel,
        authenticatedActor: actor.credential,
        claimedActor: claim,
        outcome: result.status === 401 ? 'unauthenticated' : result.status === 403 ? 'forbidden' : 'served',
        httpStatus: result.status,
        recorder: { credential: 'proc:authz', claimed_role: null },
        readLengths: result.readLengths,
      });
    }
    return { status: result.status, body: result.body, routeId: route.id };
  }
}
