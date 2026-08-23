// SPDX-License-Identifier: AGPL-3.0-only
/** Native HTTP host for the ADR-002 authorization-service boundary. */
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';

import { z, ZodError } from 'zod';

import {
  AuthorizationCore,
  AuthorizationError,
  bindMandate,
  type ContinueEscalationRevisionResult,
  type DisposeEscalationResult,
  type EffectOutcomeReportResult,
  type RespondDialogueResult,
  type RuleProposalResult,
  type SubmitChallengeResult,
} from './authorizationCore.js';
import {
  AUTHORIZATION_ROUTES,
  AuthorizationHttpAdapter,
  type AuthorizationAdapterContext,
  type AuthorizationOperationResult,
} from './authorizationHttpAdapter.js';
import { proposalRulingProjection } from './authorizationProjection.js';
import { AuthorizationReadSide, AuthorizationReadSideError } from './authorizationReadSide.js';
import {
  ConversationProjectionService,
  ConversationProjectionServiceError,
} from './conversationProjectionService.js';
import {
  CASE_OFFICER_MESSAGE_PROFILE_DIGEST,
  ConversationTransportError,
  type ConversationTransportService,
} from './conversationTransport.js';
import {
  CaseSessionHandoffError,
  type CaseSessionHandoffService,
} from './caseSessionHandoff.js';
import type { Keyring } from './keyring.js';
import { SystemUseDecisionError, type SystemUseDecisionService } from './systemUseDecision.js';
import { ProposalIntakeError, type ProposalIntakeService } from './proposalIntake.js';
import { ProposalPrecommitError, type ProposalPrecommitService } from './proposalPrecommit.js';
import { ExecutionPreparationError, type ExecutionPreparationService } from './executionPreparation.js';
import { ScreeningCallError, type ScreeningCallService } from './screeningCall.js';
import {
  classToken,
  browserOrigin,
  disposition,
  effectIntent,
  frozenProposal,
  gate,
  generalDisposition,
  hexDigest,
  id,
  integer,
  nativeCommitVerifyRequest,
  modelCallAdmissionRequest,
  modelCallBeginRequest,
  modelCallFailureRequest,
  screeningCallFailureRequest,
  screeningCallOutputRequest,
  conversationMessageIngressRequest,
  outputReleaseConsumeRequest,
  modelSelectionCheckRequest,
  modelSelectionRequest,
  timestamp,
  worldId,
  type Mandate,
} from './schemas/index.js';

const jsonObject = z.record(z.string(), z.unknown());
const strictEmptyRequest = z.object({}).strict();
const proposalIntakeConsumeRequest = z.object({ content: z.string() }).strict();
const proposalRequest = z
  .object({
    gate,
    proposal: frozenProposal,
    service: id,
    action_class: classToken,
    context: jsonObject.optional(),
  })
  .strict();
const commitVerifyRequest = z
  .object({
    ruling_id: id,
    intent: effectIntent,
    services_host_boot_id: id,
    services_ledger_id: id,
  })
  .strict();
const effectOutcomeRequest = z
  .object({
    world_id: z.string(),
    commitment_id: id,
    effect_id: id,
    idempotency_key: hexDigest,
    effect_request_digest: hexDigest,
    services_host_boot_id: id,
    services_ledger_id: id,
    outcome: z.enum(['success', 'failed']),
    recorded_at: timestamp,
    detail: z.string().optional(),
    delivery: z.enum(['executed', 'retry', 'reconciliation-probe']),
  })
  .strict();
const revokeRequest = z.object({ version: integer.min(1) }).strict();
const dispositionRequest = z.object({ disposition: generalDisposition }).strict();
const dialogueResponseRequest = z
  .object({
    escalation_id: id,
    disposition,
    answer_text: z.string().min(1).max(32_768).optional(),
    evidence_ref: z
      .object({ kind: z.literal('registry_record'), id: z.string().min(1).max(256), retrieved_at: timestamp })
      .strict()
      .optional(),
    scope: z
      .object({ item_ref: id, applies_to: z.literal('this_case_only') })
      .strict()
      .optional(),
  })
  .strict();
const revisionRequest = z
  .object({ proposal: frozenProposal, context: jsonObject.optional() })
  .strict();
const caseHandoffMintRequest = z.object({ case_id: id }).strict();
const challengeRequest = z
  .object({
    action_id: id,
    contested_entry_id: id,
    correction_text: z.string().trim().min(1).max(32_768),
  })
  .strict();
const caseHandoffRedeemRequest = z
  .object({
    handoff_id: id,
    handoff_code: z.string().regex(/^[0-9a-f]{64,}$/),
    role: z.literal('case_officer'),
    world_id: worldId,
    case_id: id,
    target_origin: browserOrigin,
    authorization_boot_id: id,
    session_id: id,
  })
  .strict();
const runtimeConsoleConfig = z
  .object({
    authorization_origin: browserOrigin,
    orchestrator_origin: browserOrigin,
  })
  .strict();
const servicesAccessRoute = z.enum(['services.execute', 'services.native-execute', 'services.effect-probe', 'services.registry-read']);
const servicesAccessReportRequest = z.discriminatedUnion('outcome', [
  z
    .object({
      route: servicesAccessRoute,
      authenticated_actor: z.null(),
      outcome: z.literal('unauthenticated'),
      http_status: z.literal(401),
    })
    .strict(),
  z
    .object({
      route: servicesAccessRoute,
      authenticated_actor: z.enum(['proc:orchestrator', 'proc:authz']),
      outcome: z.literal('forbidden'),
      http_status: z.literal(403),
    })
    .strict(),
  z
    .object({
      route: z.literal('services.unauthenticated-ingress'),
      authenticated_actor: z.null(),
      outcome: z.literal('rate-limited'),
      http_status: z.literal(429),
      suppressed_count: integer.min(1),
      suppression_window_ms: integer.min(1),
      suppression_final: z.boolean(),
    })
    .strict(),
]);

const ACCESS_ROUTE_LABELS = {
  'services.execute': 'POST /w/{world_id}/services/{service}/execute',
  'services.native-execute': 'POST /w/{world_id}/execution-preparations/{execution_preparation_id}/execute',
  'services.effect-probe': 'GET /w/{world_id}/effects/{idempotency_key}',
  'services.registry-read': 'GET /w/{world_id}/registry-records/{record_id}',
  'services.unauthenticated-ingress': 'SERVICES unauthenticated ingress',
} as const;

class HttpInputError extends Error {
  constructor(readonly status: 400 | 413 | 415, readonly responseCode: string) {
    super(responseCode);
  }
}

async function readJson(request: IncomingMessage, maxBytes: number): Promise<unknown> {
  const contentType = request.headers['content-type'];
  if (contentType === undefined || !contentType.toLowerCase().startsWith('application/json')) {
    throw new HttpInputError(415, 'json-required');
  }
  const declared = request.headers['content-length'];
  if (declared !== undefined) {
    const bytes = Number(declared);
    if (!Number.isSafeInteger(bytes) || bytes < 0) throw new HttpInputError(400, 'invalid-content-length');
    if (bytes > maxBytes) throw new HttpInputError(413, 'body-too-large');
  }
  const chunks: Buffer[] = [];
  let length = 0;
  for await (const chunk of request) {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    length += bytes.length;
    if (length > maxBytes) throw new HttpInputError(413, 'body-too-large');
    chunks.push(bytes);
  }
  if (length === 0) throw new HttpInputError(400, 'empty-json-body');
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw new HttpInputError(400, 'malformed-json');
  }
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const bytes = Buffer.from(JSON.stringify(body), 'utf8');
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': bytes.length,
    'cache-control': 'no-store',
    'content-security-policy': "frame-ancestors 'none'",
  });
  response.end(bytes);
}

const CONSOLE_CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self'",
  "base-uri 'none'",
  "form-action 'self'",
  "frame-ancestors 'none'",
  "object-src 'none'",
].join('; ');

export interface GovernanceConsoleAssetPaths {
  readonly shell: string;
  readonly script: string;
  readonly stylesheet: string;
}

export interface GovernanceConsoleAssets {
  readonly shell: string;
  readonly script: string;
  readonly stylesheet: string;
}

/** Load every console byte before the listener binds, so a partial UI cannot start. */
export function loadGovernanceConsoleAssets(paths: GovernanceConsoleAssetPaths): GovernanceConsoleAssets {
  return {
    shell: readFileSync(paths.shell, 'utf8'),
    script: readFileSync(paths.script, 'utf8').replace(/\r?\n\/\/# sourceMappingURL=.*\r?\n?$/u, '\n'),
    stylesheet: readFileSync(paths.stylesheet, 'utf8'),
  };
}

function sendConsoleAsset(
  response: ServerResponse,
  status: number,
  body: string,
  contentType: string,
): void {
  const bytes = Buffer.from(body, 'utf8');
  response.writeHead(status, {
    'content-type': `${contentType}; charset=utf-8`,
    'content-length': bytes.length,
    'cache-control': 'no-store',
    'content-security-policy': CONSOLE_CSP,
    'cross-origin-resource-policy': 'same-origin',
    'permissions-policy': 'camera=(), microphone=(), geolocation=()',
    'referrer-policy': 'no-referrer',
    'x-content-type-options': 'nosniff',
  });
  response.end(bytes);
}

type Handler = (
  request: IncomingMessage,
  context: AuthorizationAdapterContext,
) => Promise<AuthorizationOperationResult<unknown>>;

export interface AuthorizationHttpServerOptions {
  readonly authorization: AuthorizationCore;
  readonly conversationProjections: ConversationProjectionService;
  readonly conversationTransport: ConversationTransportService;
  readonly proposalIntakes?: ProposalIntakeService;
  readonly proposalPrecommit?: ProposalPrecommitService;
  readonly executionPreparations?: ExecutionPreparationService;
  readonly screeningCalls?: ScreeningCallService;
  readonly reads: AuthorizationReadSide;
  readonly adapter: AuthorizationHttpAdapter;
  readonly keyring: Keyring;
  readonly caseHandoffs: CaseSessionHandoffService;
  readonly systemUse: SystemUseDecisionService;
  readonly runtimeConfig: {
    readonly authorization_origin: string;
    readonly orchestrator_origin: string;
  };
  readonly consoleAssets: GovernanceConsoleAssets;
  /** Authorization-owned case binding for the bounded POC domain. */
  readonly caseId: string;
  readonly host: string;
  readonly port: number;
  readonly maxBodyBytes?: number;
}

export interface ListeningAddress {
  readonly host: string;
  readonly port: number;
  readonly origin: string;
}

/**
 * The handler table is closed over route ids. The caller cannot pair a permitted path
 * with an arbitrary core operation: route matching and operation selection happen in
 * one authorization-owned callback.
 */
export class AuthorizationHttpServer {
  readonly #server: Server;
  readonly #host: string;
  readonly #port: number;
  readonly #handlers: Readonly<Record<string, Handler>>;

  constructor(options: AuthorizationHttpServerOptions) {
    const maxBodyBytes = options.maxBodyBytes ?? 1024 * 1024;
    if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1) {
      throw new RangeError('maxBodyBytes must be a positive safe integer');
    }
    if (!Number.isSafeInteger(options.port) || options.port < 0 || options.port > 65_535) {
      throw new RangeError('port must be an integer from 0 through 65535');
    }
    this.#host = options.host;
    this.#port = options.port;
    const configuredCaseId = id.parse(options.caseId);
    const configuredRuntimeOrigins = runtimeConsoleConfig.parse(options.runtimeConfig);

    const body = (request: IncomingMessage) => readJson(request, maxBodyBytes);
    const requireActor = (context: AuthorizationAdapterContext) => {
      if (context.actor === null) throw new AuthorizationError('unauthorized-actor', 'authenticated actor required');
      return context.actor;
    };
    const handlers: Record<string, Handler> = {
      health: async () => ({ status: 200, body: { status: 'ready', service: 'authorization' } }),
      'console.config': async () => ({ status: 200, body: configuredRuntimeOrigins }),
      'console.shell': async () => ({ status: 200, body: options.consoleAssets.shell }),
      'console.script': async () => ({ status: 200, body: options.consoleAssets.script }),
      'console.style': async () => ({ status: 200, body: options.consoleAssets.stylesheet }),
      'case-handoff.mint': async (request, context) => {
        const parsed = caseHandoffMintRequest.parse(await body(request));
        const minted = await options.caseHandoffs.mint(parsed.case_id, requireActor(context));
        return { status: 201, body: minted };
      },
      'case-handoff.redeem': async (request, context) => {
        const parsed = caseHandoffRedeemRequest.parse(await body(request));
        if (
          parsed.handoff_id !== context.params['id'] ||
          parsed.world_id !== context.worldId
        ) {
          return { status: 403, body: { error: 'handoff-refused' } };
        }
        const claim = await options.caseHandoffs.redeem(parsed, requireActor(context));
        return { status: 200, body: claim };
      },
      'case-session.close': async (request, context) => {
        const sessionId = context.params['id'];
        if (sessionId === undefined || context.sessionId !== sessionId) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        strictEmptyRequest.parse(await body(request));
        const result = await options.caseHandoffs.closeSession(sessionId, requireActor(context));
        return { status: 200, body: result };
      },
      'proposal.submit': async (request, context) => {
        const parsed = proposalRequest.parse(await body(request));
        const result: RuleProposalResult = await options.authorization.ruleProposal({
          gate: parsed.gate,
          proposal: parsed.proposal,
          caseId: configuredCaseId,
          service: parsed.service,
          actionClass: parsed.action_class,
          actor: requireActor(context),
          ...(parsed.context === undefined ? {} : { context: parsed.context }),
        });
        return {
          status: 200,
          body: proposalRulingProjection.parse({
            ruling: {
              ruling_id: result.ruling.ruling_id,
              verdict: result.ruling.verdict,
              ux_class: result.ruling.ux_class,
              reason: result.ruling.reason,
              status: result.ruling.status,
              successor_ruling_id: result.ruling.successor_ruling_id ?? null,
              validity_window: result.ruling.binding.validity_window,
            },
            escalation_id: result.escalationId,
          }),
        };
      },
      'proposal-intake.consume': async (request, context) => {
        if (options.proposalIntakes === undefined) return { status: 503, body: { error: 'proposal-intake-unavailable' } };
        const intakeId = context.params['id'];
        if (intakeId === undefined) return { status: 404, body: { error: 'not-found' } };
        const parsed = proposalIntakeConsumeRequest.parse(await body(request));
        const result = await options.proposalIntakes.consume(intakeId, parsed.content, requireActor(context));
        return { status: 200, body: result, accessEvidence: result };
      },
      'proposal-intake.read': async (_request, context) => {
        if (options.proposalIntakes === undefined) return { status: 503, body: { error: 'proposal-intake-unavailable' } };
        const intakeId = context.params['id'];
        if (intakeId === undefined) return { status: 404, body: { error: 'not-found' } };
        const result = options.proposalIntakes.status(intakeId, requireActor(context));
        return { status: 200, body: result, accessEvidence: result };
      },
      'proposal-revision.prepare': async (request, context) => {
        if (options.proposalIntakes === undefined) return { status: 503, body: { error: 'proposal-intake-unavailable' } };
        const runId = context.params['id'];
        const caseId = context.params['case_id'];
        if (runId === undefined || caseId === undefined || context.sessionId === null) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        strictEmptyRequest.parse(await body(request));
        const result = await options.proposalIntakes.prepareRevision(
          caseId,
          runId,
          context.sessionId,
          requireActor(context),
        );
        return { status: 201, body: result, accessEvidence: result };
      },
      'execution-preparation.issue': async (request, context) => {
        if (options.executionPreparations === undefined) return { status: 503, body: { error: 'execution-preparation-unavailable' } };
        const runId = context.params['id'];
        const caseId = context.params['case_id'];
        if (runId === undefined || caseId === undefined || context.sessionId === null) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        strictEmptyRequest.parse(await body(request));
        const result = await options.executionPreparations.issue(caseId, runId, context.sessionId, requireActor(context));
        return { status: 201, body: result, accessEvidence: result };
      },
      'proposal-run.read': async (_request, context) => {
        if (options.proposalIntakes === undefined || options.proposalPrecommit === undefined) {
          return { status: 503, body: { error: 'proposal-intake-unavailable' } };
        }
        const runId = context.params['id'];
        const caseId = context.params['case_id'];
        if (runId === undefined || caseId === undefined) return { status: 404, body: { error: 'not-found' } };
        const actor = requireActor(context);
        const precommit = options.proposalPrecommit.statusByRun(caseId, runId, actor);
        if (precommit !== null) return { status: 200, body: precommit, readLengths: { gates: precommit.gates.length } };
        const result = options.proposalIntakes.runStatus(caseId, runId, actor);
        return { status: 200, body: result, accessEvidence: result };
      },
      'proposal-precommit.run': async (request, context) => {
        if (options.proposalPrecommit === undefined) return { status: 503, body: { error: 'proposal-precommit-unavailable' } };
        const proposalId = context.params['id'];
        if (proposalId === undefined) return { status: 404, body: { error: 'not-found' } };
        strictEmptyRequest.parse(await body(request));
        const result = await options.proposalPrecommit.run(proposalId, requireActor(context));
        return { status: 200, body: result, readLengths: { gates: result.gates.length } };
      },
      'proposal-precommit.read': async (_request, context) => {
        if (options.proposalPrecommit === undefined) return { status: 503, body: { error: 'proposal-precommit-unavailable' } };
        const proposalId = context.params['id'];
        if (proposalId === undefined) return { status: 404, body: { error: 'not-found' } };
        const result = options.proposalPrecommit.status(proposalId, requireActor(context));
        return { status: 200, body: result, readLengths: { gates: result.gates.length } };
      },
      'screening-call.output': async (request, context) => {
        if (options.screeningCalls === undefined) return { status: 503, body: { error: 'screening-unavailable' } };
        const callId = context.params['id'];
        if (callId === undefined) return { status: 404, body: { error: 'not-found' } };
        const parsed = screeningCallOutputRequest.parse(await body(request));
        const result = await options.screeningCalls.admit(callId, parsed, requireActor(context));
        return { status: 200, body: result, accessEvidence: result };
      },
      'screening-call.failure': async (request, context) => {
        if (options.screeningCalls === undefined) return { status: 503, body: { error: 'screening-unavailable' } };
        const callId = context.params['id'];
        if (callId === undefined) return { status: 404, body: { error: 'not-found' } };
        const parsed = screeningCallFailureRequest.parse(await body(request));
        const result = await options.screeningCalls.fail(callId, parsed, requireActor(context));
        return { status: 200, body: result, accessEvidence: result };
      },
      'model-selection.read': async (_request, context) => {
        if (context.params['case_id'] !== configuredCaseId) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        const projection = options.conversationProjections.currentSelection(requireActor(context));
        return {
          status: 200,
          body: projection,
          accessEvidence: {
            kind: 'model_selection_read',
            case_id: configuredCaseId,
            current_selection_id: projection.selection?.selection_id ?? null,
            latest_observation_id: projection.latest_observation?.observation_id ?? null,
          },
        };
      },
      'model-selection.check': async (request, context) => {
        if (context.params['case_id'] !== configuredCaseId) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        const parsed = modelSelectionCheckRequest.parse(await body(request));
        const projection = await options.conversationProjections.checkSelection({
          ...parsed,
          actor: requireActor(context),
        });
        return { status: 200, body: projection, accessEvidence: projection.check };
      },
      'model-selection.apply': async (request, context) => {
        if (context.params['case_id'] !== configuredCaseId) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        const parsed = modelSelectionRequest.parse(await body(request));
        const projection = await options.conversationProjections.selectModel({
          ...parsed,
          actor: requireActor(context),
        });
        return { status: 200, body: projection, accessEvidence: projection };
      },
      'model-call.begin': async (request, context) => {
        const parsed = modelCallBeginRequest.parse(await body(request));
        const started = await options.conversationProjections.beginCall({
          ...parsed,
          actor: requireActor(context),
          ...(context.sessionId === null ? {} : { sessionId: context.sessionId }),
        });
        return {
          status: 200,
          body: started,
          readLengths: { conversation_items: started.projection.items.length },
          accessEvidence: started.call,
        };
      },
      'conversation.admit-output': async (request, context) => {
        const parsed = modelCallAdmissionRequest.parse(await body(request));
        const admission = await options.conversationProjections.completeCall({
          ...parsed,
          actor: requireActor(context),
          ...(context.sessionId === null ? {} : { sessionId: context.sessionId }),
        });
        return {
          status: 200,
          body: admission,
          readLengths: { conversation_items: admission.decision.projection_item_count },
          accessEvidence: admission,
        };
      },
      'conversation.message-ingress': async (request, context) => {
        if (context.params['case_id'] !== configuredCaseId || context.sessionId === null) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        const parsed = conversationMessageIngressRequest.parse(await body(request));
        const result = await options.conversationTransport.ingestMessage(
          parsed,
          requireActor(context),
          context.sessionId,
        );
        return {
          status: 200,
          body: result,
          accessEvidence: {
            kind: 'conversation_message_ingress',
            case_id: configuredCaseId,
            message_id: result.message_id,
            turn_id: result.turn_id,
            item_id: result.message_item_id,
            conversation_version: result.conversation_version,
            content_digest: result.message_digest,
            byte_length: Buffer.byteLength(parsed.text, 'utf8'),
            ingress_profile_id: 'case-officer-message@1',
            ingress_profile_digest: CASE_OFFICER_MESSAGE_PROFILE_DIGEST,
            recorded_at: result.recorded_at,
          },
        };
      },
      'output-release.consume': async (request, context) => {
        const releaseId = context.params['id'];
        if (releaseId === undefined || context.sessionId === null) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        const parsed = outputReleaseConsumeRequest.parse(await body(request));
        const result = await options.conversationTransport.consumeRelease(
          releaseId,
          parsed.content,
          requireActor(context),
          context.sessionId,
        );
        return {
          status: 200,
          body: result,
          accessEvidence: options.conversationTransport.releaseConsumptionEvidence(releaseId, result),
        };
      },
      'output-release.read': async (_request, context) => {
        const releaseId = context.params['id'];
        if (releaseId === undefined || context.sessionId === null) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        const result = options.conversationTransport.releaseStatus(
          releaseId,
          requireActor(context),
          context.sessionId,
        );
        return { status: 200, body: result, accessEvidence: result };
      },
      'conversation.read': async (_request, context) => {
        if (context.params['case_id'] !== configuredCaseId || context.sessionId === null) {
          return { status: 403, body: { error: 'forbidden' } };
        }
        const result = options.conversationTransport.conversation(requireActor(context), context.sessionId);
        return {
          status: 200,
          body: result,
          readLengths: { conversation_events: result.events.length },
          accessEvidence: {
            kind: 'conversation_read',
            case_id: result.case_id,
            conversation_version: result.conversation_version,
            event_count: result.events.length,
            utf8_bytes: result.events.reduce((sum, event) => sum + Buffer.byteLength(event.text, 'utf8'), 0),
          },
        };
      },
      'model-call.fail': async (request, context) => {
        const parsed = modelCallFailureRequest.parse(await body(request));
        const failed = await options.conversationProjections.failCall({ ...parsed, actor: requireActor(context) });
        return { status: 200, body: failed, accessEvidence: failed };
      },
      'ruling.read': async (_request, context) => {
        const rulingId = context.params['id'];
        if (rulingId === undefined) return { status: 404, body: { error: 'not-found' } };
        const result = options.reads.ruling(rulingId, requireActor(context));
        return result === null
          ? { status: 404, body: { error: 'not-found' } }
          : { status: 200, body: result };
      },
      'models.read': async (_request, context) => {
        const mandateId = context.params['id'];
        if (mandateId === undefined) return { status: 404, body: { error: 'not-found' } };
        const result = options.reads.approvedModels(mandateId, requireActor(context));
        return result === null
          ? { status: 404, body: { error: 'not-found' } }
          : { status: 200, body: result };
      },
      'commit.verify': async (request, context) => {
        const parsed = commitVerifyRequest.parse(await body(request));
        const result = await options.authorization.commitVerify({
          rulingId: parsed.ruling_id,
          intent: parsed.intent,
          servicesHostBootId: parsed.services_host_boot_id,
          servicesLedgerId: parsed.services_ledger_id,
          actor: requireActor(context),
        });
        return { status: 200, body: result };
      },
      'execution-preparation.commit-verify': async (request, context) => {
        if (options.executionPreparations === undefined) return { status: 503, body: { error: 'execution-preparation-unavailable' } };
        const preparationId = context.params['id'];
        if (preparationId === undefined) return { status: 404, body: { error: 'not-found' } };
        const parsed = nativeCommitVerifyRequest.parse(await body(request));
        const result = await options.executionPreparations.commitVerify(
          preparationId,
          parsed.services_host_boot_id,
          parsed.services_ledger_id,
          requireActor(context),
        );
        return { status: 200, body: result };
      },
      'effect.outcome': async (request, context) => {
        const parsed = effectOutcomeRequest.parse(await body(request));
        if (context.worldId !== parsed.world_id || context.params['id'] !== parsed.effect_id) {
          return { status: 422, body: { error: 'binding-mismatch' } };
        }
        const result: EffectOutcomeReportResult = await options.authorization.reportEffectOutcome({
          worldId: parsed.world_id,
          commitmentId: parsed.commitment_id,
          effectId: parsed.effect_id,
          idempotencyKey: parsed.idempotency_key,
          effectRequestDigest: parsed.effect_request_digest,
          servicesHostBootId: parsed.services_host_boot_id,
          servicesLedgerId: parsed.services_ledger_id,
          outcome: parsed.outcome,
          recordedAt: parsed.recorded_at,
          ...(parsed.detail === undefined ? {} : { detail: parsed.detail }),
          delivery: parsed.delivery,
          actor: requireActor(context),
        });
        return { status: 200, body: result };
      },
      'access.report': async (request) => {
        const parsed = servicesAccessReportRequest.parse(await body(request));
        // Authorization remains the chain writer; the closed services.* route namespace
        // and this route's services-only ACL preserve the reporter boundary.
        const entryId = await options.authorization.recordAccess({
          route: ACCESS_ROUTE_LABELS[parsed.route],
          authenticatedActor: parsed.authenticated_actor,
          claimedActor: null,
          outcome: parsed.outcome,
          httpStatus: parsed.http_status,
          recorder: { credential: 'proc:authz', claimed_role: null },
          ...(parsed.outcome === 'rate-limited'
            ? {
                suppressedCount: parsed.suppressed_count,
                suppressionWindowMs: parsed.suppression_window_ms,
                suppressionFinal: parsed.suppression_final,
              }
            : {}),
        });
        return { status: 201, body: { entry_id: entryId } };
      },
      'mandate.grant': async (request, context) => {
        const raw = jsonObject.parse(await body(request));
        if (Object.hasOwn(raw, 'binding')) return { status: 422, body: { error: 'binding-server-owned' } };
        const bound = bindMandate(options.keyring, raw as unknown as Omit<Mandate, 'binding'>);
        await options.authorization.grantMandate(bound, requireActor(context));
        return { status: 201, body: { mandate_id: bound.mandate_id, version: bound.version } };
      },
      'mandate.amend': async (request, context) => {
        const raw = jsonObject.parse(await body(request));
        if (Object.hasOwn(raw, 'binding')) return { status: 422, body: { error: 'binding-server-owned' } };
        const bound = bindMandate(options.keyring, raw as unknown as Omit<Mandate, 'binding'>);
        if (context.params['id'] !== bound.mandate_id) return { status: 422, body: { error: 'binding-mismatch' } };
        await options.authorization.amendMandate(bound, requireActor(context));
        return { status: 200, body: { mandate_id: bound.mandate_id, version: bound.version } };
      },
      'mandate.revoke': async (request, context) => {
        const parsed = revokeRequest.parse(await body(request));
        const mandateId = context.params['id'];
        if (mandateId === undefined) return { status: 422, body: { error: 'binding-mismatch' } };
        await options.authorization.revokeMandate(mandateId, parsed.version, requireActor(context));
        return { status: 200, body: { mandate_id: mandateId, version: parsed.version, state: 'revoked' } };
      },
      'mandate.list': async (_request, context) => ({
        status: 200,
        body: options.reads.mandates(requireActor(context)),
      }),
      'system-use.read': async (_request, context) => {
        const actor = requireActor(context);
        if (actor.credential !== 'role:principal') return { status: 403, body: { error: 'forbidden' } };
        return { status: 200, body: options.systemUse.governanceProjection(new Date().toISOString()) };
      },
      'escalation.list': async (_request, context) => ({
        status: 200,
        body: options.reads.escalations(requireActor(context)),
      }),
      'escalation.read': async (_request, context) => {
        const escalationId = context.params['id'];
        if (escalationId === undefined) return { status: 404, body: { error: 'not-found' } };
        const result = options.reads.escalation(escalationId, requireActor(context));
        return result === null
          ? { status: 404, body: { error: 'not-found' } }
          : { status: 200, body: result };
      },
      'escalation.dispose': async (request, context) => {
        const parsed = dispositionRequest.parse(await body(request));
        const escalationId = context.params['id'];
        if (escalationId === undefined) return { status: 422, body: { error: 'binding-mismatch' } };
        const result: DisposeEscalationResult = await options.authorization.disposeEscalation({
          escalationId,
          disposition: parsed.disposition,
          actor: requireActor(context),
        });
        return { status: result.accepted ? 200 : 422, body: result };
      },
      'escalation.respond': async (request, context) => {
        const parsed = dialogueResponseRequest.parse(await body(request));
        const escalationId = context.params['id'];
        if (escalationId === undefined || parsed.escalation_id !== escalationId) {
          return { status: 400, body: { error: 'binding-mismatch' } };
        }
        const result: RespondDialogueResult = await options.authorization.respondDialogue({
          escalationId,
          disposition: parsed.disposition,
          actor: requireActor(context),
          ...(parsed.answer_text === undefined ? {} : { answerText: parsed.answer_text }),
          ...(parsed.evidence_ref === undefined ? {} : { evidenceRef: parsed.evidence_ref }),
          ...(parsed.scope === undefined ? {} : { scope: parsed.scope }),
        });
        if (result.accepted) return { status: 200, body: result };
        if (result.defect === 'missing-escalation') return { status: 404, body: result };
        if (result.defect === 'wrong-role') return { status: 403, body: result };
        if (result.defect === 'late-response') return { status: 409, body: result };
        return { status: 422, body: result };
      },
      'escalation.revise': async (request, context) => {
        const parsed = revisionRequest.parse(await body(request));
        const escalationId = context.params['id'];
        if (escalationId === undefined) return { status: 422, body: { error: 'binding-mismatch' } };
        const result: ContinueEscalationRevisionResult = await options.authorization.continueEscalationRevision({
          escalationId,
          proposal: parsed.proposal,
          actor: requireActor(context),
          ...(parsed.context === undefined ? {} : { context: parsed.context }),
        });
        return { status: result.accepted ? 200 : 422, body: result };
      },
      'challenge.submit': async (request, context) => {
        const parsed = challengeRequest.parse(await body(request));
        const result: SubmitChallengeResult = await options.authorization.submitChallenge({
          actionId: parsed.action_id,
          contestedEntryId: parsed.contested_entry_id,
          correctionText: parsed.correction_text,
          actor: requireActor(context),
        });
        if (result.accepted) return { status: 201, body: result };
        if (result.defect === 'wrong-role') return { status: 403, body: result };
        if (result.defect === 'missing-action' || result.defect === 'missing-entry') {
          return { status: 404, body: result };
        }
        if (result.defect === 'already-open') return { status: 409, body: result };
        return { status: 422, body: result };
      },
      'records.verify': async (_request, context) => {
        const result = await options.reads.verification(requireActor(context));
        return {
          status: result.body.status === 'alarm' ? 409 : 200,
          body: result.body,
          readLengths: result.readLengths,
        };
      },
      'records.read': async (_request, context) => {
        const result = options.reads.records(requireActor(context));
        return { status: 200, body: result.body, readLengths: result.readLengths };
      },
      'extract.read': async (_request, context) => {
        const result = await options.reads.applicantExtract(requireActor(context));
        return { status: 200, body: result.body, readLengths: result.readLengths };
      },
    };
    const unsupported: Handler = async () => ({ status: 501, body: { error: 'not-implemented' } });
    this.#handlers = Object.fromEntries(
      AUTHORIZATION_ROUTES.map((route) => [route.id, handlers[route.id] ?? unsupported]),
    );

    this.#server = createServer((request, response) => {
      void this.#handle(request, response, options.adapter);
    });
  }

  async #handle(
    request: IncomingMessage,
    response: ServerResponse,
    adapter: AuthorizationHttpAdapter,
  ): Promise<void> {
    try {
      const url = new URL(request.url ?? '/', `http://${this.#host}`);
      const adapted = await adapter.dispatch(
        {
          method: request.method ?? 'GET',
          pathname: url.pathname,
          authorization: request.headers.authorization,
          origin: Array.isArray(request.headers.origin) ? request.headers.origin[0] : request.headers.origin,
          claimedRole: Array.isArray(request.headers['x-on-behalf-of-role'])
            ? request.headers['x-on-behalf-of-role'][0]
            : request.headers['x-on-behalf-of-role'],
          sessionId: Array.isArray(request.headers['x-session-id'])
            ? request.headers['x-session-id'][0]
            : request.headers['x-session-id'],
        },
        async (context) => {
          try {
            const handler = this.#handlers[context.routeId];
            if (handler === undefined) return { status: 500, body: { error: 'route-handler-missing' } };
            return await handler(request, context);
          } catch (error) {
            if (error instanceof HttpInputError) return { status: error.status, body: { error: error.responseCode } };
            if (error instanceof ZodError) return { status: 422, body: { error: 'invalid-request' } };
            if (error instanceof AuthorizationError) return { status: 422, body: { error: error.code } };
            if (error instanceof AuthorizationReadSideError) {
              return {
                status: error.code === 'forbidden' ? 403 : 409,
                body: { error: error.code },
              };
            }
            if (error instanceof ConversationProjectionServiceError) {
              return {
                status: error.code === 'forbidden' ? 403 : error.code === 'invalid-scope' ? 422 : 409,
                body: { error: error.code },
              };
            }
            if (error instanceof ConversationTransportError) {
              return {
                status:
                  error.code === 'forbidden'
                    ? 403
                    : error.code === 'invalid-message' || error.code === 'invalid-scope'
                      ? 422
                      : 409,
                body: { error: error.code },
              };
            }
            if (error instanceof ProposalIntakeError) {
              return {
                status: error.code === 'forbidden' ? 403 : error.code === 'not-found' ? 404 : 409,
                body: { error: error.code },
              };
            }
            if (error instanceof ProposalPrecommitError) {
              return {
                status: error.code === 'forbidden' ? 403 : error.code === 'not-found' ? 404 : 409,
                body: { error: error.code },
              };
            }
            if (error instanceof ExecutionPreparationError) {
              return {
                status: error.code === 'forbidden' ? 403 : error.code === 'not-found' ? 404 : 409,
                body: { error: error.code },
              };
            }
            if (error instanceof ScreeningCallError) {
              return {
                status: error.code === 'forbidden' ? 403 : error.code === 'not-found' ? 404 : 409,
                body: { error: error.code },
              };
            }
            if (error instanceof CaseSessionHandoffError) {
              return { status: 403, body: { error: 'handoff-refused' } };
            }
            if (error instanceof SystemUseDecisionError) {
              return { status: error.code === 'forbidden' ? 403 : 409, body: { error: error.code } };
            }
            throw error;
          }
        },
      );
      if (adapted.routeId === 'console.shell' && typeof adapted.body === 'string') {
        sendConsoleAsset(response, adapted.status, adapted.body, 'text/html');
      } else if (adapted.routeId === 'console.script' && typeof adapted.body === 'string') {
        sendConsoleAsset(response, adapted.status, adapted.body, 'text/javascript');
      } else if (adapted.routeId === 'console.style' && typeof adapted.body === 'string') {
        sendConsoleAsset(response, adapted.status, adapted.body, 'text/css');
      } else {
        sendJson(response, adapted.status, adapted.body);
      }
    } catch {
      if (!response.headersSent) sendJson(response, 500, { error: 'internal-error' });
      else response.destroy();
    }
  }

  listen(): Promise<ListeningAddress> {
    return new Promise((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      this.#server.once('error', onError);
      this.#server.listen(this.#port, this.#host, () => {
        this.#server.off('error', onError);
        const address = this.#server.address();
        if (address === null || typeof address === 'string') {
          reject(new Error('authorization listener did not expose a TCP address'));
          return;
        }
        resolve({ host: this.#host, port: address.port, origin: `http://${this.#host}:${address.port}` });
      });
    });
  }

  close(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.#server.listening) {
        resolve();
        return;
      }
      this.#server.close((error) => (error === undefined ? resolve() : reject(error)));
    });
  }
}
