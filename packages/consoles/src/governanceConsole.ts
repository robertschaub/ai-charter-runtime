// SPDX-License-Identifier: MIT
/** Authorization-origin governance console. No authority decision is made in this client. */

export const CONSOLE_ROLES = ['principal', 'case_officer', 'applicant'] as const;
export type ConsoleRole = (typeof CONSOLE_ROLES)[number];

const WORLD_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const OPAQUE_ID = /^[a-z0-9][a-z0-9_.:-]*$/;
const TOKEN = /^[0-9a-fA-F]{64,}$/;
const READY_TYPE = 'runtime.case-handoff.ready';
const TRANSFER_TYPE = 'runtime.case-handoff.transfer';
const WINDOWS_RESERVED = new Set([
  'con',
  'prn',
  'aux',
  'nul',
  ...Array.from({ length: 9 }, (_, index) => `com${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `lpt${index + 1}`),
]);

export const GENERAL_CONSOLE_DISPOSITIONS = [
  'allow-within-scope',
  'deny',
  'narrow-or-modify',
  'seek-review',
  'cancel',
  'reverse',
  'route-to-remedy',
] as const;

type GeneralConsoleDisposition = (typeof GENERAL_CONSOLE_DISPOSITIONS)[number];

export const DIALOGUE_CONSOLE_DISPOSITIONS = [
  'confirm',
  'correct',
  'narrow',
  'permit',
  'abstain',
  'route',
] as const;

type DialogueConsoleDisposition = (typeof DIALOGUE_CONSOLE_DISPOSITIONS)[number];

export interface ConsoleDeepLink {
  readonly kind: 'dialogue';
  readonly worldId: string;
  readonly escalationId: string;
}

export interface GovernanceRuntimeConfig {
  readonly authorization_origin: string;
  readonly orchestrator_origin: string;
}

interface MintedCaseHandoff {
  readonly handoff_id: string;
  readonly handoff_code: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly target_origin: string;
  readonly authorization_boot_id: string;
}

export function validWorldId(value: string): boolean {
  return WORLD_ID.test(value) && !WINDOWS_RESERVED.has(value);
}

export function consoleApiPath(worldId: string, ...segments: readonly string[]): string {
  if (!validWorldId(worldId)) throw new Error('invalid world id');
  if (segments.length === 0 || segments.some((segment) => !OPAQUE_ID.test(segment))) {
    throw new Error('invalid API path segment');
  }
  return `/w/${worldId}/${segments.join('/')}`;
}

export function parseConsoleDeepLink(pathname: string): ConsoleDeepLink | null {
  const match = /^\/console\/dialogue\/([^/]+)\/([^/]+)\/?$/.exec(pathname);
  if (match === null) return null;
  const worldId = match[1];
  const escalationId = match[2];
  if (worldId === undefined || escalationId === undefined || !validWorldId(worldId) || !OPAQUE_ID.test(escalationId)) {
    return null;
  }
  return { kind: 'dialogue', worldId, escalationId };
}

export function permittedGeneralDispositions(
  status: unknown,
  values: unknown,
): readonly GeneralConsoleDisposition[] {
  if (status !== 'open' || !Array.isArray(values)) return [];
  const permitted = new Set(values.filter((value): value is string => typeof value === 'string'));
  return GENERAL_CONSOLE_DISPOSITIONS.filter((value) => permitted.has(value));
}

export function permittedDialogueDispositions(
  status: unknown,
  values: unknown,
): readonly DialogueConsoleDisposition[] {
  if (status !== 'open' || !Array.isArray(values)) return [];
  const permitted = new Set(values.filter((value): value is string => typeof value === 'string'));
  return DIALOGUE_CONSOLE_DISPOSITIONS.filter((value) => permitted.has(value));
}

interface ConsoleState {
  role: ConsoleRole;
  worldId: string;
  token: string;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function exactOrigin(value: unknown): value is string {
  if (typeof value !== 'string') return false;
  try {
    const parsed = new URL(value);
    return (parsed.protocol === 'http:' || parsed.protocol === 'https:') && parsed.origin === value;
  } catch {
    return false;
  }
}

export function parseGovernanceRuntimeConfig(value: unknown): GovernanceRuntimeConfig | null {
  if (!isRecord(value) || Object.keys(value).length !== 2) return null;
  if (!exactOrigin(value['authorization_origin']) || !exactOrigin(value['orchestrator_origin'])) return null;
  return {
    authorization_origin: value['authorization_origin'],
    orchestrator_origin: value['orchestrator_origin'],
  };
}

export function acceptsHandoffReady(
  event: Pick<MessageEvent<unknown>, 'origin' | 'source' | 'data'>,
  orchestratorOrigin: string,
  expectedChild: WindowProxy,
): boolean {
  return (
    event.origin === orchestratorOrigin &&
    event.source === expectedChild &&
    isRecord(event.data) &&
    Object.keys(event.data).length === 1 &&
    event.data['type'] === READY_TYPE
  );
}

function parseMintedCaseHandoff(value: unknown, config: GovernanceRuntimeConfig): MintedCaseHandoff | null {
  if (!isRecord(value) || Object.keys(value).length !== 8) return null;
  if (
    typeof value['handoff_id'] !== 'string' || !OPAQUE_ID.test(value['handoff_id']) ||
    typeof value['handoff_code'] !== 'string' || !/^[0-9a-f]{64,}$/.test(value['handoff_code']) ||
    value['role'] !== 'case_officer' ||
    typeof value['world_id'] !== 'string' || !validWorldId(value['world_id']) ||
    typeof value['case_id'] !== 'string' || !OPAQUE_ID.test(value['case_id']) ||
    value['target_origin'] !== config.orchestrator_origin ||
    typeof value['authorization_boot_id'] !== 'string' || !OPAQUE_ID.test(value['authorization_boot_id']) ||
    typeof value['expires_at'] !== 'string'
  ) {
    return null;
  }
  return {
    handoff_id: value['handoff_id'],
    handoff_code: value['handoff_code'],
    role: 'case_officer',
    world_id: value['world_id'],
    case_id: value['case_id'],
    target_origin: value['target_origin'],
    authorization_boot_id: value['authorization_boot_id'],
  };
}

let runtimeConfig: GovernanceRuntimeConfig | null = null;
let dialogueDeepLink: ConsoleDeepLink | null = null;

function element<T extends HTMLElement>(id: string): T {
  const found = document.getElementById(id);
  if (found === null) throw new Error(`console element missing: ${id}`);
  return found as T;
}

function storageKey(role: ConsoleRole): string {
  return `runtime-governance-token:${role}`;
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function setOutput(id: string, value: unknown): void {
  element<HTMLElement>(id).textContent = jsonText(value);
}

function setActivity(message: string): void {
  element<HTMLElement>('activity').textContent = message;
}

function clearChildren(target: HTMLElement): void {
  while (target.firstChild !== null) target.removeChild(target.firstChild);
}

function text(tag: keyof HTMLElementTagNameMap, value: string, className?: string): HTMLElement {
  const node = document.createElement(tag);
  node.textContent = value;
  if (className !== undefined) node.className = className;
  return node;
}

function tokenFromStorage(role: ConsoleRole): string {
  try {
    return localStorage.getItem(storageKey(role)) ?? '';
  } catch {
    return '';
  }
}

function persistToken(role: ConsoleRole, token: string): void {
  localStorage.setItem(storageKey(role), token);
}

function currentState(): ConsoleState {
  const role = element<HTMLSelectElement>('role').value as ConsoleRole;
  const worldId = element<HTMLInputElement>('world').value.trim();
  const token = element<HTMLInputElement>('token').value.trim();
  if (!CONSOLE_ROLES.includes(role)) throw new Error('select a supported role');
  if (!validWorldId(worldId)) throw new Error('enter a valid world id');
  if (!TOKEN.test(token)) throw new Error('enter a valid role token');
  return { role, worldId, token };
}

async function apiRequest(
  state: ConsoleState,
  path: string,
  init: { readonly method?: 'GET' | 'POST'; readonly body?: unknown } = {},
): Promise<unknown> {
  const method = init.method ?? 'GET';
  const response = await fetch(path, {
    method,
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    headers: {
      authorization: `Bearer ${state.token}`,
      ...(init.body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  const contentType = response.headers.get('content-type') ?? '';
  const body: unknown = contentType.startsWith('application/json') ? await response.json() : await response.text();
  if (!response.ok) {
    const code =
      isRecord(body) && typeof body['error'] === 'string'
        ? body['error']
        : isRecord(body) && typeof body['defect'] === 'string'
          ? body['defect']
          : `http-${response.status}`;
    throw new Error(`${code} (${response.status})`);
  }
  return body;
}

function requireRole(state: ConsoleState, role: ConsoleRole): void {
  if (state.role !== role) throw new Error(`select the ${role} credential first`);
}

function formJson(id: string): Record<string, unknown> {
  const raw = element<HTMLTextAreaElement>(id).value;
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed)) throw new Error('mandate JSON must be an object');
  if (Object.hasOwn(parsed, 'binding')) throw new Error('remove the server-owned binding field');
  return parsed;
}

function itemButton(label: string, action: () => void): HTMLButtonElement {
  const button = document.createElement('button');
  button.type = 'button';
  button.textContent = label;
  button.className = 'secondary';
  button.addEventListener('click', action);
  return button;
}

async function loadMandates(): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  const result = await apiRequest(state, consoleApiPath(state.worldId, 'mandates'));
  const mandates = isRecord(result) && Array.isArray(result['mandates']) ? result['mandates'] : [];
  const target = element<HTMLElement>('mandate-list');
  clearChildren(target);
  if (mandates.length === 0) target.append(text('p', 'No current mandates are visible for this role.'));
  for (const value of mandates) {
    if (!isRecord(value)) continue;
    const mandateId = typeof value['mandate_id'] === 'string' ? value['mandate_id'] : 'unknown';
    const version = typeof value['version'] === 'number' ? value['version'] : null;
    const item = text('article', '', 'item');
    item.append(text('h4', mandateId));
    item.append(text('p', `Version ${version ?? 'unknown'} · state ${String(value['state'] ?? 'unknown')}`));
    const actions = text('div', '', 'item-actions');
    actions.append(
      itemButton('Check model cards', () => {
        element<HTMLInputElement>('card-mandate-id').value = mandateId;
        void loadCards().catch(reportError);
      }),
    );
    actions.append(
      itemButton('Prepare amendment', () => {
        element<HTMLInputElement>('amend-id').value = mandateId;
      }),
    );
    if (version !== null) {
      actions.append(
        itemButton('Prepare revocation', () => {
          element<HTMLInputElement>('revoke-id').value = mandateId;
          element<HTMLInputElement>('revoke-version').value = String(version);
        }),
      );
    }
    item.append(actions);
    target.append(item);
  }
  setActivity(`Loaded ${mandates.length} mandate envelope(s).`);
}

async function loadCards(): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  const mandateId = element<HTMLInputElement>('card-mandate-id').value.trim();
  if (!OPAQUE_ID.test(mandateId)) throw new Error('enter a valid mandate id');
  const result = await apiRequest(
    state,
    consoleApiPath(state.worldId, 'mandates', mandateId, 'approved-models'),
  );
  setOutput('card-output', result);
  setActivity('Loaded signed model-card evidence. No aggregate assurance result was computed.');
}

async function submitMandate(operation: 'grant' | 'amend'): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  const body = formJson(operation === 'grant' ? 'grant-json' : 'amend-json');
  const mandateId = operation === 'amend' ? element<HTMLInputElement>('amend-id').value.trim() : null;
  if (mandateId !== null && !OPAQUE_ID.test(mandateId)) throw new Error('enter a valid mandate id');
  const path =
    mandateId === null
      ? consoleApiPath(state.worldId, 'mandates')
      : consoleApiPath(state.worldId, 'mandates', mandateId, 'amend');
  const result = await apiRequest(state, path, { method: 'POST', body });
  setOutput('mandate-mutation-output', result);
  setActivity(operation === 'grant' ? 'Mandate grant recorded.' : 'Mandate amendment recorded.');
  await loadMandates();
}

async function revokeMandate(): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  const mandateId = element<HTMLInputElement>('revoke-id').value.trim();
  const version = Number(element<HTMLInputElement>('revoke-version').value);
  if (!OPAQUE_ID.test(mandateId)) throw new Error('enter a valid mandate id');
  if (!Number.isSafeInteger(version) || version < 1) throw new Error('enter a valid mandate version');
  if (!window.confirm(`Revoke ${mandateId} version ${version}?`)) return;
  const result = await apiRequest(state, consoleApiPath(state.worldId, 'mandates', mandateId, 'revoke'), {
    method: 'POST',
    body: { version },
  });
  setOutput('mandate-mutation-output', result);
  setActivity('Mandate revocation recorded.');
  await loadMandates();
}

async function loadEscalations(): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  const result = await apiRequest(state, consoleApiPath(state.worldId, 'escalations'));
  const escalations = isRecord(result) && Array.isArray(result['escalations']) ? result['escalations'] : [];
  const target = element<HTMLElement>('escalation-list');
  clearChildren(target);
  clearChildren(element<HTMLElement>('escalation-detail'));
  if (escalations.length === 0) target.append(text('p', 'No escalations are routed to this role.'));
  for (const value of escalations) {
    if (!isRecord(value)) continue;
    const escalationId = typeof value['escalation_id'] === 'string' ? value['escalation_id'] : 'unknown';
    const item = text('article', '', 'item');
    item.append(text('h4', escalationId));
    item.append(
      text('p', `${String(value['trigger'] ?? 'unknown trigger')} · ${String(value['status'] ?? 'unknown')}`),
    );
    item.append(itemButton('Open contract', () => void loadEscalationDetail(escalationId).catch(reportError)));
    target.append(item);
  }
  setActivity(`Loaded ${escalations.length} routed escalation(s).`);
}

async function loadEscalationDetail(escalationId: string): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  const result = await apiRequest(state, consoleApiPath(state.worldId, 'escalations', escalationId));
  if (!isRecord(result)) throw new Error('unexpected escalation projection');
  const target = element<HTMLElement>('escalation-detail');
  clearChildren(target);
  target.append(text('h4', `Intervention contract · ${escalationId}`));
  const output = text('pre', jsonText(result), 'data-output');
  output.tabIndex = 0;
  target.append(output);
  const permitted = permittedGeneralDispositions(result['status'], result['permitted_dispositions']);
  const actions = text('div', '', 'item-actions');
  for (const disposition of permitted) {
    const button = itemButton(disposition, () => void disposeEscalation(escalationId, disposition).catch(reportError));
    actions.append(button);
  }
  if (permitted.length === 0) {
    actions.append(text('p', 'No general disposition is currently available from this contract.'));
  }
  target.append(actions);
}

async function disposeEscalation(escalationId: string, disposition: GeneralConsoleDisposition): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  await apiRequest(
    state,
    consoleApiPath(state.worldId, 'escalations', escalationId, 'disposition'),
    { method: 'POST', body: { disposition } },
  );
  setActivity(`Escalation disposition ${disposition} was submitted to the authorization service.`);
  await loadEscalations();
}

async function loadDialogue(): Promise<void> {
  const deepLink = dialogueDeepLink;
  if (deepLink === null) throw new Error('no dialogue deep link is active');
  const state = currentState();
  if (state.worldId !== deepLink.worldId) throw new Error('the credential world does not match the dialogue link');
  const result = await apiRequest(state, consoleApiPath(state.worldId, 'escalations', deepLink.escalationId));
  if (!isRecord(result) || !isRecord(result['contract'])) throw new Error('unexpected dialogue projection');
  const target = element<HTMLElement>('dialogue-detail');
  clearChildren(target);
  target.append(text('h3', `Dialogue ${deepLink.escalationId}`));
  target.append(text('p', typeof result['question_text'] === 'string' ? result['question_text'] : 'No question was recorded.'));
  const contract = text('pre', jsonText(result['contract']), 'data-output');
  contract.tabIndex = 0;
  target.append(contract);
  const permitted = permittedDialogueDispositions(result['status'], result['permitted_dispositions']);
  const select = element<HTMLSelectElement>('dialogue-disposition');
  clearChildren(select);
  for (const disposition of permitted) {
    const option = document.createElement('option');
    option.value = disposition;
    option.textContent = disposition;
    select.append(option);
  }
  const form = element<HTMLFormElement>('dialogue-form');
  form.hidden = permitted.length === 0;
  if (permitted.length === 0) target.append(text('p', 'This dialogue has no open response disposition.'));
  setActivity('Loaded the routed question and six-field contract directly from the authorization service.');
}

async function respondDialogue(): Promise<void> {
  const deepLink = dialogueDeepLink;
  if (deepLink === null) throw new Error('no dialogue deep link is active');
  const state = currentState();
  if (state.worldId !== deepLink.worldId) throw new Error('the credential world does not match the dialogue link');
  const disposition = element<HTMLSelectElement>('dialogue-disposition').value as DialogueConsoleDisposition;
  if (!DIALOGUE_CONSOLE_DISPOSITIONS.includes(disposition)) throw new Error('select a permitted dialogue disposition');
  const answer = element<HTMLTextAreaElement>('dialogue-answer').value.trim();
  const evidenceId = element<HTMLInputElement>('dialogue-evidence-id').value.trim();
  const evidenceRetrieved = element<HTMLInputElement>('dialogue-evidence-retrieved').value.trim();
  const scopeItem = element<HTMLInputElement>('dialogue-scope-item').value.trim();
  if ((disposition === 'correct' || disposition === 'narrow') && answer === '') {
    throw new Error(`${disposition} requires answer text`);
  }
  if ((disposition === 'permit' || disposition === 'narrow') && !OPAQUE_ID.test(scopeItem)) {
    throw new Error(`${disposition} requires a valid scope item reference`);
  }
  if ((evidenceId === '') !== (evidenceRetrieved === '')) throw new Error('evidence id and retrieved-at are supplied together');
  const body = {
    escalation_id: deepLink.escalationId,
    disposition,
    ...(answer === '' ? {} : { answer_text: answer }),
    ...(evidenceId === ''
      ? {}
      : {
          evidence_ref: {
            kind: 'registry_record',
            id: evidenceId,
            retrieved_at: evidenceRetrieved,
          },
        }),
    ...(scopeItem === '' ? {} : { scope: { item_ref: scopeItem, applies_to: 'this_case_only' } }),
  };
  await apiRequest(
    state,
    consoleApiPath(state.worldId, 'escalations', deepLink.escalationId, 'response'),
    { method: 'POST', body },
  );
  element<HTMLTextAreaElement>('dialogue-answer').value = '';
  setActivity(`Dialogue response ${disposition} was recorded directly by the authorization service.`);
  await loadDialogue();
}

async function loadRecords(): Promise<void> {
  const state = currentState();
  requireRole(state, 'principal');
  const result = await apiRequest(state, consoleApiPath(state.worldId, 'records'));
  setOutput('record-output', result);
  setActivity('Loaded action and access record projections; this read was itself recorded.');
}

async function loadExtract(): Promise<void> {
  const state = currentState();
  requireRole(state, 'applicant');
  const result = await apiRequest(state, consoleApiPath(state.worldId, 'extract'));
  setOutput('extract-output', result);
  setActivity('Loaded the server-side applicant extract and local receipt.');
}

async function loadRuntimeConfig(): Promise<void> {
  const response = await fetch('/console/runtime-config.json', {
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  const parsed = parseGovernanceRuntimeConfig(await response.json());
  if (!response.ok || parsed === null || parsed.authorization_origin !== window.location.origin) {
    throw new Error('invalid runtime console configuration');
  }
  runtimeConfig = parsed;
  element<HTMLButtonElement>('open-case-session').disabled = false;
}

async function openCaseSession(): Promise<void> {
  const state = currentState();
  requireRole(state, 'case_officer');
  const config = runtimeConfig;
  if (config === null) throw new Error('runtime console configuration is not ready');
  const caseId = element<HTMLInputElement>('case-id').value.trim();
  if (!OPAQUE_ID.test(caseId)) throw new Error('enter a valid case id');

  let child: WindowProxy | null = null;
  let timeout = 0;
  let removeReadyListener: () => void = () => undefined;
  const ready = new Promise<void>((resolve, reject) => {
    const onReady = (event: MessageEvent<unknown>) => {
      if (child === null || !acceptsHandoffReady(event, config.orchestrator_origin, child)) return;
      window.clearTimeout(timeout);
      window.removeEventListener('message', onReady);
      resolve();
    };
    removeReadyListener = () => window.removeEventListener('message', onReady);
    window.addEventListener('message', onReady);
    timeout = window.setTimeout(() => {
      window.removeEventListener('message', onReady);
      reject(new Error('case-session window did not become ready'));
    }, 30_000);
  });
  child = window.open(`${config.orchestrator_origin}/console/handoff`, '_blank');
  if (child === null) {
    window.clearTimeout(timeout);
    removeReadyListener();
    throw new Error('case-session window was blocked');
  }

  return (async () => {
    try {
      await ready;
      const raw = await apiRequest(
        state,
        consoleApiPath(state.worldId, 'case-session-handoffs'),
        { method: 'POST', body: { case_id: caseId } },
      );
      const handoff = parseMintedCaseHandoff(raw, config);
      if (handoff === null || handoff.world_id !== state.worldId || handoff.case_id !== caseId) {
        throw new Error('authorization service returned an invalid handoff');
      }
      child?.postMessage({ type: TRANSFER_TYPE, ...handoff }, config.orchestrator_origin);
      setActivity('One-time case-session handoff transferred to the exact orchestrator window.');
    } catch (error) {
      child?.close();
      throw error;
    }
  })();
}

function reportError(error: unknown): void {
  const message = error instanceof Error ? error.message : 'unexpected console error';
  setActivity(`Request refused: ${message}`);
}

function setView(view: ConsoleRole): void {
  element<HTMLElement>('principal-view').hidden = view !== 'principal';
  element<HTMLElement>('case-officer-view').hidden = view !== 'case_officer';
  element<HTMLElement>('applicant-view').hidden = view !== 'applicant';
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-view]')) {
    button.setAttribute('aria-pressed', String(button.dataset['view'] === view));
  }
  element<HTMLSelectElement>('role').value = view;
  element<HTMLInputElement>('token').value = tokenFromStorage(view);
  element<HTMLElement>('session-status').textContent = tokenFromStorage(view) === ''
    ? `No ${view} token is stored on this origin.`
    : `${view} token is stored on this origin.`;
}

function wireForm(id: string, action: () => Promise<void>): void {
  element<HTMLFormElement>(id).addEventListener('submit', (event) => {
    event.preventDefault();
    void action().catch(reportError);
  });
}

export function mountGovernanceConsole(): void {
  const role = element<HTMLSelectElement>('role');
  const token = element<HTMLInputElement>('token');
  const world = element<HTMLInputElement>('world');
  const deepLink = parseConsoleDeepLink(window.location.pathname);
  if (deepLink !== null) {
    dialogueDeepLink = deepLink;
    world.value = deepLink.worldId;
    element<HTMLElement>('dialogue-view').hidden = false;
    setActivity(`Dialogue ${deepLink.escalationId} was linked safely without a token. Supply its routed role credential to load it.`);
  }
  const savedWorld = localStorage.getItem('runtime-governance-world');
  if (deepLink === null && savedWorld !== null && validWorldId(savedWorld)) world.value = savedWorld;
  token.value = tokenFromStorage('principal');
  setView('principal');

  wireForm('credential-form', async () => {
    const state = currentState();
    persistToken(state.role, state.token);
    localStorage.setItem('runtime-governance-world', state.worldId);
    element<HTMLElement>('session-status').textContent = `${state.role} token is stored on this origin.`;
    setActivity('Credential saved locally; its value was not displayed or sent yet.');
    if (dialogueDeepLink !== null) await loadDialogue();
  });
  element<HTMLButtonElement>('clear-token').addEventListener('click', () => {
    const selected = role.value as ConsoleRole;
    localStorage.removeItem(storageKey(selected));
    token.value = '';
    element<HTMLElement>('session-status').textContent = `${selected} token cleared from this origin.`;
    setActivity('Stored role credential cleared.');
  });
  role.addEventListener('change', () => setView(role.value as ConsoleRole));
  for (const button of document.querySelectorAll<HTMLButtonElement>('[data-view]')) {
    button.addEventListener('click', () => setView(button.dataset['view'] as ConsoleRole));
  }

  element<HTMLButtonElement>('load-mandates').addEventListener(
    'click',
    () => void loadMandates().catch(reportError),
  );
  wireForm('card-form', loadCards);
  wireForm('grant-form', () => submitMandate('grant'));
  wireForm('amend-form', () => submitMandate('amend'));
  wireForm('revoke-form', revokeMandate);
  element<HTMLButtonElement>('load-escalations').addEventListener(
    'click',
    () => void loadEscalations().catch(reportError),
  );
  element<HTMLButtonElement>('load-records').addEventListener('click', () => void loadRecords().catch(reportError));
  element<HTMLButtonElement>('load-extract').addEventListener('click', () => void loadExtract().catch(reportError));
  wireForm('case-session-form', openCaseSession);
  element<HTMLButtonElement>('load-dialogue').addEventListener('click', () => void loadDialogue().catch(reportError));
  wireForm('dialogue-form', respondDialogue);
  void loadRuntimeConfig().catch(reportError);
}

if (typeof document !== 'undefined') {
  mountGovernanceConsole();
}
