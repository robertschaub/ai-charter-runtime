// SPDX-License-Identifier: MIT
/** Orchestrator-origin receiver for ADR-002's exact-window handoff. */

const WORLD_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const OPAQUE_ID = /^[a-z0-9][a-z0-9_.:-]*$/;
const SECRET = /^[0-9a-f]{64,}$/;
const SESSION_STORAGE_KEY = 'runtime-case-session';
const MODEL_STORAGE_KEY = 'runtime-case-model-choice';
const READY_TYPE = 'runtime.case-handoff.ready';
const TRANSFER_TYPE = 'runtime.case-handoff.transfer';

export interface RuntimeConsoleConfig {
  readonly authorization_origin: string;
  readonly orchestrator_origin: string;
}

export interface TransferredCaseHandoff {
  readonly type: typeof TRANSFER_TYPE;
  readonly handoff_id: string;
  readonly handoff_code: string;
  readonly role: 'case_officer';
  readonly world_id: string;
  readonly case_id: string;
  readonly target_origin: string;
  readonly authorization_boot_id: string;
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

export function parseRuntimeConsoleConfig(value: unknown): RuntimeConsoleConfig | null {
  if (!isRecord(value) || Object.keys(value).length !== 2) return null;
  if (!exactOrigin(value['authorization_origin']) || !exactOrigin(value['orchestrator_origin'])) return null;
  return {
    authorization_origin: value['authorization_origin'],
    orchestrator_origin: value['orchestrator_origin'],
  };
}

export function acceptsHandoffTransfer(
  event: Pick<MessageEvent<unknown>, 'origin' | 'source' | 'data'>,
  authorizationOrigin: string,
  expectedOpener: WindowProxy,
  ownOrigin: string,
): event is Pick<MessageEvent<TransferredCaseHandoff>, 'origin' | 'source' | 'data'> {
  if (event.origin !== authorizationOrigin || event.source !== expectedOpener || !isRecord(event.data)) return false;
  const data = event.data;
  return (
    Object.keys(data).length === 8 &&
    data['type'] === TRANSFER_TYPE &&
    typeof data['handoff_id'] === 'string' && OPAQUE_ID.test(data['handoff_id']) &&
    typeof data['handoff_code'] === 'string' && SECRET.test(data['handoff_code']) &&
    data['role'] === 'case_officer' &&
    typeof data['world_id'] === 'string' && WORLD_ID.test(data['world_id']) &&
    typeof data['case_id'] === 'string' && OPAQUE_ID.test(data['case_id']) &&
    data['target_origin'] === ownOrigin &&
    typeof data['authorization_boot_id'] === 'string' && OPAQUE_ID.test(data['authorization_boot_id'])
  );
}

function status(message: string): void {
  const target = document.getElementById('handoff-status');
  if (target !== null) target.textContent = message;
}

async function sameOriginJson(path: string, body: unknown, token?: string): Promise<unknown> {
  const response = await fetch(path, {
    method: 'POST',
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    headers: {
      'content-type': 'application/json',
      ...(token === undefined ? {} : { authorization: `Bearer ${token}` }),
    },
    body: JSON.stringify(body),
  });
  const parsed: unknown = await response.json();
  if (!response.ok) throw new Error('request-refused');
  return parsed;
}

async function sameOriginGet(path: string, token: string): Promise<unknown> {
  const response = await fetch(path, {
    method: 'GET',
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    headers: { authorization: `Bearer ${token}` },
  });
  const parsed: unknown = await response.json();
  if (!response.ok) throw new Error('request-refused');
  return parsed;
}

export function parseCreatedSession(
  value: unknown,
): { readonly session_token: string; readonly world_id: string; readonly case_id: string } | null {
  if (!isRecord(value) || Object.keys(value).length !== 6) return null;
  if (
    typeof value['session_token'] !== 'string' || !SECRET.test(value['session_token']) ||
    typeof value['session_id'] !== 'string' || !OPAQUE_ID.test(value['session_id']) ||
    value['role'] !== 'case_officer' ||
    typeof value['world_id'] !== 'string' || !WORLD_ID.test(value['world_id']) ||
    typeof value['case_id'] !== 'string' || !OPAQUE_ID.test(value['case_id']) ||
    typeof value['expires_at'] !== 'string'
  ) {
    return null;
  }
  return { session_token: value['session_token'], world_id: value['world_id'], case_id: value['case_id'] };
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

function renderModels(value: unknown): void {
  const target = document.getElementById('model-list');
  if (target === null) return;
  clearChildren(target);
  const models = isRecord(value) && Array.isArray(value['models']) ? value['models'] : [];
  const mandateActive = isRecord(value) && value['mandate_state'] === 'active';
  for (const candidate of models) {
    if (!isRecord(candidate) || !isRecord(candidate['approval'])) continue;
    const approval = candidate['approval'];
    const requestedId = typeof approval['requested_id'] === 'string' ? approval['requested_id'] : null;
    if (requestedId === null) continue;
    const item = text('article', '', 'model-card');
    item.append(text('h3', requestedId));
    item.append(
      text(
        'p',
        `Card ${String(approval['card_id'] ?? 'unknown')} v${String(approval['card_version'] ?? '?')} · ` +
          `card ${String(candidate['card_status'] ?? 'unknown')} · signature ${String(candidate['signature_status'] ?? 'unknown')}`,
      ),
    );
    const evidence = text('pre', JSON.stringify(candidate['current_card'] ?? candidate, null, 2), 'evidence');
    evidence.hidden = true;
    evidence.tabIndex = 0;
    const review = document.createElement('button');
    review.type = 'button';
    review.textContent = 'Review signed card evidence';
    const prepare = document.createElement('button');
    prepare.type = 'button';
    prepare.textContent = 'Prepare this model';
    prepare.disabled = true;
    const selectable =
      mandateActive &&
      candidate['signature_status'] === 'valid' &&
      candidate['integrity_alarm'] === false &&
      candidate['card_status'] !== 'withdrawn' &&
      candidate['current_card'] !== null;
    review.addEventListener('click', () => {
      evidence.hidden = false;
      prepare.disabled = !selectable;
      review.textContent = 'Evidence reviewed in this tab';
    });
    prepare.addEventListener('click', () => {
      sessionStorage.setItem(MODEL_STORAGE_KEY, requestedId);
      const output = document.getElementById('model-status');
      if (output !== null) {
        output.textContent = `${requestedId} is prepared for a later model interaction. No model request was sent.`;
      }
    });
    const actions = text('div', '', 'model-actions');
    actions.append(review, prepare);
    item.append(actions, evidence);
    if (!selectable) item.append(text('p', 'This model cannot be prepared from the current evidence state.'));
    target.append(item);
  }
  if (target.childElementCount === 0) target.append(text('p', 'No acting model evidence is available for this mandate.'));
}

export function shouldPollCaseState(value: unknown): boolean {
  return (
    isRecord(value) &&
    isRecord(value['dialogue']) &&
    value['dialogue']['status'] === 'open'
  );
}

function renderCaseState(value: unknown, config: RuntimeConsoleConfig): void {
  if (!isRecord(value)) throw new Error('invalid-case-state');
  const target = document.getElementById('case-state');
  const linkTarget = document.getElementById('dialogue-link');
  if (target === null || linkTarget === null) return;
  clearChildren(target);
  clearChildren(linkTarget);
  const ruling = isRecord(value['ruling']) ? value['ruling'] : null;
  if (ruling === null) {
    target.append(text('p', 'No ruling is currently mirrored for this case.'));
  } else {
    target.append(text('h3', `Ruling ${String(ruling['ruling_id'] ?? 'unknown')}`));
    target.append(text('p', String(ruling['reason'] ?? 'No ruling reason was provided.')));
    target.append(text('p', `Status: ${String(ruling['status'] ?? 'unknown')}`));
  }
  const dialogue = isRecord(value['dialogue']) ? value['dialogue'] : null;
  if (
    dialogue !== null &&
    typeof dialogue['response_url'] === 'string' &&
    typeof dialogue['escalation_id'] === 'string' &&
    OPAQUE_ID.test(dialogue['escalation_id'])
  ) {
    const responseUrl = new URL(dialogue['response_url']);
    const expectedPath = `/console/dialogue/${String(value['world_id'] ?? document.body.dataset['world'])}/${dialogue['escalation_id']}`;
    if (
      responseUrl.origin !== config.authorization_origin ||
      responseUrl.pathname !== expectedPath ||
      responseUrl.search !== '' ||
      responseUrl.hash !== ''
    ) {
      throw new Error('invalid-dialogue-link');
    }
    const link = document.createElement('a');
    link.href = responseUrl.href;
    link.target = '_blank';
    link.rel = 'noopener';
    link.textContent = dialogue['status'] === 'open'
      ? 'Respond in the governance console'
      : 'View the terminal dialogue in the governance console';
    linkTarget.append(link);
  }
}

async function loadCaseSurface(
  token: string,
  world: string,
  caseId: string,
  config: RuntimeConsoleConfig,
): Promise<void> {
  const models = await sameOriginGet(`/w/${world}/models`, token);
  renderModels(models);
  const refresh = async (): Promise<void> => {
    const state = await sameOriginGet(`/w/${world}/cases/${caseId}/state`, token);
    renderCaseState({ ...(isRecord(state) ? state : {}), world_id: world }, config);
    if (shouldPollCaseState(state)) window.setTimeout(() => void refresh().catch(() => status('Case-state polling was refused.')), 2_000);
  };
  await refresh();
}

async function mountCaseHandoffConsole(): Promise<void> {
  const opener = window.opener;
  if (opener === null) throw new Error('missing-opener');
  const configResponse = await fetch('/console/runtime-config.json', {
    cache: 'no-store',
    credentials: 'omit',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
  });
  const config = parseRuntimeConsoleConfig(await configResponse.json());
  if (!configResponse.ok || config === null || config.orchestrator_origin !== window.location.origin) {
    throw new Error('invalid-runtime-config');
  }

  await new Promise<void>((resolve, reject) => {
    const timeout = window.setTimeout(() => {
      window.removeEventListener('message', onMessage);
      window.opener = null;
      reject(new Error('handoff-timeout'));
    }, 30_000);
    const onMessage = (event: MessageEvent<unknown>) => {
      if (!acceptsHandoffTransfer(event, config.authorization_origin, opener, window.location.origin)) return;
      window.clearTimeout(timeout);
      window.removeEventListener('message', onMessage);
      window.opener = null;
      const handoff = event.data;
      void (async () => {
        const created = parseCreatedSession(
          await sameOriginJson(`/w/${handoff.world_id}/case-sessions/redeem`, {
            handoff_id: handoff.handoff_id,
            handoff_code: handoff.handoff_code,
            role: handoff.role,
            world_id: handoff.world_id,
            case_id: handoff.case_id,
            target_origin: handoff.target_origin,
            authorization_boot_id: handoff.authorization_boot_id,
          }),
        );
        if (created === null || created.world_id !== handoff.world_id || created.case_id !== handoff.case_id) {
          throw new Error('invalid-session-response');
        }
        sessionStorage.setItem(SESSION_STORAGE_KEY, created.session_token);
        document.body.dataset['world'] = created.world_id;
        document.body.dataset['case'] = created.case_id;
        const logout = document.getElementById('close-session');
        if (logout instanceof HTMLButtonElement) logout.disabled = false;
        const surface = document.getElementById('case-console');
        if (surface !== null) surface.hidden = false;
        status('Case session established for this tab. Loading approved-model evidence and gate state.');
        await loadCaseSurface(created.session_token, created.world_id, created.case_id, config);
        status('Case session ready.');
        resolve();
      })().catch(reject);
    };
    window.addEventListener('message', onMessage);
    opener.postMessage({ type: READY_TYPE }, config.authorization_origin);
  });

  document.getElementById('close-session')?.addEventListener('click', () => {
    void (async () => {
      const token = sessionStorage.getItem(SESSION_STORAGE_KEY);
      if (token === null) return;
      const world = document.body.dataset['world'];
      if (world === undefined || !WORLD_ID.test(world)) throw new Error('session-world-unavailable');
      await sameOriginJson(`/w/${world}/case-sessions/close`, {}, token);
      sessionStorage.removeItem(SESSION_STORAGE_KEY);
      sessionStorage.removeItem(MODEL_STORAGE_KEY);
      status('Case session closed.');
      const button = document.getElementById('close-session');
      if (button instanceof HTMLButtonElement) button.disabled = true;
    })().catch(() => status('Session close was refused.'));
  });
}

if (typeof document !== 'undefined') {
  mountCaseHandoffConsole().catch(() => {
    window.opener = null;
    status('The case-session handoff was refused. Return to the governance console and try again.');
  });
}
