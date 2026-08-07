// SPDX-License-Identifier: MIT
/** Orchestrator-origin receiver for ADR-002's exact-window handoff. */

const WORLD_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;
const OPAQUE_ID = /^[a-z0-9][a-z0-9_.:-]*$/;
const SECRET = /^[0-9a-f]{64,}$/;
const SESSION_STORAGE_KEY = 'runtime-case-session';
const READY_TYPE = 'runtime.case-handoff.ready';
const TRANSFER_TYPE = 'runtime.case-handoff.transfer';

interface BrowserModelTarget {
  readonly card_id: string;
  readonly card_version: number;
  readonly requested_id: string;
}

interface ActiveBrowserPreparation {
  readonly preparationId: string;
  readonly targetKey: string;
}

interface ActiveModelTurnPreparation {
  readonly preparationId: string;
  readonly turnId: string;
  readonly selectionId: string;
  readonly target: BrowserModelTarget;
}

export interface BrowserModelTurnStatus {
  readonly turn_id: string;
  readonly selection_id: string;
  readonly target: BrowserModelTarget;
  readonly state: 'prepared' | 'running' | 'quarantined' | 'withheld' | 'discarded' | 'failed';
  readonly provider_disclosure: 'none' | 'possible' | 'confirmed';
  readonly requested_id: string;
  readonly served_id: string | null;
  readonly terminal_reason: string | null;
  readonly quarantine: Record<string, unknown> | null;
}

let activePreparation: ActiveBrowserPreparation | null = null;
let preparationRequestSequence = 0;
let selectionOperationPending = false;
let activeModelTurnPreparation: ActiveModelTurnPreparation | null = null;
let modelTurnOperationPending = false;

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

function hasExactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
  const keys = Object.keys(value);
  const permitted = new Set([...required, ...optional]);
  return required.every((key) => Object.hasOwn(value, key)) && keys.every((key) => permitted.has(key));
}

function validTimestamp(value: unknown): value is string {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
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

function parseTarget(value: unknown): BrowserModelTarget | null {
  if (!isRecord(value) || Object.keys(value).length !== 3) return null;
  if (
    typeof value['card_id'] !== 'string' ||
    !OPAQUE_ID.test(value['card_id']) ||
    typeof value['card_version'] !== 'number' ||
    !Number.isSafeInteger(value['card_version']) ||
    value['card_version'] < 1 ||
    typeof value['requested_id'] !== 'string' ||
    value['requested_id'].length === 0
  ) {
    return null;
  }
  return {
    card_id: value['card_id'],
    card_version: value['card_version'],
    requested_id: value['requested_id'],
  };
}

function targetKey(target: BrowserModelTarget): string {
  return `${target.card_id}\u0000${target.card_version}\u0000${target.requested_id}`;
}

function containsHiddenSelectionBinding(value: unknown): boolean {
  if (Array.isArray(value)) return value.some(containsHiddenSelectionBinding);
  if (!isRecord(value)) return false;
  const forbidden = new Set([
    'check_id',
    'card_digest',
    'current_card_digest',
    'verifying_key_id',
    'system_use_decision',
    'policy_version',
    'policy_content_digest',
    'authenticated_actor',
    'call_id',
  ]);
  return Object.entries(value).some(([key, nested]) => forbidden.has(key) || containsHiddenSelectionBinding(nested));
}

function validRestrictionMap(value: unknown): boolean {
  return (
    isRecord(value) &&
    Object.entries(value).every(
      ([role, tags]) =>
        (role === 'acting' || role === 'screening') &&
        Array.isArray(tags) &&
        tags.every((tag) => typeof tag === 'string' && tag.length > 0),
    )
  );
}

function validBrowserEvidence(value: unknown): value is Record<string, unknown> {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'approval',
      'effective_data_classes',
      'card_status',
      'signature_status',
      'integrity_alarm',
      'current_card',
    ]) ||
    !isRecord(value['approval'])
  ) {
    return false;
  }
  const approval = value['approval'];
  const approvalTarget = parseTarget({
    card_id: approval['card_id'],
    card_version: approval['card_version'],
    requested_id: approval['requested_id'],
  });
  return (
    approvalTarget !== null &&
    hasExactKeys(approval, ['card_id', 'card_version', 'requested_id', 'roles', 'data_classes'], [
      're_confirmation_required',
    ]) &&
    Array.isArray(approval['roles']) &&
    approval['roles'].every((role) => role === 'acting' || role === 'screening') &&
    validRestrictionMap(approval['data_classes']) &&
    validRestrictionMap(value['effective_data_classes']) &&
    (value['card_status'] === 'current' ||
      value['card_status'] === 'superseded' ||
      value['card_status'] === 'withdrawn') &&
    (value['signature_status'] === 'valid' || value['signature_status'] === 'invalid') &&
    typeof value['integrity_alarm'] === 'boolean' &&
    (value['current_card'] === null || isRecord(value['current_card'])) &&
    (approval['re_confirmation_required'] === undefined ||
      typeof approval['re_confirmation_required'] === 'boolean')
  );
}

function parseBrowserTransition(value: unknown): BrowserModelTarget | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'selection_id',
      'kind',
      'predecessor_selection_id',
      'mandate_id',
      'mandate_version',
      'target',
      'selected_at',
      'authority_effect',
    ]) ||
    typeof value['selection_id'] !== 'string' ||
    !OPAQUE_ID.test(value['selection_id']) ||
    typeof value['mandate_id'] !== 'string' ||
    !OPAQUE_ID.test(value['mandate_id']) ||
    typeof value['mandate_version'] !== 'number' ||
    !Number.isSafeInteger(value['mandate_version']) ||
    value['mandate_version'] < 1 ||
    !validTimestamp(value['selected_at']) ||
    value['authority_effect'] !== 'none'
  ) {
    return null;
  }
  if (
    (value['kind'] === 'initial' && value['predecessor_selection_id'] !== null) ||
    (value['kind'] === 'switch' &&
      (typeof value['predecessor_selection_id'] !== 'string' ||
        !OPAQUE_ID.test(value['predecessor_selection_id']))) ||
    (value['kind'] !== 'initial' && value['kind'] !== 'switch')
  ) {
    return null;
  }
  return parseTarget(value['target']);
}

export function parseBrowserSelectionPreparation(
  value: unknown,
): { readonly preparation_id: string; readonly target: BrowserModelTarget; readonly evidence: unknown } | null {
  if (!isRecord(value) || !hasExactKeys(value, ['preparation', 'evidence']) || !isRecord(value['preparation'])) {
    return null;
  }
  const preparation = value['preparation'];
  if (
    !hasExactKeys(preparation, ['preparation_id', 'target', 'issued_at', 'expires_at']) ||
    typeof preparation['preparation_id'] !== 'string' ||
    !OPAQUE_ID.test(preparation['preparation_id']) ||
    !validTimestamp(preparation['issued_at']) ||
    !validTimestamp(preparation['expires_at']) ||
    Date.parse(preparation['issued_at']) >= Date.parse(preparation['expires_at']) ||
    containsHiddenSelectionBinding(value)
  ) {
    return null;
  }
  const target = parseTarget(preparation['target']);
  if (target === null || !validBrowserEvidence(value['evidence'])) return null;
  return { preparation_id: preparation['preparation_id'], target, evidence: value['evidence'] };
}

export function parseBrowserCurrentSelection(
  value: unknown,
): { readonly state: 'unselected' | 'selected'; readonly target: BrowserModelTarget | null } | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['state', 'case_id', 'selection', 'latest_observation']) ||
    typeof value['case_id'] !== 'string' ||
    !OPAQUE_ID.test(value['case_id']) ||
    containsHiddenSelectionBinding(value)
  ) {
    return null;
  }
  if (value['state'] === 'unselected' && value['selection'] === null && value['latest_observation'] === null) {
    return { state: 'unselected', target: null };
  }
  if (value['state'] !== 'selected') return null;
  if (value['latest_observation'] !== null) {
    const observation = value['latest_observation'];
    if (
      !isRecord(observation) ||
      !hasExactKeys(observation, ['served_id', 'model_resolution', 'terminal_outcome', 'observed_at']) ||
      typeof observation['served_id'] !== 'string' ||
      observation['served_id'].length === 0 ||
      (observation['model_resolution'] !== 'exact' &&
        observation['model_resolution'] !== 'benign-resolution' &&
        observation['model_resolution'] !== 'mismatch') ||
      (observation['terminal_outcome'] !== 'admitted' &&
        observation['terminal_outcome'] !== 'withheld' &&
        observation['terminal_outcome'] !== 'failed') ||
      !validTimestamp(observation['observed_at'])
    ) {
      return null;
    }
  }
  const target = parseBrowserTransition(value['selection']);
  return target === null ? null : { state: 'selected', target };
}

export function parseBrowserSelectionResult(
  value: unknown,
): { readonly selection_id: string; readonly target: BrowserModelTarget } | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['selection', 'invalidated_ruling_count', 'terminalized_open_call_count']) ||
    !isRecord(value['selection']) ||
    !Number.isSafeInteger(value['invalidated_ruling_count']) ||
    Number(value['invalidated_ruling_count']) < 0 ||
    !Number.isSafeInteger(value['terminalized_open_call_count']) ||
    Number(value['terminalized_open_call_count']) < 0 ||
    containsHiddenSelectionBinding(value)
  ) {
    return null;
  }
  const selectionId = value['selection']['selection_id'];
  const target = parseBrowserTransition(value['selection']);
  if (typeof selectionId !== 'string' || !OPAQUE_ID.test(selectionId) || target === null) return null;
  return { selection_id: selectionId, target };
}

export function parseBrowserModelTurnPreparation(value: unknown): ActiveModelTurnPreparation | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ['preparation_id', 'turn_id', 'selection_id', 'target', 'issued_at', 'expires_at']) ||
    typeof value['preparation_id'] !== 'string' ||
    !OPAQUE_ID.test(value['preparation_id']) ||
    typeof value['turn_id'] !== 'string' ||
    !OPAQUE_ID.test(value['turn_id']) ||
    typeof value['selection_id'] !== 'string' ||
    !OPAQUE_ID.test(value['selection_id']) ||
    !validTimestamp(value['issued_at']) ||
    !validTimestamp(value['expires_at']) ||
    Date.parse(value['issued_at']) >= Date.parse(value['expires_at'])
  ) {
    return null;
  }
  const target = parseTarget(value['target']);
  return target === null
    ? null
    : {
        preparationId: value['preparation_id'],
        turnId: value['turn_id'],
        selectionId: value['selection_id'],
        target,
      };
}

const MODEL_TURN_STATES = new Set(['prepared', 'running', 'quarantined', 'withheld', 'discarded', 'failed']);
const DISCLOSURE_STATES = new Set(['none', 'possible', 'confirmed']);
const TERMINAL_REASONS = new Set([
  'authorization-refused',
  'provider-failure',
  'provider-protocol',
  'quarantine-capacity',
  'admission-binding-invalid',
  'lane-unconfigured',
  'lane-halted',
  'lane-busy',
  'turn-replay',
  'output-withheld',
  'selection-changed',
  'session-ended',
  'runtime-failure',
]);

export function parseBrowserModelTurnStatus(value: unknown): BrowserModelTurnStatus | null {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'turn_id',
      'selection_id',
      'target',
      'state',
      'provider_disclosure',
      'requested_id',
      'served_id',
      'terminal_reason',
      'quarantine',
    ]) ||
    typeof value['turn_id'] !== 'string' ||
    !OPAQUE_ID.test(value['turn_id']) ||
    typeof value['selection_id'] !== 'string' ||
    !OPAQUE_ID.test(value['selection_id']) ||
    typeof value['state'] !== 'string' ||
    !MODEL_TURN_STATES.has(value['state']) ||
    typeof value['provider_disclosure'] !== 'string' ||
    !DISCLOSURE_STATES.has(value['provider_disclosure']) ||
    typeof value['requested_id'] !== 'string' ||
    value['requested_id'].length === 0 ||
    (value['served_id'] !== null && (typeof value['served_id'] !== 'string' || value['served_id'].length === 0)) ||
    (value['terminal_reason'] !== null &&
      (typeof value['terminal_reason'] !== 'string' || !TERMINAL_REASONS.has(value['terminal_reason'])))
  ) {
    return null;
  }
  const target = parseTarget(value['target']);
  if (target === null || target.requested_id !== value['requested_id']) return null;
  let quarantine: Record<string, unknown> | null = null;
  if (value['quarantine'] !== null) {
    if (
      !isRecord(value['quarantine']) ||
      !hasExactKeys(value['quarantine'], [
        'release_state',
        'call_id',
        'projection_digest',
        'output_digest',
        'derived_tags',
      ]) ||
      value['quarantine']['release_state'] !== 'sealed-no-release-path' ||
      typeof value['quarantine']['call_id'] !== 'string' ||
      !OPAQUE_ID.test(value['quarantine']['call_id']) ||
      typeof value['quarantine']['projection_digest'] !== 'string' ||
      !/^[0-9a-f]{64}$/.test(value['quarantine']['projection_digest']) ||
      typeof value['quarantine']['output_digest'] !== 'string' ||
      !/^[0-9a-f]{64}$/.test(value['quarantine']['output_digest']) ||
      !Array.isArray(value['quarantine']['derived_tags']) ||
      !value['quarantine']['derived_tags'].every((tag) => typeof tag === 'string' && tag.length > 0)
    ) {
      return null;
    }
    quarantine = value['quarantine'];
  }
  const state = value['state'] as BrowserModelTurnStatus['state'];
  const disclosure = value['provider_disclosure'] as BrowserModelTurnStatus['provider_disclosure'];
  const terminal = state === 'quarantined' || state === 'withheld' || state === 'discarded' || state === 'failed';
  if (
    (state === 'quarantined') !== (quarantine !== null) ||
    (state === 'quarantined' && disclosure !== 'confirmed') ||
    (value['served_id'] !== null && disclosure !== 'confirmed') ||
    (terminal !== (value['terminal_reason'] !== null || state === 'quarantined'))
  ) {
    return null;
  }
  return {
    turn_id: value['turn_id'],
    selection_id: value['selection_id'],
    target,
    state,
    provider_disclosure: disclosure,
    requested_id: value['requested_id'],
    served_id: value['served_id'] as string | null,
    terminal_reason: value['terminal_reason'] as string | null,
    quarantine,
  };
}

function renderModelTurnStatus(value: BrowserModelTurnStatus): void {
  const statusTarget = document.getElementById('model-turn-status');
  const metadata = document.getElementById('model-turn-metadata');
  if (statusTarget !== null) {
    statusTarget.textContent =
      `Run ${value.turn_id}: ${value.state}; provider disclosure ${value.provider_disclosure}. ` +
      'No response content is available on this surface.';
  }
  if (metadata !== null) {
    metadata.textContent = JSON.stringify(value, null, 2);
    metadata.hidden = false;
  }
}

function clearModelTurnSurface(message: string): void {
  activeModelTurnPreparation = null;
  const statusTarget = document.getElementById('model-turn-status');
  const metadata = document.getElementById('model-turn-metadata');
  if (statusTarget !== null) statusTarget.textContent = message;
  if (metadata !== null) {
    metadata.textContent = '';
    metadata.hidden = true;
  }
}

function configureModelTurnControls(
  current: ReturnType<typeof parseBrowserCurrentSelection>,
  token: string,
  world: string,
  caseId: string,
): void {
  const prepare = document.getElementById('prepare-model-turn');
  const use = document.getElementById('use-model-turn');
  const output = document.getElementById('model-turn-status');
  if (!(prepare instanceof HTMLButtonElement) || !(use instanceof HTMLButtonElement) || current === null) return;
  if (current.state !== 'selected' || current.target === null) {
    activeModelTurnPreparation = null;
    prepare.disabled = true;
    use.disabled = true;
    if (output !== null) output.textContent = 'Select a model before preparing a run.';
    return;
  }
  const currentTarget = current.target;
  if (
    activeModelTurnPreparation !== null &&
    targetKey(activeModelTurnPreparation.target) !== targetKey(currentTarget)
  ) {
    activeModelTurnPreparation = null;
  }
  prepare.disabled = modelTurnOperationPending;
  use.disabled = modelTurnOperationPending || activeModelTurnPreparation === null;
  prepare.onclick = () => {
    if (modelTurnOperationPending) return;
    modelTurnOperationPending = true;
    activeModelTurnPreparation = null;
    prepare.disabled = true;
    use.disabled = true;
    if (output !== null) output.textContent = 'Preparing a single model run.';
    void (async () => {
      const parsed = parseBrowserModelTurnPreparation(
        await sameOriginJson(`/w/${world}/cases/${caseId}/model-turn-preparations`, {}, token),
      );
      if (parsed === null || targetKey(parsed.target) !== targetKey(currentTarget)) {
        throw new Error('invalid-model-turn-preparation');
      }
      activeModelTurnPreparation = parsed;
      if (output !== null) {
        output.textContent = 'Run prepared. Confirm the second step to contact the selected provider.';
      }
    })()
      .catch(() => {
        if (output !== null) output.textContent = 'The model run could not be prepared.';
      })
      .finally(() => {
        modelTurnOperationPending = false;
        prepare.disabled = false;
        use.disabled = activeModelTurnPreparation === null;
      });
  };
  use.onclick = () => {
    if (modelTurnOperationPending) return;
    const prepared = activeModelTurnPreparation;
    activeModelTurnPreparation = null;
    if (prepared === null) return;
    modelTurnOperationPending = true;
    prepare.disabled = true;
    use.disabled = true;
    if (output !== null) output.textContent = 'Running the selected model. No response content will be shown.';
    void (async () => {
      let raw: unknown;
      try {
        raw = await sameOriginJson(
          `/w/${world}/cases/${caseId}/model-turns`,
          { preparation_id: prepared.preparationId },
          token,
        );
      } catch {
        raw = await sameOriginGet(`/w/${world}/cases/${caseId}/model-turns/${prepared.turnId}`, token);
      }
      const result = parseBrowserModelTurnStatus(raw);
      if (
        result === null ||
        result.turn_id !== prepared.turnId ||
        result.selection_id !== prepared.selectionId ||
        targetKey(result.target) !== targetKey(prepared.target)
      ) {
        throw new Error('invalid-model-turn-status');
      }
      renderModelTurnStatus(result);
    })()
      .catch(() => {
        if (output !== null) {
          output.textContent = 'The run outcome could not be recovered. It was not retried.';
        }
      })
      .finally(() => {
        modelTurnOperationPending = false;
        prepare.disabled = false;
      });
  };
}

function disableSelectionControls(): void {
  activePreparation = null;
  for (const candidate of document.querySelectorAll<HTMLButtonElement>('button[data-model-select]')) {
    candidate.disabled = true;
  }
}

function renderModels(
  value: unknown,
  currentValue: unknown,
  token: string,
  world: string,
  caseId: string,
  reload: () => Promise<void>,
): void {
  const target = document.getElementById('model-list');
  if (target === null) return;
  preparationRequestSequence += 1;
  selectionOperationPending = false;
  activePreparation = null;
  clearChildren(target);
  const models = isRecord(value) && Array.isArray(value['models']) ? value['models'] : [];
  const mandateActive = isRecord(value) && value['mandate_state'] === 'active';
  const defaultTarget = isRecord(value) ? parseTarget(value['default_acting_model']) : null;
  const current = parseBrowserCurrentSelection(currentValue);
  if (defaultTarget === null || current === null) throw new Error('invalid-model-selection-projection');
  const currentKey = current.target === null ? null : targetKey(current.target);
  const defaultKey = targetKey(defaultTarget);
  const selectionStatus = document.getElementById('model-status');
  if (selectionStatus !== null) {
    selectionStatus.textContent = current.target === null
      ? `No model is selected. The mandate default is ${defaultTarget.requested_id}.`
      : `${current.target.requested_id} is the authorization-owned current selection.`;
  }
  for (const candidate of models) {
    if (!isRecord(candidate) || !isRecord(candidate['approval'])) continue;
    const approval = candidate['approval'];
    const modelTarget = parseTarget({
      card_id: approval['card_id'],
      card_version: approval['card_version'],
      requested_id: approval['requested_id'],
    });
    if (modelTarget === null) continue;
    const requestedId = modelTarget.requested_id;
    const modelKey = targetKey(modelTarget);
    const isCurrent = currentKey === modelKey;
    const isDefault = defaultKey === modelKey;
    const item = text('article', '', 'model-card');
    item.append(text('h3', `${requestedId}${isCurrent ? ' · current' : ''}${isDefault ? ' · mandate default' : ''}`));
    item.append(
      text(
        'p',
        `Card ${String(approval['card_id'] ?? 'unknown')} v${String(approval['card_version'] ?? '?')} · ` +
          `card ${String(candidate['card_status'] ?? 'unknown')} · signature ${String(candidate['signature_status'] ?? 'unknown')}`,
      ),
    );
    const evidence = text('pre', 'Request current signed-card evidence before selecting.', 'evidence');
    evidence.hidden = true;
    evidence.tabIndex = 0;
    const review = document.createElement('button');
    review.type = 'button';
    review.textContent = 'Review current evidence';
    const select = document.createElement('button');
    select.type = 'button';
    select.textContent = 'Select this model for the case';
    select.dataset['modelSelect'] = 'true';
    select.disabled = true;
    const selectable =
      mandateActive &&
      candidate['signature_status'] === 'valid' &&
      candidate['integrity_alarm'] === false &&
      candidate['card_status'] !== 'withdrawn' &&
      candidate['current_card'] !== null &&
      !isCurrent &&
      (current.state === 'selected' || isDefault);
    if (!selectable) review.disabled = true;
    review.addEventListener('click', () => {
      if (selectionOperationPending) return;
      selectionOperationPending = true;
      const requestSequence = ++preparationRequestSequence;
      void (async () => {
        disableSelectionControls();
        const output = document.getElementById('model-status');
        if (output !== null) output.textContent = `Refreshing evidence for ${requestedId}.`;
        const parsed = parseBrowserSelectionPreparation(
          await sameOriginJson(
            `/w/${world}/cases/${caseId}/model-selection-preparations`,
            { target: modelTarget },
            token,
          ),
        );
        if (parsed === null || targetKey(parsed.target) !== modelKey) throw new Error('invalid-preparation-response');
        if (requestSequence !== preparationRequestSequence) return;
        evidence.textContent = JSON.stringify(parsed.evidence, null, 2);
        evidence.hidden = false;
        activePreparation = { preparationId: parsed.preparation_id, targetKey: modelKey };
        select.disabled = false;
        review.textContent = 'Current evidence refreshed in this tab';
        if (output !== null) {
          output.textContent = `Evidence refreshed for ${requestedId}. Select within two minutes or refresh again.`;
        }
      })()
        .catch(() => {
          if (requestSequence !== preparationRequestSequence) return;
          disableSelectionControls();
          const output = document.getElementById('model-status');
          if (output !== null) output.textContent = `Current evidence for ${requestedId} could not be prepared.`;
        })
        .finally(() => {
          if (requestSequence === preparationRequestSequence) selectionOperationPending = false;
        });
    });
    select.addEventListener('click', () => {
      if (selectionOperationPending) return;
      selectionOperationPending = true;
      void (async () => {
        const prepared = activePreparation;
        preparationRequestSequence += 1;
        disableSelectionControls();
        if (prepared === null || prepared.targetKey !== modelKey) throw new Error('preparation-unavailable');
        const selected = parseBrowserSelectionResult(
          await sameOriginJson(
            `/w/${world}/cases/${caseId}/model-selections`,
            { preparation_id: prepared.preparationId },
            token,
          ),
        );
        if (selected === null || targetKey(selected.target) !== modelKey) throw new Error('invalid-selection-response');
        const output = document.getElementById('model-status');
        if (output !== null) {
          output.textContent = `${requestedId} is selected for this case. No model request was sent.`;
        }
        clearModelTurnSurface('The model selection changed. Prepare a new run for the new selection.');
        await reload();
      })()
        .catch(async () => {
          disableSelectionControls();
          const output = document.getElementById('model-status');
          if (output !== null) {
            output.textContent = 'Selection was not confirmed. Current state is being recovered from authorization.';
          }
          await reload().catch(() => status('Current model selection could not be recovered.'));
        })
        .finally(() => {
          selectionOperationPending = false;
        });
    });
    const actions = text('div', '', 'model-actions');
    actions.append(review, select);
    item.append(actions, evidence);
    if (isCurrent) item.append(text('p', 'This is the current selection; no-op re-selection is unavailable.'));
    else if (current.state === 'unselected' && !isDefault) {
      item.append(text('p', 'The mandate default must be selected before switching to this model.'));
    } else if (!selectable) item.append(text('p', 'This model cannot be selected from the current evidence state.'));
    target.append(item);
  }
  if (target.childElementCount === 0) target.append(text('p', 'No acting model evidence is available for this mandate.'));
  configureModelTurnControls(current, token, world, caseId);
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
  const refreshModels = async (): Promise<void> => {
    const [models, current] = await Promise.all([
      sameOriginGet(`/w/${world}/models`, token),
      sameOriginGet(`/w/${world}/cases/${caseId}/model-selection`, token),
    ]);
    renderModels(models, current, token, world, caseId, refreshModels);
  };
  await refreshModels();
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
      preparationRequestSequence += 1;
      selectionOperationPending = true;
      activeModelTurnPreparation = null;
      modelTurnOperationPending = true;
      disableSelectionControls();
      const prepareRun = document.getElementById('prepare-model-turn');
      const useRun = document.getElementById('use-model-turn');
      if (prepareRun instanceof HTMLButtonElement) prepareRun.disabled = true;
      if (useRun instanceof HTMLButtonElement) useRun.disabled = true;
      clearModelTurnSurface('Case session closed; no retained model output remains available.');
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
