/**
 * Client WebSocket WSS de télémétrie.
 *
 * Sécurité :
 * - Seul le schéma `wss:` est accepté (aucun `ws:` en clair).
 * - Le jeton n'est JAMAIS placé dans l'URL (pas de query string) : il est envoyé
 *   dans le PREMIER message binaire/textuel après l'ouverture, avant toute
 *   souscription. Un jeton absent interrompt la connexion.
 * - Reconnexion exponentielle avec back-off plafonné et gigue, nombre de
 *   tentatives borné. Les fermetures d'authentification (1008/4001/4003)
 *   n'entraînent aucune reconnexion automatique.
 * - Les messages sont parsés défensivement ; un message malformé est ignoré.
 */

export type SocketStatus =
  | 'idle'
  | 'connecting'
  | 'authenticating'
  | 'live'
  | 'reconnecting'
  | 'closed'
  | 'error';

export type AnomalySeverity = 'NORMAL' | 'WARNING' | 'CRITICAL';

/** Diagnostic du détecteur d'anomalies (Isolation Forest + signatures de pannes). */
export interface AnomalyDiagnosis {
  isAnomaly: boolean;
  severity: AnomalySeverity;
  score: number;
  diagnosis: string | null;
}

export interface TelemetrySample {
  furnaceTempC: number | null;
  glassThicknessMm: number | null;
  lineSpeedMps: number | null;
  timestamp: string | null;
  zonesC?: number[] | undefined;
  glassTempC?: number | null;
  quenchPressureBar?: number | null;
  powerKw?: number | null;
  /** Absent = pas de diagnostic disponible (jamais présenté comme « normal »). */
  anomaly?: AnomalyDiagnosis | null;
}

export interface SocketStatusDetail {
  attempt: number;
  nextRetryMs: number | null;
  error: string | null;
}

export interface TelemetrySocketHandlers {
  onStatus: (status: SocketStatus, detail: SocketStatusDetail) => void;
  onSample: (sample: TelemetrySample) => void;
}

export interface SocketLike {
  readonly readyState: number;
  send(data: string): void;
  close(code?: number, reason?: string): void;
  onopen: ((event: Event) => void) | null;
  onmessage: ((event: MessageEvent<unknown>) => void) | null;
  onerror: ((event: Event) => void) | null;
  onclose: ((event: CloseEvent) => void) | null;
}

export interface TelemetrySocket {
  readonly status: SocketStatus;
  connect: (getToken: () => string | null) => void;
  disconnect: () => void;
}

export interface TelemetrySocketOptions extends TelemetrySocketHandlers {
  url: string;
  factory?: (url: string) => SocketLike;
  baseDelayMs?: number;
  maxDelayMs?: number;
  maxAttempts?: number;
  random?: () => number;
}

const AUTH_CLOSE_CODES: ReadonlySet<number> = new Set([1008, 4001, 4003]);
const FORBIDDEN_URL_KEYS = ['token', 'access_token', 'jwt', 'authorization'];

export function assertSecureWssUrl(rawUrl: string): URL {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error('URL WSS invalide');
  }
  const loopbackDev =
    url.protocol === 'ws:' &&
    ['localhost', '127.0.0.1', '[::1]', '::1'].includes(url.hostname);
  if (url.protocol !== 'wss:' && !loopbackDev) {
    throw new Error('WSS requis : le schéma ws: en clair est interdit');
  }
  if (url.username.length > 0 || url.password.length > 0) {
    throw new Error('Identifiants interdits dans l’URL WSS');
  }
  if (url.hash.length > 0) {
    throw new Error('Fragment interdit dans l’URL WSS');
  }
  for (const key of FORBIDDEN_URL_KEYS) {
    if (url.searchParams.has(key)) {
      throw new Error('Le jeton ne doit jamais figurer dans l’URL WSS');
    }
  }
  return url;
}

function numberOrNull(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

export function parseAnomaly(raw: unknown): AnomalyDiagnosis | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return null;
  }
  const record = raw as Record<string, unknown>;
  const severity = record['severity'];
  if (severity !== 'NORMAL' && severity !== 'WARNING' && severity !== 'CRITICAL') {
    return null;
  }
  return {
    isAnomaly: record['is_anomaly'] === true,
    severity,
    score: numberOrNull(record['score']) ?? 0,
    diagnosis:
      typeof record['diagnosis'] === 'string' ? record['diagnosis'] : null,
  };
}

function parseZones(raw: unknown): number[] | undefined {
  if (!Array.isArray(raw)) {
    return undefined;
  }
  const zones = raw.map(numberOrNull);
  return zones.every((z): z is number => z !== null) ? zones : undefined;
}

export function parseTelemetryPayload(raw: unknown): TelemetrySample | null {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
    return null;
  }
  const payload = raw as Record<string, unknown>;
  return {
    furnaceTempC: numberOrNull(payload['furnace_temp_c']),
    glassThicknessMm: numberOrNull(payload['glass_thickness_mm']),
    lineSpeedMps: numberOrNull(payload['line_speed_mps']),
    timestamp:
      typeof payload['timestamp'] === 'string' ? payload['timestamp'] : null,
    ...(payload['zones_c'] !== undefined
      ? { zonesC: parseZones(payload['zones_c']) }
      : {}),
    ...(payload['glass_temp_c'] !== undefined
      ? { glassTempC: numberOrNull(payload['glass_temp_c']) }
      : {}),
    ...(payload['quench_pressure_bar'] !== undefined
      ? { quenchPressureBar: numberOrNull(payload['quench_pressure_bar']) }
      : {}),
    ...(payload['power_kw'] !== undefined
      ? { powerKw: numberOrNull(payload['power_kw']) }
      : {}),
    ...(payload['anomaly'] !== undefined
      ? { anomaly: parseAnomaly(payload['anomaly']) }
      : {}),
  };
}

interface ParsedFrame {
  type: string;
  raw: Record<string, unknown>;
}

function parseFrame(data: unknown): ParsedFrame | null {
  if (typeof data !== 'string') {
    return null;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(data) as unknown;
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return null;
  }
  const record = parsed as Record<string, unknown>;
  const type = record['type'];
  if (typeof type !== 'string') {
    return null;
  }
  return { type, raw: record };
}

export function createUnavailableTelemetrySocket(
  error: string,
  handlers: TelemetrySocketHandlers,
): TelemetrySocket {
  let status: SocketStatus = 'idle';
  return {
    get status(): SocketStatus {
      return status;
    },
    connect() {
      status = 'error';
      handlers.onStatus('error', { attempt: 0, nextRetryMs: null, error });
    },
    disconnect() {
      status = 'closed';
    },
  };
}

export function createTelemetrySocket(
  options: TelemetrySocketOptions,
): TelemetrySocket {
  const validatedUrl = assertSecureWssUrl(options.url);
  const url = validatedUrl.toString();
  const factory =
    options.factory ??
    ((target: string) => new WebSocket(target) as unknown as SocketLike);
  const baseDelayMs = options.baseDelayMs ?? 500;
  const maxDelayMs = options.maxDelayMs ?? 15_000;
  const maxAttempts = options.maxAttempts ?? 6;
  const random = options.random ?? Math.random;
  const { onStatus, onSample } = options;

  let socket: SocketLike | null = null;
  let status: SocketStatus = 'idle';
  let attempt = 0;
  let timer: ReturnType<typeof setTimeout> | null = null;
  let manualClose = false;
  let terminal = false;
  let getToken: (() => string | null) | null = null;

  function emit(
    next: SocketStatus,
    detail: Partial<SocketStatusDetail> = {},
  ): void {
    status = next;
    onStatus(next, {
      attempt: detail.attempt ?? attempt,
      nextRetryMs: detail.nextRetryMs ?? null,
      error: detail.error ?? null,
    });
  }

  function clearTimer(): void {
    if (timer !== null) {
      clearTimeout(timer);
      timer = null;
    }
  }

  function scheduleReconnect(): void {
    if (attempt >= maxAttempts) {
      terminal = true;
      emit('error', {
        error: `Connexion WSS interrompue après ${maxAttempts} tentatives.`,
      });
      return;
    }
    const exponential = Math.min(maxDelayMs, baseDelayMs * 2 ** attempt);
    const jittered = Math.round(exponential * (0.8 + random() * 0.4));
    attempt += 1;
    emit('reconnecting', { attempt, nextRetryMs: jittered });
    timer = setTimeout(() => {
      timer = null;
      open();
    }, jittered);
  }

  function handleClose(ws: SocketLike, event: CloseEvent): void {
    if (socket === ws) {
      socket = null;
    }
    if (manualClose) {
      return;
    }
    if (terminal) {
      return;
    }
    if (AUTH_CLOSE_CODES.has(event.code)) {
      terminal = true;
      emit('error', {
        attempt,
        error: 'Authentification WSS refusée par le serveur.',
      });
      return;
    }
    scheduleReconnect();
  }

  function handleMessage(ws: SocketLike, event: MessageEvent<unknown>): void {
    const frame = parseFrame(event.data);
    if (frame === null) {
      return;
    }
    if (frame.type === 'auth_ok') {
      attempt = 0;
      emit('live');
      ws.send(JSON.stringify({ type: 'subscribe', channels: ['telemetry'] }));
      return;
    }
    if (frame.type === 'auth_error') {
      terminal = true;
      emit('error', { error: 'Authentification WSS refusée par le serveur.' });
      ws.close(1008, 'auth failed');
      return;
    }
    if (frame.type === 'telemetry' && status === 'live') {
      const sample = parseTelemetryPayload(frame.raw['payload']);
      if (sample !== null) {
        onSample(sample);
      }
    }
  }

  function open(): void {
    emit(attempt === 0 ? 'connecting' : 'reconnecting');
    let ws: SocketLike;
    try {
      ws = factory(url);
    } catch {
      terminal = true;
      emit('error', { error: 'Impossible d’ouvrir la connexion WSS.' });
      return;
    }
    socket = ws;

    ws.onopen = () => {
      const token = getToken?.() ?? null;
      if (token === null || token.length === 0) {
        terminal = true;
        emit('error', { error: 'Jeton absent : connexion WSS refusée.' });
        ws.close(1008, 'no token');
        return;
      }
      emit('authenticating');
      // PREMIER message envoyé : authentification. Jamais dans l'URL.
      ws.send(JSON.stringify({ type: 'auth', token }));
    };

    ws.onmessage = (event) => {
      handleMessage(ws, event);
    };

    ws.onerror = () => {
      // La fermeture qui suit déclenche la politique de reconnexion.
    };

    ws.onclose = (event) => {
      handleClose(ws, event);
    };
  }

  return {
    get status(): SocketStatus {
      return status;
    },
    connect(getTokenFn: () => string | null) {
      if (socket !== null) {
        return;
      }
      clearTimer();
      getToken = getTokenFn;
      manualClose = false;
      terminal = false;
      attempt = 0;
      const token = getTokenFn();
      if (token === null || token.length === 0) {
        terminal = true;
        emit('error', { error: 'Session absente : connexion WSS impossible.' });
        return;
      }
      open();
    },
    disconnect() {
      manualClose = true;
      clearTimer();
      const current = socket;
      socket = null;
      if (current !== null) {
        current.close(1000, 'client disconnect');
      }
      emit('closed');
    },
  };
}
