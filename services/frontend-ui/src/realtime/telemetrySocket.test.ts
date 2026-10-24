import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  assertSecureWssUrl,
  createTelemetrySocket,
  type SocketLike,
  type SocketStatus,
  type SocketStatusDetail,
  type TelemetrySample,
  type TelemetrySocket,
  type TelemetrySocketOptions,
} from './telemetrySocket';

class FakeWebSocket implements SocketLike {
  static instances: FakeWebSocket[] = [];

  readonly url: string;
  readyState = 0;
  sent: string[] = [];
  onopen: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent<unknown>) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onclose: ((event: CloseEvent) => void) | null = null;

  constructor(url: string) {
    this.url = url;
    FakeWebSocket.instances.push(this);
  }

  send(data: string): void {
    this.sent.push(data);
  }

  close(code = 1000, reason = ''): void {
    this.readyState = 3;
    this.onclose?.({ code, reason } as CloseEvent);
  }

  simulateOpen(): void {
    this.readyState = 1;
    this.onopen?.(new Event('open'));
  }

  simulateMessage(payload: unknown): void {
    const data = typeof payload === 'string' ? payload : JSON.stringify(payload);
    this.onmessage?.({ data } as MessageEvent<unknown>);
  }

  simulateClose(code = 1006): void {
    this.readyState = 3;
    this.onclose?.({ code, reason: '' } as CloseEvent);
  }
}

interface Harness {
  socket: TelemetrySocket;
  statuses: Array<{ status: SocketStatus; detail: SocketStatusDetail }>;
  samples: TelemetrySample[];
  latest: () => FakeWebSocket;
  options: TelemetrySocketOptions;
}

function createHarness(
  overrides: Partial<TelemetrySocketOptions> = {},
  token: string | null = 'secret-token',
): Harness {
  FakeWebSocket.instances = [];
  const statuses: Harness['statuses'] = [];
  const samples: TelemetrySample[] = [];
  const options: TelemetrySocketOptions = {
    url: 'wss://factory.example.test/ws/telemetry',
    factory: (url) => new FakeWebSocket(url),
    onStatus: (status, detail) => {
      statuses.push({ status, detail });
    },
    onSample: (sample) => {
      samples.push(sample);
    },
    baseDelayMs: 500,
    maxDelayMs: 4000,
    maxAttempts: 2,
    random: () => 0.5,
  };
  const socket = createTelemetrySocket({ ...options, ...overrides });
  socket.connect(() => token);
  return {
    socket,
    statuses,
    samples,
    latest: () => {
      const latest = FakeWebSocket.instances[FakeWebSocket.instances.length - 1];
      if (latest === undefined) {
        throw new Error('aucun socket factice');
      }
      return latest;
    },
    options,
  };
}

function lastStatus(harness: Harness): SocketStatus {
  return harness.statuses[harness.statuses.length - 1]?.status ?? 'idle';
}

describe('sécurité de l’URL WSS', () => {
  it('accepte une URL wss sans secret', () => {
    expect(assertSecureWssUrl('wss://factory.example.test/ws').protocol).toBe('wss:');
  });

  it('accepte ws: uniquement en bouclage (développement)', () => {
    expect(() => assertSecureWssUrl('ws://localhost:5173/ws/telemetry')).not.toThrow();
    expect(() => assertSecureWssUrl('ws://127.0.0.1:5173/ws/telemetry')).not.toThrow();
    expect(() => assertSecureWssUrl('ws://10.0.0.5/ws')).toThrow(/WSS/);
  });

  it('refuse ws: en clair', () => {
    expect(() => assertSecureWssUrl('ws://factory.example.test/ws')).toThrow(/WSS/);
  });

  it('refuse un jeton dans la query string', () => {
    expect(() =>
      assertSecureWssUrl('wss://factory.example.test/ws?token=secret'),
    ).toThrow(/jamais/);
  });

  it('refuse les identifiants et le fragment', () => {
    expect(() => assertSecureWssUrl('wss://user:pass@host/ws')).toThrow(/Identifiants/);
    expect(() => assertSecureWssUrl('wss://host/ws#token')).toThrow(/Fragment/);
    expect(() => assertSecureWssUrl('pas-une-url')).toThrow(/invalide/);
  });
});

describe('client WSS — authentification et messages', () => {
  it('transmet le jeton dans le PREMIER message, jamais dans l’URL', () => {
    const harness = createHarness();
    const ws = harness.latest();

    expect(ws.url).toBe('wss://factory.example.test/ws/telemetry');
    expect(ws.url).not.toContain('secret-token');

    ws.simulateOpen();

    expect(ws.sent).toHaveLength(1);
    expect(JSON.parse(ws.sent[0] ?? '{}')).toEqual({
      type: 'auth',
      token: 'secret-token',
    });
    expect(lastStatus(harness)).toBe('authenticating');
  });

  it('passe en live et souscrit uniquement après auth_ok', () => {
    const harness = createHarness();
    const ws = harness.latest();
    ws.simulateOpen();
    ws.simulateMessage({ type: 'auth_ok' });

    expect(lastStatus(harness)).toBe('live');
    expect(ws.sent).toHaveLength(2);
    expect(JSON.parse(ws.sent[1] ?? '{}')).toEqual({
      type: 'subscribe',
      channels: ['telemetry'],
    });
  });

  it('ignore la télémétrie avant authentification puis l’accepte en live', () => {
    const harness = createHarness();
    const ws = harness.latest();
    ws.simulateOpen();
    ws.simulateMessage({
      type: 'telemetry',
      payload: { furnace_temp_c: 700 },
    });
    expect(harness.samples).toHaveLength(0);

    ws.simulateMessage({ type: 'auth_ok' });
    ws.simulateMessage({
      type: 'telemetry',
      payload: {
        furnace_temp_c: 712.5,
        glass_thickness_mm: 6,
        line_speed_mps: 1.2,
        timestamp: '2026-10-24T10:20:00Z',
      },
    });

    expect(harness.samples).toHaveLength(1);
    expect(harness.samples[0]?.furnaceTempC).toBe(712.5);
    expect(harness.samples[0]?.glassThicknessMm).toBe(6);
  });

  it('ignore les trames malformées, binaires ou inconnues', () => {
    const harness = createHarness();
    const ws = harness.latest();
    ws.simulateOpen();
    ws.simulateMessage({ type: 'auth_ok' });
    ws.simulateMessage('{invalide');
    ws.simulateMessage({ type: 'telemetry', payload: 'oops' });
    ws.simulateMessage({ type: 'telemetry' });
    ws.simulateMessage({ type: 42 });
    ws.simulateMessage([1, 2, 3]);
    expect(harness.samples).toHaveLength(0);
    expect(lastStatus(harness)).toBe('live');
  });

  it('refuse d’ouvrir sans jeton et ferme en 1008', () => {
    const harness = createHarness({}, null);
    expect(FakeWebSocket.instances).toHaveLength(0);
    expect(lastStatus(harness)).toBe('error');
    expect(harness.statuses[0]?.detail.error).toContain('Session absente');
  });

  it('ferme si le jeton disparaît avant l’ouverture', () => {
    let token: string | null = 'secret-token';
    FakeWebSocket.instances = [];
    const statuses: SocketStatus[] = [];
    const socket = createTelemetrySocket({
      url: 'wss://factory.example.test/ws',
      factory: (url) => new FakeWebSocket(url),
      onStatus: (status) => statuses.push(status),
      onSample: () => undefined,
    });
    socket.connect(() => token);
    token = null;
    const ws = FakeWebSocket.instances[0];
    ws?.simulateOpen();

    expect(ws?.sent).toHaveLength(0);
    expect(statuses[statuses.length - 1]).toBe('error');
  });
});

describe('client WSS — reconnexion et back-off', () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it('reconnecte avec un délai exponentiel et une gigue', () => {
    const harness = createHarness();
    harness.latest().simulateOpen();
    harness.latest().simulateMessage({ type: 'auth_ok' });

    harness.latest().simulateClose(1006);
    expect(lastStatus(harness)).toBe('reconnecting');
    expect(harness.statuses[harness.statuses.length - 1]?.detail.nextRetryMs).toBe(500);
    expect(FakeWebSocket.instances).toHaveLength(1);

    vi.advanceTimersByTime(499);
    expect(FakeWebSocket.instances).toHaveLength(1);
    vi.advanceTimersByTime(1);
    expect(FakeWebSocket.instances).toHaveLength(2);

    harness.latest().simulateOpen();
    harness.latest().simulateClose(1006);
    expect(harness.statuses[harness.statuses.length - 1]?.detail.nextRetryMs).toBe(1000);
  });

  it('abandonne après le nombre maximal de tentatives', () => {
    const harness = createHarness({ maxAttempts: 1 });
    harness.latest().simulateOpen();
    harness.latest().simulateClose(1006);
    vi.advanceTimersByTime(500);
    expect(FakeWebSocket.instances).toHaveLength(2);

    harness.latest().simulateOpen();
    harness.latest().simulateClose(1006);
    expect(lastStatus(harness)).toBe('error');
    expect(harness.statuses[harness.statuses.length - 1]?.detail.error).toContain(
      'tentatives',
    );
    vi.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(2);
  });

  it('ne reconnecte pas sur une fermeture d’authentification 1008', () => {
    const harness = createHarness();
    harness.latest().simulateOpen();
    harness.latest().simulateClose(1008);
    expect(lastStatus(harness)).toBe('error');
    vi.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('ne reconnecte pas sur auth_error et ferme la socket', () => {
    const harness = createHarness();
    const ws = harness.latest();
    ws.simulateOpen();
    ws.simulateMessage({ type: 'auth_error' });
    expect(lastStatus(harness)).toBe('error');
    vi.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('annule la reconnexion planifiée lors d’une déconnexion manuelle', () => {
    const harness = createHarness();
    harness.latest().simulateOpen();
    harness.latest().simulateClose(1006);
    expect(lastStatus(harness)).toBe('reconnecting');

    harness.socket.disconnect();
    expect(lastStatus(harness)).toBe('closed');
    vi.advanceTimersByTime(60_000);
    expect(FakeWebSocket.instances).toHaveLength(1);
  });

  it('est idempotent : un deuxième connect n’ouvre pas une socket', () => {
    const harness = createHarness();
    const ws = harness.latest();
    harness.socket.connect(() => 'secret-token');
    expect(FakeWebSocket.instances).toHaveLength(1);
    expect(ws.url).toContain('wss://');
  });

  it('signale une erreur si la fabrique échoue', () => {
    const statuses: SocketStatus[] = [];
    const socket = createTelemetrySocket({
      url: 'wss://factory.example.test/ws',
      factory: () => {
        throw new Error('boom');
      },
      onStatus: (status) => statuses.push(status),
      onSample: () => undefined,
    });
    socket.connect(() => 'secret-token');
    expect(statuses[statuses.length - 1]).toBe('error');
  });
});
