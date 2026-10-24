import { describe, expect, it } from 'vitest';

import { resolveTelemetryUrl } from './config';

const HREF = 'https://factory.example.test/console';

describe('résolution de l’URL WSS', () => {
  it('dérive wss:// de l’origine courante par défaut', () => {
    expect(resolveTelemetryUrl({ configuredUrl: undefined, currentHref: HREF })).toEqual({
      url: 'wss://factory.example.test/ws/telemetry',
    });
    expect(resolveTelemetryUrl({ configuredUrl: '   ', currentHref: HREF })).toEqual({
      url: 'wss://factory.example.test/ws/telemetry',
    });
  });

  it('accepte une URL wss explicite', () => {
    expect(
      resolveTelemetryUrl({
        configuredUrl: 'wss://telemetry.example.test/stream',
        currentHref: HREF,
      }),
    ).toEqual({ url: 'wss://telemetry.example.test/stream' });
  });

  it('refuse ws: en clair', () => {
    const result = resolveTelemetryUrl({
      configuredUrl: 'ws://telemetry.example.test/stream',
      currentHref: HREF,
    });
    expect('error' in result).toBe(true);
  });

  it('refuse un jeton dans l’URL', () => {
    const result = resolveTelemetryUrl({
      configuredUrl: 'wss://telemetry.example.test/stream?access_token=secret',
      currentHref: HREF,
    });
    expect('error' in result && result.error).toContain('jamais');
  });

  it('refuse les identifiants et les URLs invalides', () => {
    expect(
      'error' in
        resolveTelemetryUrl({
          configuredUrl: 'wss://user:pass@telemetry.example.test/stream',
          currentHref: HREF,
        }),
    ).toBe(true);
    expect(
      'error' in
        resolveTelemetryUrl({
          configuredUrl: 'wss://[invalide',
          currentHref: HREF,
        }),
    ).toBe(true);
    expect(
      'error' in resolveTelemetryUrl({ configuredUrl: undefined, currentHref: 'nope' }),
    ).toBe(true);
  });

  it('utilise ws: uniquement pour un poste de développement en bouclage', () => {
    expect(
      resolveTelemetryUrl({ configuredUrl: undefined, currentHref: 'http://localhost:5173/login' }),
    ).toEqual({ url: 'ws://localhost:5173/ws/telemetry' });
    expect(
      resolveTelemetryUrl({ configuredUrl: undefined, currentHref: 'https://factory.example.test/' }),
    ).toEqual({ url: 'wss://factory.example.test/ws/telemetry' });
    expect(
      resolveTelemetryUrl({ configuredUrl: undefined, currentHref: 'http://factory.example.test/' }),
    ).toEqual({ url: 'wss://factory.example.test/ws/telemetry' });
  });

  it('refuse ws: vers un hôte distant même configuré explicitement', () => {
    expect(
      'error' in
        resolveTelemetryUrl({ configuredUrl: 'ws://10.0.0.5/ws', currentHref: 'http://localhost:5173/' }),
    ).toBe(true);
    expect(
      'url' in
        resolveTelemetryUrl({ configuredUrl: 'ws://127.0.0.1:5173/ws', currentHref: 'http://localhost:5173/' }),
    ).toBe(true);
  });
});
