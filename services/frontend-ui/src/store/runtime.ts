/**
 * Assemblage runtime : API HTTP réelle + socket WSS réel (ou indisponible).
 * Aucune donnée sensible n'est persistée ici.
 */

import { createApiClient } from '../api/client';
import {
  resolveTelemetryUrl,
  type TelemetryUrlResolution,
} from '../realtime/config';
import {
  createTelemetrySocket,
  createUnavailableTelemetrySocket,
  type TelemetrySocket,
  type TelemetrySocketHandlers,
} from '../realtime/telemetrySocket';
import { createAppStore, type AppStoreApi } from './createAppStore';

function buildSocketFactory(
  resolution: TelemetryUrlResolution,
): (handlers: TelemetrySocketHandlers) => TelemetrySocket {
  return (handlers) => {
    if ('error' in resolution) {
      return createUnavailableTelemetrySocket(resolution.error, handlers);
    }
    return createTelemetrySocket({ url: resolution.url, ...handlers });
  };
}

export function createRuntimeStore(): AppStoreApi {
  const resolution = resolveTelemetryUrl({
    configuredUrl: import.meta.env.VITE_WSS_URL,
    currentHref: window.location.href,
  });
  return createAppStore({
    api: createApiClient(),
    socketFactory: buildSocketFactory(resolution),
  });
}
