/**
 * Résolution de l'URL WSS.
 *
 * Par défaut : `wss://<hôte courant>/ws/telemetry` (même origine, derrière nginx).
 * Une URL explicite `VITE_WSS_URL` est acceptée uniquement si elle est en `wss:`.
 * Seule exception : un poste de développement servi en `http://` sur une adresse de
 * bouclage (localhost, 127.0.0.1, ::1) utilise `ws:` vers la même origine (proxy Vite) ;
 * aucun hôte distant ne peut jamais utiliser `ws:`.
 * Le jeton n'est jamais intégré à l'URL.
 */

export type TelemetryUrlResolution =
  | { readonly url: string }
  | { readonly error: string };

export interface ResolveTelemetryUrlOptions {
  readonly configuredUrl: unknown;
  readonly currentHref: string;
}

export function isLoopbackHost(hostname: string): boolean {
  return (
    hostname === 'localhost' ||
    hostname === '127.0.0.1' ||
    hostname === '[::1]' ||
    hostname === '::1'
  );
}

const FORBIDDEN_QUERY_KEYS = ['token', 'access_token', 'jwt', 'authorization'];

export function resolveTelemetryUrl(
  options: ResolveTelemetryUrlOptions,
): TelemetryUrlResolution {
  const configured =
    typeof options.configuredUrl === 'string' ? options.configuredUrl.trim() : '';

  let candidate: string;
  if (configured.length > 0) {
    candidate = configured;
  } else {
    try {
      const page = new URL(options.currentHref);
      const dev = page.protocol === 'http:' && isLoopbackHost(page.hostname);
      candidate = `${dev ? 'ws' : 'wss'}://${page.host}/ws/telemetry`;
    } catch {
      return { error: 'URL de page invalide : WSS indéterminable.' };
    }
  }

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return { error: 'VITE_WSS_URL invalide.' };
  }
  const loopbackDev = parsed.protocol === 'ws:' && isLoopbackHost(parsed.hostname);
  if (parsed.protocol !== 'wss:' && !loopbackDev) {
    return { error: 'VITE_WSS_URL doit utiliser le schéma wss:.' };
  }
  if (parsed.username.length > 0 || parsed.password.length > 0) {
    return { error: 'Identifiants interdits dans VITE_WSS_URL.' };
  }
  for (const key of FORBIDDEN_QUERY_KEYS) {
    if (parsed.searchParams.has(key)) {
      return { error: 'Le jeton ne doit jamais figurer dans VITE_WSS_URL.' };
    }
  }
  return { url: parsed.toString() };
}
