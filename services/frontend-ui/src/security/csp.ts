/**
 * Source de vérité de la CSP de production.
 *
 * La balise <meta> de index.html doit rester alignée sur cette constante :
 * `src/security/csp.test.ts` et `scripts/verify-build.mjs` vérifient l'alignement
 * et l'absence de `unsafe-inline` / `unsafe-eval`.
 */

export const CSP_DIRECTIVES = {
  'default-src': ["'none'"],
  'script-src': ["'self'"],
  'style-src': ["'self'"],
  'img-src': ["'self'", 'data:'],
  'font-src': ["'self'"],
  'connect-src': ["'self'"],
  'base-uri': ["'none'"],
  'form-action': ["'self'"],
  'frame-ancestors': ["'none'"],
  'object-src': ["'none'"],
  'manifest-src': ["'self'"],
  'worker-src': ["'none'"],
} as const satisfies Readonly<Record<string, readonly string[]>>;

export const CSP_POLICY = Object.entries(CSP_DIRECTIVES)
  .map(([directive, sources]) => `${directive} ${sources.join(' ')}`)
  .join('; ');

/** Directives qui ne sont PAS honorées dans une balise <meta> (spec CSP). */
export const META_IGNORED_DIRECTIVES: readonly string[] = [
  'frame-ancestors',
  'report-uri',
  'sandbox',
];

/**
 * Assouplissements réservés au serveur de développement Vite (HMR).
 * Jamais présents dans le bundle de production.
 */
export const DEV_CSP_ADDITIONS: readonly string[] = [
  "style-src 'unsafe-inline'",
  'connect-src ws://localhost:5173',
];
