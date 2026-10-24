/** Erreurs typées du client API — aucun message serveur brut n'est exposé. */

export type ApiErrorKind =
  | 'unauthorized'
  | 'forbidden'
  | 'validation'
  | 'rate_limited'
  | 'server'
  | 'network'
  | 'protocol'
  | 'http';

export interface ApiErrorOptions {
  status: number;
  kind: ApiErrorKind;
  fieldErrors?: Readonly<Record<string, string>> | null;
  cause?: unknown;
}

export class ApiError extends Error {
  readonly status: number;
  readonly kind: ApiErrorKind;
  readonly fieldErrors: Readonly<Record<string, string>> | null;

  constructor(message: string, options: ApiErrorOptions) {
    super(message, options.cause === undefined ? undefined : { cause: options.cause });
    this.name = 'ApiError';
    this.status = options.status;
    this.kind = options.kind;
    this.fieldErrors = options.fieldErrors ?? null;
  }
}

export class UnauthorizedError extends ApiError {
  constructor(message = 'Authentification requise') {
    super(message, { status: 401, kind: 'unauthorized' });
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends ApiError {
  constructor(message = 'Accès refusé') {
    super(message, { status: 403, kind: 'forbidden' });
    this.name = 'ForbiddenError';
  }
}

export class ValidationError extends ApiError {
  constructor(fieldErrors: Readonly<Record<string, string>>) {
    super('Données invalides', {
      status: 422,
      kind: 'validation',
      fieldErrors,
    });
    this.name = 'ValidationError';
  }
}

export class RateLimitError extends ApiError {
  constructor() {
    super('Trop de tentatives', { status: 429, kind: 'rate_limited' });
    this.name = 'RateLimitError';
  }
}

export class ServerError extends ApiError {
  constructor(status: number) {
    super('Erreur interne du service', { status, kind: 'server' });
    this.name = 'ServerError';
  }
}

export class NetworkError extends ApiError {
  constructor(cause?: unknown) {
    super('Service injoignable', { status: 0, kind: 'network', cause });
    this.name = 'NetworkError';
  }
}

export class ProtocolError extends ApiError {
  constructor(message = 'Réponse serveur invalide') {
    super(message, { status: 0, kind: 'protocol' });
    this.name = 'ProtocolError';
  }
}

export function isUnauthorized(error: unknown): error is UnauthorizedError {
  return error instanceof UnauthorizedError;
}

export function isForbidden(error: unknown): error is ForbiddenError {
  return error instanceof ForbiddenError;
}
