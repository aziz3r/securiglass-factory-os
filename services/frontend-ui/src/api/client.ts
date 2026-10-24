/**
 * Client HTTP de la SPA.
 *
 * Décisions de sécurité :
 * - Base URL RELATIVE et figée (`/api/v1`) : aucun jeton ne peut être envoyé à
 *   un hôte tiers, et `connect-src 'self'` reste applicable.
 * - Aucun cookie (`credentials: 'omit'`), aucun cache navigateur, pas de
 *   redirection suivie (évite les fuites d'en-tête Authorization).
 * - Le jeton n'est jamais stocké ici : il est fourni à chaque appel par le store.
 */

import {
  ApiError,
  ForbiddenError,
  NetworkError,
  ProtocolError,
  RateLimitError,
  ServerError,
  UnauthorizedError,
  ValidationError,
} from './errors';
import {
  parseAuditLogList,
  parseAuditVerify,
  parseCurrentUser,
  parseCustomer,
  parseCustomerList,
  parseFieldErrors,
  parseHealth,
  parseTokenResponse,
} from './parse';
import type {
  ApiPort,
  AuditListParams,
  AuditLog,
  AuditVerifyResult,
  CurrentUser,
  Customer,
  CustomerCreateInput,
  FetchLike,
  HealthStatus,
  ListParams,
  LoginCredentials,
  TokenResponse,
} from './types';

export const API_BASE_URL = '/api/v1';
const HEALTH_URL = '/health';

type HttpMethod = 'GET' | 'POST';
type Parser<T> = (raw: unknown) => T;

export interface ApiClientOptions {
  fetchImpl?: FetchLike;
}

function buildListQuery(params: ListParams | undefined): string {
  const search = new URLSearchParams();
  if (params?.limit !== undefined) {
    search.set('limit', String(params.limit));
  }
  if (params?.offset !== undefined) {
    search.set('offset', String(params.offset));
  }
  const query = search.toString();
  return query.length > 0 ? `?${query}` : '';
}

function buildAuditQuery(params: AuditListParams | undefined): string {
  const search = new URLSearchParams();
  if (params?.limit !== undefined) {
    search.set('limit', String(params.limit));
  }
  if (params?.offset !== undefined) {
    search.set('offset', String(params.offset));
  }
  if (params?.eventType !== undefined && params.eventType.length > 0) {
    search.set('event_type', params.eventType);
  }
  const query = search.toString();
  return query.length > 0 ? `?${query}` : '';
}

function mapHttpError(status: number, raw: unknown): ApiError {
  if (status === 401) {
    return new UnauthorizedError();
  }
  if (status === 403) {
    return new ForbiddenError();
  }
  if (status === 422) {
    return new ValidationError(parseFieldErrors(raw));
  }
  if (status === 429) {
    return new RateLimitError();
  }
  if (status >= 500) {
    return new ServerError(status);
  }
  return new ApiError('Requête refusée', { status, kind: 'http' });
}

function decodeJson(text: string): { ok: true; value: unknown } | { ok: false } {
  if (text.length === 0) {
    return { ok: true, value: null };
  }
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false };
  }
}

export function createApiClient(options: ApiClientOptions = {}): ApiPort {
  const fetchImpl: FetchLike =
    options.fetchImpl ?? ((input, init) => fetch(input, init));

  async function send(
    url: string,
    method: HttpMethod,
    token: string | null,
    body: unknown,
    parse: Parser<unknown>,
  ): Promise<unknown> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };
    if (token !== null) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    const init: RequestInit = {
      method,
      headers,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }

    let response: Response;
    try {
      response = await fetchImpl(url, init);
    } catch (error) {
      if (error instanceof ApiError) {
        throw error;
      }
      throw new NetworkError(error);
    }

    let text: string;
    try {
      text = await response.text();
    } catch {
      throw new ProtocolError('Corps de réponse illisible');
    }

    const decoded = decodeJson(text);
    if (!response.ok) {
      throw mapHttpError(response.status, decoded.ok ? decoded.value : null);
    }
    if (!decoded.ok) {
      throw new ProtocolError();
    }
    return parse(decoded.value);
  }

  return {
    async login(credentials: LoginCredentials): Promise<TokenResponse> {
      const raw = await send(
        `${API_BASE_URL}/auth/login`,
        'POST',
        null,
        credentials,
        (value) => value,
      );
      return parseTokenResponse(raw);
    },

    async logout(token: string): Promise<void> {
      await send(`${API_BASE_URL}/auth/logout`, 'POST', token, undefined, () => null);
    },

    async me(token: string): Promise<CurrentUser> {
      const raw = await send(
        `${API_BASE_URL}/auth/me`,
        'GET',
        token,
        undefined,
        (value) => value,
      );
      return parseCurrentUser(raw);
    },

    async listCustomers(
      token: string,
      params?: ListParams,
    ): Promise<Customer[]> {
      const raw = await send(
        `${API_BASE_URL}/customers${buildListQuery(params)}`,
        'GET',
        token,
        undefined,
        (value) => value,
      );
      return parseCustomerList(raw);
    },

    async createCustomer(
      token: string,
      input: CustomerCreateInput,
    ): Promise<Customer> {
      const raw = await send(
        `${API_BASE_URL}/customers`,
        'POST',
        token,
        input,
        (value) => value,
      );
      return parseCustomer(raw);
    },

    async listAuditLogs(
      token: string,
      params?: AuditListParams,
    ): Promise<AuditLog[]> {
      const raw = await send(
        `${API_BASE_URL}/audit/logs${buildAuditQuery(params)}`,
        'GET',
        token,
        undefined,
        (value) => value,
      );
      return parseAuditLogList(raw);
    },

    async verifyAuditChain(token: string): Promise<AuditVerifyResult> {
      const raw = await send(
        `${API_BASE_URL}/audit/verify`,
        'GET',
        token,
        undefined,
        (value) => value,
      );
      return parseAuditVerify(raw);
    },

    async health(): Promise<HealthStatus> {
      const raw = await send(HEALTH_URL, 'GET', null, undefined, (value) => value);
      return parseHealth(raw);
    },
  };
}
