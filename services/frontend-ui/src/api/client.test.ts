import { describe, expect, it, vi } from 'vitest';

import { createApiClient } from './client';
import {
  ForbiddenError,
  NetworkError,
  ProtocolError,
  ServerError,
  UnauthorizedError,
  ValidationError,
} from './errors';
import type { FetchLike } from './types';

const USER = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'manager',
  email: 'manager@securiglass.local',
  roles: ['PLANT_MANAGER'],
  clearance_level: 3,
};

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function makeFetch(response: Response): FetchLike {
  return vi.fn(async () => response);
}

function headerOf(init: RequestInit | undefined, name: string): string | null {
  if (init === undefined || init.headers === undefined) {
    return null;
  }
  const headers = init.headers as Record<string, string>;
  return headers[name] ?? null;
}

describe('client API — requêtes et en-têtes', () => {
  it('authentifie sans jeton et sans cookie, puis parse le token', async () => {
    const fetchImpl = makeFetch(
      json({
        access_token: 'token-abc',
        token_type: 'bearer',
        expires_in: 1800,
      }),
    );
    const client = createApiClient({ fetchImpl });

    const result = await client.login({ username: 'manager', password: 'S3cret!' });

    expect(result.access_token).toBe('token-abc');
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/auth/login');
    expect(init.method).toBe('POST');
    expect(init.credentials).toBe('omit');
    expect(init.cache).toBe('no-store');
    expect(init.redirect).toBe('error');
    expect(headerOf(init, 'Authorization')).toBeNull();
    expect(headerOf(init, 'Content-Type')).toBe('application/json');
    expect(init.body).toBe(JSON.stringify({ username: 'manager', password: 'S3cret!' }));
  });

  it('envoie le jeton en en-tête Bearer pour /auth/me', async () => {
    const fetchImpl = makeFetch(json(USER));
    const client = createApiClient({ fetchImpl });

    const user = await client.me('token-abc');

    expect(user.roles).toEqual(['PLANT_MANAGER']);
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/auth/me');
    expect(headerOf(init, 'Authorization')).toBe('Bearer token-abc');
  });

  it('construit la pagination clients et décode la liste', async () => {
    const fetchImpl = makeFetch(
      json([
        {
          id: '66666666-6666-4666-8666-666666666666',
          company_name: 'Vitrerie',
          contact_name: 'Camille',
          email: 'camille@example.test',
          phone: null,
          vat_number: null,
          country_code: 'FR',
          is_active: true,
          created_at: null,
        },
      ]),
    );
    const client = createApiClient({ fetchImpl });

    const customers = await client.listCustomers('token-abc', { limit: 10, offset: 20 });

    expect(customers).toHaveLength(1);
    const [url] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/api/v1/customers?limit=10&offset=20');
  });

  it('crée un client avec un corps JSON et parse la réponse', async () => {
    const fetchImpl = makeFetch(
      json(
        {
          id: '66666666-6666-4666-8666-666666666666',
          company_name: 'Vitrerie',
          contact_name: 'Camille',
          email: 'camille@example.test',
          phone: '+33 4 72 00 00 00',
          vat_number: null,
          country_code: 'FR',
          is_active: true,
          created_at: '2026-10-20T10:00:00Z',
        },
        201,
      ),
    );
    const client = createApiClient({ fetchImpl });

    const created = await client.createCustomer('token-abc', {
      company_name: 'Vitrerie',
      contact_name: 'Camille',
      email: 'camille@example.test',
      country_code: 'FR',
    });

    expect(created.company_name).toBe('Vitrerie');
    const [url, init] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [
      string,
      RequestInit,
    ];
    expect(url).toBe('/api/v1/customers');
    expect(init.method).toBe('POST');
    expect(headerOf(init, 'Authorization')).toBe('Bearer token-abc');
  });

  it('filtre les logs d’audit par event_type et vérifie la chaîne', async () => {
    const fetchImpl = vi
      .fn<FetchLike>()
      .mockResolvedValueOnce(json([]))
      .mockResolvedValueOnce(
        json({ chain_valid: true, first_broken_id: null, total_records_checked: 3 }),
      );
    const client = createApiClient({ fetchImpl });

    await client.listAuditLogs('token-abc', { limit: 50, offset: 0, eventType: 'AUTH_LOGIN' });
    const verification = await client.verifyAuditChain('token-abc');

    expect(verification.total_records_checked).toBe(3);
    const calls = fetchImpl.mock.calls as Array<[string, RequestInit]>;
    expect(calls[0]?.[0]).toBe(
      '/api/v1/audit/logs?limit=50&offset=0&event_type=AUTH_LOGIN',
    );
    expect(calls[1]?.[0]).toBe('/api/v1/audit/verify');
  });

  it('appelle /health hors du préfixe /api/v1', async () => {
    const fetchImpl = makeFetch(
      json({
        status: 'UP',
        service: 'securiglass-backend-api',
        version: '1.0.0',
        environment: 'test',
      }),
    );
    const client = createApiClient({ fetchImpl });

    const health = await client.health();

    expect(health.status).toBe('UP');
    const [url] = (fetchImpl as ReturnType<typeof vi.fn>).mock.calls[0] as [string, RequestInit];
    expect(url).toBe('/health');
  });

  it('accepte une déconnexion 204 sans corps', async () => {
    const fetchImpl = makeFetch(new Response(null, { status: 204 }));
    const client = createApiClient({ fetchImpl });

    await expect(client.logout('token-abc')).resolves.toBeUndefined();
  });
});

describe('client API — erreurs typées', () => {
  it('401 → UnauthorizedError', async () => {
    const client = createApiClient({ fetchImpl: makeFetch(json({ detail: 'nope' }, 401)) });
    await expect(client.me('expired')).rejects.toBeInstanceOf(UnauthorizedError);
  });

  it('403 → ForbiddenError', async () => {
    const client = createApiClient({ fetchImpl: makeFetch(json({ detail: 'no' }, 403)) });
    await expect(client.listCustomers('token')).rejects.toBeInstanceOf(ForbiddenError);
  });

  it('422 → ValidationError avec remappage des champs', async () => {
    const client = createApiClient({
      fetchImpl: makeFetch(
        json(
          {
            detail: 'Échec de validation',
            errors: [
              { field: 'body -> email', message: 'Adresse invalide', type: 'value_error' },
              { field: 'body -> company_name', message: 'Champ requis', type: 'missing' },
            ],
          },
          422,
        ),
      ),
    });

    try {
      await client.createCustomer('token', {
        company_name: '',
        contact_name: 'X',
        email: 'bad',
        country_code: 'FR',
      });
      expect.unreachable('une ValidationError était attendue');
    } catch (error) {
      expect(error).toBeInstanceOf(ValidationError);
      if (error instanceof ValidationError) {
        expect(error.fieldErrors).toEqual({
          email: 'Adresse invalide',
          company_name: 'Champ requis',
        });
      }
    }
  });

  it('500 → ServerError sans message serveur', async () => {
    const client = createApiClient({
      fetchImpl: makeFetch(json({ detail: 'stacktrace secrète' }, 500)),
    });
    await expect(client.me('token')).rejects.toBeInstanceOf(ServerError);
  });

  it('panne réseau → NetworkError', async () => {
    const fetchImpl: FetchLike = vi.fn(async () => {
      throw new TypeError('Failed to fetch');
    });
    const client = createApiClient({ fetchImpl });
    await expect(client.me('token')).rejects.toBeInstanceOf(NetworkError);
  });

  it('200 avec JSON invalide → ProtocolError', async () => {
    const client = createApiClient({
      fetchImpl: makeFetch(new Response('<html>', { status: 200 })),
    });
    await expect(client.me('token')).rejects.toBeInstanceOf(ProtocolError);
  });

  it('token sans rôle exploitable → ProtocolError', async () => {
    const client = createApiClient({
      fetchImpl: makeFetch(json({ ...USER, roles: ['ROLE_INCONNU'] })),
    });
    await expect(client.me('token')).rejects.toBeInstanceOf(ProtocolError);
  });

  it('durée de token nulle → ProtocolError', async () => {
    const client = createApiClient({
      fetchImpl: makeFetch(
        json({ access_token: 'x', token_type: 'bearer', expires_in: 0 }),
      ),
    });
    await expect(client.login({ username: 'u', password: 'p' })).rejects.toBeInstanceOf(
      ProtocolError,
    );
  });
});
