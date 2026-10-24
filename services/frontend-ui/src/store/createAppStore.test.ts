import { beforeEach, describe, expect, it } from 'vitest';

import { ForbiddenError, UnauthorizedError, ValidationError } from '../api/errors';
import type { AuditLog, CustomerCreateInput } from '../api/types';
import {
  AUDIT_LOG,
  createFakeApi,
  createFakeSocket,
  FIXED_NOW,
  OT_OPERATOR,
  PLANT_MANAGER,
  SECURITY_AUDITOR,
  SUPER_ADMIN,
  TELEMETRY_SAMPLE,
  TOKEN_RESPONSE,
  type FakeApi,
  type FakeSocketHarness,
} from '../test/fixtures';
import { createAppStore, type AppStoreApi } from './createAppStore';
import {
  selectCanReadAudit,
  selectCanReadCustomers,
  selectRoles,
  selectVisibleAuditLogs,
  selectVisibleCustomers,
} from './selectors';

interface Setup {
  store: AppStoreApi;
  api: FakeApi;
  socket: FakeSocketHarness;
}

function setup(api: FakeApi = createFakeApi()): Setup {
  const socket = createFakeSocket();
  const store = createAppStore({
    api: api.api,
    socketFactory: socket.factory,
    now: () => FIXED_NOW,
  });
  return { store, api, socket };
}

async function loginAs(store: AppStoreApi, username = 'manager'): Promise<void> {
  const ok = await store.getState().login({ username, password: 'correct-horse' });
  expect(ok).toBe(true);
}

const VALID_INPUT: CustomerCreateInput = {
  company_name: 'Nouvelle Verrerie',
  contact_name: 'Dana Dupont',
  email: 'dana@verrerie.example',
  phone: '+33 1 23 45 67 89',
  country_code: 'FR',
};

describe('store — authentification et jeton en mémoire', () => {
  beforeEach(() => {
    window.localStorage.clear();
    window.sessionStorage.clear();
  });

  it('connecte l’utilisateur, garde le jeton en mémoire et calcule l’expiration', async () => {
    const { store, api } = setup();
    await loginAs(store);

    const state = store.getState();
    expect(state.session.token).toBe(TOKEN_RESPONSE.access_token);
    expect(state.session.user?.username).toBe(PLANT_MANAGER.username);
    expect(state.session.status).toBe('authenticated');
    expect(state.session.expiresAt).toBe(FIXED_NOW + TOKEN_RESPONSE.expires_in * 1000);
    expect(api.login).toHaveBeenCalledWith({
      username: 'manager',
      password: 'correct-horse',
    });
    expect(api.me).toHaveBeenCalledWith(TOKEN_RESPONSE.access_token);
  });

  it('ne persiste rien dans localStorage/sessionStorage', async () => {
    const { store } = setup();
    await loginAs(store);

    expect(window.localStorage.length).toBe(0);
    expect(window.sessionStorage.length).toBe(0);
    expect(JSON.stringify(window.localStorage)).not.toContain(
      TOKEN_RESPONSE.access_token,
    );
  });

  it('refuse des identifiants invalides sans conserver de jeton', async () => {
    const { store, api } = setup();
    api.login.mockRejectedValueOnce(new UnauthorizedError());

    const ok = await store.getState().login({ username: 'manager', password: 'bad' });

    expect(ok).toBe(false);
    expect(store.getState().session.token).toBeNull();
    expect(store.getState().session.user).toBeNull();
    expect(store.getState().session.error).toBe('Identifiants invalides.');
  });

  it('purge tout si /auth/me échoue après la délivrance du jeton', async () => {
    const { store, api } = setup();
    api.me.mockRejectedValueOnce(new UnauthorizedError());

    const ok = await store.getState().login({ username: 'manager', password: 'x' });

    expect(ok).toBe(false);
    expect(store.getState().session.token).toBeNull();
    expect(store.getState().session.error).not.toBeNull();
  });

  it('déconnecte localement même si l’appel serveur de logout échoue', async () => {
    const { store, api, socket } = setup();
    await loginAs(store);
    await store.getState().loadCustomers();
    api.logout.mockRejectedValueOnce(new Error('réseau coupé'));

    await expect(store.getState().logout()).resolves.toBeUndefined();

    expect(store.getState().session.token).toBeNull();
    expect(store.getState().session.user).toBeNull();
    expect(store.getState().customers.items).toBeNull();
    expect(api.logout).toHaveBeenCalledWith(TOKEN_RESPONSE.access_token);
    expect(socket.disconnect).toHaveBeenCalled();
  });
});

describe('store — isolation des données par rôle', () => {
  it('un opérateur OT ne peut ni charger ni lire les clients', async () => {
    const api = createFakeApi(OT_OPERATOR);
    const { store } = setup(api);
    await loginAs(store, 'operator');

    await store.getState().loadCustomers();

    expect(api.listCustomers).not.toHaveBeenCalled();
    expect(selectCanReadCustomers(store.getState())).toBe(false);
    expect(selectVisibleCustomers(store.getState())).toBeNull();
    expect(store.getState().customers.accessDenied).toBe(true);
  });

  it('un état clients corrompu reste invisible pour un OT (sélecteur fail-closed)', async () => {
    const api = createFakeApi(OT_OPERATOR);
    const { store } = setup(api);
    await loginAs(store, 'operator');

    store.setState((state) => ({
      customers: {
        ...state.customers,
        items: [
          {
            id: 'x',
            company_name: 'Fuite',
            contact_name: 'Fuite',
            email: 'fuite@example.test',
            phone: null,
            vat_number: null,
            country_code: 'FR',
            is_active: true,
            created_at: null,
          },
        ],
        status: 'ready',
      },
    }));

    expect(selectVisibleCustomers(store.getState())).toBeNull();
  });

  it('purge les données d’un précédent rôle lors d’une nouvelle connexion', async () => {
    const api = createFakeApi(PLANT_MANAGER);
    const { store } = setup(api);
    await loginAs(store, 'manager');
    await store.getState().loadCustomers();
    expect(selectVisibleCustomers(store.getState())).not.toBeNull();

    api.me.mockResolvedValueOnce(OT_OPERATOR);
    await loginAs(store, 'operator');

    expect(selectRoles(store.getState())).toEqual(['OT_OPERATOR']);
    expect(store.getState().customers.items).toBeNull();
    expect(selectVisibleCustomers(store.getState())).toBeNull();
  });

  it('un auditeur accède aux logs, un responsable usine non', async () => {
    const auditorApi = createFakeApi(SECURITY_AUDITOR);
    const auditor = setup(auditorApi);
    await loginAs(auditor.store, 'auditor');
    await auditor.store.getState().loadAuditLogs();
    expect(selectCanReadAudit(auditor.store.getState())).toBe(true);
    expect(selectVisibleAuditLogs(auditor.store.getState())).toHaveLength(1);

    const managerApi = createFakeApi(PLANT_MANAGER);
    const manager = setup(managerApi);
    await loginAs(manager.store, 'manager');
    await manager.store.getState().loadAuditLogs();
    expect(managerApi.listAuditLogs).not.toHaveBeenCalled();
    expect(selectVisibleAuditLogs(manager.store.getState())).toBeNull();
  });
});

describe('store — clients', () => {
  it('charge la liste pour un PLANT_MANAGER', async () => {
    const { store, api } = setup();
    await loginAs(store);
    await store.getState().loadCustomers();

    expect(api.listCustomers).toHaveBeenCalledWith(TOKEN_RESPONSE.access_token);
    expect(store.getState().customers.status).toBe('ready');
    expect(selectVisibleCustomers(store.getState())).toHaveLength(1);
  });

  it('crée un client validé et l’insère en tête de liste', async () => {
    const { store, api } = setup();
    await loginAs(store);
    await store.getState().loadCustomers();

    const created = await store.getState().createCustomer(VALID_INPUT);

    expect(created?.company_name).toBe('Nouvelle Verrerie');
    expect(api.createCustomer).toHaveBeenCalledWith(
      TOKEN_RESPONSE.access_token,
      VALID_INPUT,
    );
    expect(store.getState().customers.items?.[0]?.company_name).toBe(
      'Nouvelle Verrerie',
    );
    expect(store.getState().customers.items).toHaveLength(2);
  });

  it('refuse un formulaire invalide sans appeler le backend', async () => {
    const { store, api } = setup();
    await loginAs(store);

    const created = await store.getState().createCustomer({
      ...VALID_INPUT,
      email: 'pas-un-email',
      company_name: '   ',
    });

    expect(created).toBeNull();
    expect(api.createCustomer).not.toHaveBeenCalled();
    expect(store.getState().customers.fieldErrors.email).toBeDefined();
    expect(store.getState().customers.fieldErrors.company_name).toBeDefined();
  });

  it('refuse la création pour un rôle non PLANT_MANAGER', async () => {
    const api = createFakeApi(SUPER_ADMIN);
    const { store } = setup(api);
    await loginAs(store, 'admin');

    const created = await store.getState().createCustomer(VALID_INPUT);

    expect(created).toBeNull();
    expect(api.createCustomer).not.toHaveBeenCalled();
    expect(store.getState().customers.createError).toContain('Accès refusé');
  });

  it('mappe les erreurs 422 du backend sur les champs du formulaire', async () => {
    const { store, api } = setup();
    await loginAs(store);
    api.createCustomer.mockRejectedValueOnce(
      new ValidationError({ email: 'Adresse refusée par le serveur' }),
    );

    const created = await store.getState().createCustomer(VALID_INPUT);

    expect(created).toBeNull();
    expect(store.getState().customers.fieldErrors.email).toBe(
      'Adresse refusée par le serveur',
    );
  });

  it('purge la session et les clients sur 401', async () => {
    const { store, api, socket } = setup();
    await loginAs(store);
    await store.getState().loadCustomers();
    api.listCustomers.mockRejectedValueOnce(new UnauthorizedError());

    await store.getState().loadCustomers();

    expect(store.getState().session.token).toBeNull();
    expect(store.getState().session.user).toBeNull();
    expect(store.getState().session.notice).toContain('expiré');
    expect(store.getState().customers.items).toBeNull();
    expect(selectVisibleCustomers(store.getState())).toBeNull();
    expect(socket.disconnect).toHaveBeenCalled();
  });

  it('signale un 403 sans conserver la liste et sans tuer la session', async () => {
    const { store, api } = setup();
    await loginAs(store);
    api.listCustomers.mockRejectedValueOnce(new ForbiddenError());

    await store.getState().loadCustomers();

    expect(store.getState().session.token).not.toBeNull();
    expect(store.getState().customers.accessDenied).toBe(true);
    expect(store.getState().customers.items).toBeNull();
    expect(store.getState().customers.error).toContain('Accès refusé');
  });
});

describe('store — audit', () => {
  it('charge et vérifie la chaîne pour un auditeur', async () => {
    const api = createFakeApi(SECURITY_AUDITOR);
    const { store } = setup(api);
    await loginAs(store, 'auditor');

    await store.getState().loadAuditLogs();
    await store.getState().verifyAuditChain();

    expect(api.listAuditLogs).toHaveBeenCalledWith(TOKEN_RESPONSE.access_token, {
      limit: 50,
      offset: 0,
    });
    expect(store.getState().audit.verification?.chain_valid).toBe(true);
    expect(store.getState().audit.verification?.total_records_checked).toBe(42);
  });

  it('pagine les logs et détecte la fin de liste', async () => {
    const api = createFakeApi(SECURITY_AUDITOR);
    const { store } = setup(api);
    await loginAs(store, 'auditor');
    const firstBatch: AuditLog[] = Array.from({ length: 50 }, (_, index) => ({
      ...AUDIT_LOG,
      id: `00000000-0000-4000-8000-${String(index).padStart(12, '0')}`,
    }));
    api.listAuditLogs.mockResolvedValueOnce(firstBatch);
    api.listAuditLogs.mockResolvedValueOnce([AUDIT_LOG]);

    await store.getState().loadAuditLogs(0);
    expect(store.getState().audit.hasMore).toBe(true);
    expect(store.getState().audit.offset).toBe(50);

    await store.getState().loadAuditLogs(store.getState().audit.offset);
    expect(store.getState().audit.items).toHaveLength(51);
    expect(store.getState().audit.hasMore).toBe(false);
  });

  it('purge la session sur 401 lors de la vérification', async () => {
    const api = createFakeApi(SECURITY_AUDITOR);
    const { store } = setup(api);
    await loginAs(store, 'auditor');
    api.verifyAuditChain.mockRejectedValueOnce(new UnauthorizedError());

    await store.getState().verifyAuditChain();

    expect(store.getState().session.token).toBeNull();
    expect(store.getState().audit.verification).toBeNull();
  });

  it('refuse la vérification sans droit d’audit', async () => {
    const api = createFakeApi(PLANT_MANAGER);
    const { store } = setup(api);
    await loginAs(store, 'manager');

    await store.getState().verifyAuditChain();

    expect(api.verifyAuditChain).not.toHaveBeenCalled();
    expect(store.getState().audit.verificationError).toContain('Accès refusé');
  });
});

describe('store — télémétrie WSS', () => {
  it('ne connecte pas le WSS sans session', () => {
    const { store, socket } = setup();
    store.getState().connectTelemetry();
    expect(socket.connect).not.toHaveBeenCalled();
  });

  it('connecte avec un getter de jeton et expose statut + échantillon', async () => {
    const { store, socket } = setup();
    await loginAs(store);

    store.getState().connectTelemetry();
    expect(socket.connect).toHaveBeenCalledTimes(1);
    expect(socket.getToken()?.()).toBe(TOKEN_RESPONSE.access_token);

    socket.emitStatus('live');
    expect(store.getState().telemetry.status).toBe('live');

    socket.emitSample(TELEMETRY_SAMPLE);
    expect(store.getState().telemetry.sample).toEqual(TELEMETRY_SAMPLE);
    expect(store.getState().telemetry.sampleReceivedAt).toBe(FIXED_NOW);

    socket.emitStatus('reconnecting', { attempt: 2, nextRetryMs: 1500 });
    expect(store.getState().telemetry.attempt).toBe(2);
    expect(store.getState().telemetry.nextRetryMs).toBe(1500);
  });

  it('ferme le WSS à la déconnexion et remet l’état à zéro', async () => {
    const { store, socket } = setup();
    await loginAs(store);
    store.getState().connectTelemetry();
    socket.emitSample(TELEMETRY_SAMPLE);

    await store.getState().logout();

    expect(socket.disconnect).toHaveBeenCalled();
    expect(store.getState().telemetry.sample).toBeNull();
    expect(store.getState().telemetry.status).toBe('idle');
  });
});
