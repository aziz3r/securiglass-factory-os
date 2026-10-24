/**
 * Store Zustand — état applicatif cloisonné par domaine et par rôle.
 *
 * Principes :
 * - Le jeton d'accès vit uniquement dans `session.token` (mémoire du processus JS).
 *   Aucun middleware `persist`, aucun accès à localStorage/sessionStorage/cookie.
 * - Quatre slices distinctes : `session`, `customers`, `audit`, `telemetry`.
 * - Les données clients/audit sont purgées à la déconnexion, à l'expiration 401 et
 *   à chaque nouvelle authentification. Les sélecteurs refusent aussi toute
 *   lecture si le rôle courant n'y a pas droit (isolation en profondeur).
 * - Le client API ne stocke rien : le jeton lui est passé explicitement.
 */

import { createStore, type StoreApi } from 'zustand/vanilla';

import {
  ForbiddenError,
  RateLimitError,
  UnauthorizedError,
  ValidationError,
} from '../api/errors';
import type {
  ApiPort,
  AuditLog,
  AuditVerifyResult,
  CurrentUser,
  Customer,
  CustomerCreateInput,
  LoginCredentials,
} from '../api/types';
import type {
  SocketStatus,
  TelemetrySample,
  TelemetrySocket,
  TelemetrySocketHandlers,
} from '../realtime/telemetrySocket';
import {
  canCreateCustomer,
  canReadAudit,
  canReadCustomers,
} from '../security/roles';
import {
  hasErrors,
  mapServerFieldErrors,
  validateCustomerForm,
  type CustomerFormErrors,
} from '../validation/forms';

export type SessionStatus = 'anonymous' | 'authenticating' | 'authenticated';
export type LoadStatus = 'idle' | 'loading' | 'ready' | 'error';

export interface SessionState {
  token: string | null;
  user: CurrentUser | null;
  status: SessionStatus;
  error: string | null;
  notice: string | null;
  expiresAt: number | null;
}

export interface CustomersState {
  items: Customer[] | null;
  status: LoadStatus;
  error: string | null;
  accessDenied: boolean;
  creating: boolean;
  createError: string | null;
  fieldErrors: CustomerFormErrors;
}

export interface AuditState {
  items: AuditLog[] | null;
  status: LoadStatus;
  error: string | null;
  accessDenied: boolean;
  offset: number;
  hasMore: boolean;
  verifying: boolean;
  verification: AuditVerifyResult | null;
  verificationError: string | null;
}

export interface TelemetryState {
  status: SocketStatus;
  attempt: number;
  nextRetryMs: number | null;
  error: string | null;
  sample: TelemetrySample | null;
  sampleReceivedAt: number | null;
}

export interface AppStore {
  session: SessionState;
  customers: CustomersState;
  audit: AuditState;
  telemetry: TelemetryState;

  login: (credentials: LoginCredentials) => Promise<boolean>;
  logout: () => Promise<void>;
  expireSession: () => void;

  loadCustomers: () => Promise<void>;
  createCustomer: (input: CustomerCreateInput) => Promise<Customer | null>;

  loadAuditLogs: (offset?: number) => Promise<void>;
  verifyAuditChain: () => Promise<void>;

  connectTelemetry: () => void;
  disconnectTelemetry: () => void;
}

export type AppStoreApi = StoreApi<AppStore>;

export interface AppDependencies {
  api: ApiPort;
  socketFactory: (handlers: TelemetrySocketHandlers) => TelemetrySocket;
  now?: () => number;
}

export const AUDIT_PAGE_SIZE = 50;

const SESSION_EXPIRED_NOTICE =
  'Votre session a expiré. Veuillez vous reconnecter.';
const ACCESS_DENIED_MESSAGE =
  'Accès refusé : votre rôle ne dispose pas de cette autorisation.';
const GENERIC_ERROR = 'Une erreur est survenue. Veuillez réessayer.';

function createSessionState(notice: string | null = null): SessionState {
  return {
    token: null,
    user: null,
    status: 'anonymous',
    error: null,
    notice,
    expiresAt: null,
  };
}

function createCustomersState(): CustomersState {
  return {
    items: null,
    status: 'idle',
    error: null,
    accessDenied: false,
    creating: false,
    createError: null,
    fieldErrors: {},
  };
}

function createAuditState(): AuditState {
  return {
    items: null,
    status: 'idle',
    error: null,
    accessDenied: false,
    offset: 0,
    hasMore: false,
    verifying: false,
    verification: null,
    verificationError: null,
  };
}

function createTelemetryState(): TelemetryState {
  return {
    status: 'idle',
    attempt: 0,
    nextRetryMs: null,
    error: null,
    sample: null,
    sampleReceivedAt: null,
  };
}

function loginErrorMessage(error: unknown): string {
  if (error instanceof UnauthorizedError) {
    return 'Identifiants invalides.';
  }
  if (error instanceof RateLimitError) {
    return 'Trop de tentatives. Réessayez dans quelques minutes.';
  }
  if (error instanceof ForbiddenError) {
    return 'Compte non autorisé à accéder à cette console.';
  }
  return 'Connexion impossible. Vérifiez le service et réessayez.';
}

function customerInputToForm(input: CustomerCreateInput) {
  return {
    company_name: input.company_name,
    contact_name: input.contact_name,
    email: input.email,
    phone: input.phone ?? '',
    vat_number: input.vat_number ?? '',
    country_code: input.country_code,
  };
}

function isTokenUsable(session: SessionState): boolean {
  return session.token !== null && session.user !== null;
}

export function createAppStore(deps: AppDependencies): AppStoreApi {
  const now = deps.now ?? (() => Date.now());

  return createStore<AppStore>()((set, get) => {
    const socket = deps.socketFactory({
      onStatus: (status, detail) => {
        set((state) => ({
          telemetry: {
            ...state.telemetry,
            status,
            attempt: detail.attempt,
            nextRetryMs: detail.nextRetryMs,
            error: detail.error,
          },
        }));
      },
      onSample: (sample) => {
        set((state) => ({
          telemetry: {
            ...state.telemetry,
            sample,
            sampleReceivedAt: now(),
          },
        }));
      },
    });

    /**
     * Purge immédiate de toutes les données sensibles + fermeture du WSS.
     * À appeler avant toute transition de session.
     */
    function clearSession(notice: string | null): void {
      socket.disconnect();
      set({
        session: createSessionState(notice),
        customers: createCustomersState(),
        audit: createAuditState(),
        telemetry: createTelemetryState(),
      });
    }

    function handleUnauthorized(): void {
      clearSession(SESSION_EXPIRED_NOTICE);
    }

    return {
      session: createSessionState(),
      customers: createCustomersState(),
      audit: createAuditState(),
      telemetry: createTelemetryState(),

      async login(credentials: LoginCredentials): Promise<boolean> {
        socket.disconnect();
        set({
          session: {
            token: null,
            user: null,
            status: 'authenticating',
            error: null,
            notice: null,
            expiresAt: null,
          },
          customers: createCustomersState(),
          audit: createAuditState(),
          telemetry: createTelemetryState(),
        });

        try {
          const tokenResponse = await deps.api.login(credentials);
          const user = await deps.api.me(tokenResponse.access_token);
          set({
            session: {
              token: tokenResponse.access_token,
              user,
              status: 'authenticated',
              error: null,
              notice: null,
              expiresAt: now() + tokenResponse.expires_in * 1000,
            },
          });
          return true;
        } catch (error) {
          clearSession(null);
          set((state) => ({
            session: {
              ...state.session,
              error: loginErrorMessage(error),
            },
          }));
          return false;
        }
      },

      async logout(): Promise<void> {
        const token = get().session.token;
        clearSession(null);
        if (token !== null) {
          try {
            await deps.api.logout(token);
          } catch {
            // La purge locale est déjà effective : un échec réseau serveur
            // ne doit jamais maintenir une session côté client.
          }
        }
      },

      expireSession(): void {
        clearSession(SESSION_EXPIRED_NOTICE);
      },

      async loadCustomers(): Promise<void> {
        const { session } = get();
        if (!isTokenUsable(session) || session.token === null) {
          set((state) => ({
            customers: {
              ...state.customers,
              items: null,
              accessDenied: true,
              error: ACCESS_DENIED_MESSAGE,
            },
          }));
          return;
        }
        const roles = session.user?.roles ?? [];
        if (!canReadCustomers(roles)) {
          set((state) => ({
            customers: {
              ...state.customers,
              items: null,
              status: 'ready',
              accessDenied: true,
              error: ACCESS_DENIED_MESSAGE,
            },
          }));
          return;
        }
        if (get().customers.status === 'loading') {
          return;
        }

        set((state) => ({
          customers: {
            ...state.customers,
            status: 'loading',
            error: null,
            accessDenied: false,
          },
        }));

        try {
          const items = await deps.api.listCustomers(session.token);
          set((state) => ({
            customers: {
              ...state.customers,
              items,
              status: 'ready',
              error: null,
            },
          }));
        } catch (error) {
          if (error instanceof UnauthorizedError) {
            handleUnauthorized();
            return;
          }
          if (error instanceof ForbiddenError) {
            set((state) => ({
              customers: {
                ...state.customers,
                items: null,
                status: 'ready',
                accessDenied: true,
                error: ACCESS_DENIED_MESSAGE,
              },
            }));
            return;
          }
          set((state) => ({
            customers: {
              ...state.customers,
              status: 'error',
              error: GENERIC_ERROR,
            },
          }));
        }
      },

      async createCustomer(
        input: CustomerCreateInput,
      ): Promise<Customer | null> {
        const { session } = get();
        if (!isTokenUsable(session) || session.token === null) {
          set((state) => ({
            customers: {
              ...state.customers,
              accessDenied: true,
              createError: ACCESS_DENIED_MESSAGE,
            },
          }));
          return null;
        }
        const roles = session.user?.roles ?? [];
        if (!canCreateCustomer(roles)) {
          set((state) => ({
            customers: {
              ...state.customers,
              createError: ACCESS_DENIED_MESSAGE,
            },
          }));
          return null;
        }

        const fieldErrors = validateCustomerForm(customerInputToForm(input));
        if (hasErrors(fieldErrors)) {
          set((state) => ({
            customers: {
              ...state.customers,
              fieldErrors,
              createError: 'Formulaire invalide.',
            },
          }));
          return null;
        }

        set((state) => ({
          customers: {
            ...state.customers,
            creating: true,
            createError: null,
            fieldErrors: {},
          },
        }));

        try {
          const created = await deps.api.createCustomer(session.token, input);
          set((state) => ({
            customers: {
              ...state.customers,
              items: state.customers.items
                ? [created, ...state.customers.items]
                : [created],
              status: 'ready',
              creating: false,
              createError: null,
              fieldErrors: {},
            },
          }));
          return created;
        } catch (error) {
          if (error instanceof UnauthorizedError) {
            handleUnauthorized();
            return null;
          }
          if (error instanceof ForbiddenError) {
            set((state) => ({
              customers: {
                ...state.customers,
                creating: false,
                accessDenied: true,
                createError: ACCESS_DENIED_MESSAGE,
              },
            }));
            return null;
          }
          if (error instanceof ValidationError) {
            set((state) => ({
              customers: {
                ...state.customers,
                creating: false,
                fieldErrors: mapServerFieldErrors(error.fieldErrors),
                createError: 'Le serveur a refusé les données saisies.',
              },
            }));
            return null;
          }
          set((state) => ({
            customers: {
              ...state.customers,
              creating: false,
              createError: GENERIC_ERROR,
            },
          }));
          return null;
        }
      },

      async loadAuditLogs(offset?: number): Promise<void> {
        const { session } = get();
        const start = offset ?? 0;
        if (!isTokenUsable(session) || session.token === null) {
          set((state) => ({
            audit: {
              ...state.audit,
              items: null,
              accessDenied: true,
              error: ACCESS_DENIED_MESSAGE,
            },
          }));
          return;
        }
        const roles = session.user?.roles ?? [];
        if (!canReadAudit(roles)) {
          set((state) => ({
            audit: {
              ...state.audit,
              items: null,
              status: 'ready',
              accessDenied: true,
              error: ACCESS_DENIED_MESSAGE,
            },
          }));
          return;
        }
        if (get().audit.status === 'loading') {
          return;
        }

        set((state) => ({
          audit: {
            ...state.audit,
            status: 'loading',
            error: null,
            accessDenied: false,
          },
        }));

        try {
          const batch = await deps.api.listAuditLogs(session.token, {
            limit: AUDIT_PAGE_SIZE,
            offset: start,
          });
          set((state) => {
            const merged =
              start === 0
                ? batch
                : [...(state.audit.items ?? []), ...batch];
            return {
              audit: {
                ...state.audit,
                items: merged,
                status: 'ready',
                offset: start + batch.length,
                hasMore: batch.length === AUDIT_PAGE_SIZE,
                error: null,
              },
            };
          });
        } catch (error) {
          if (error instanceof UnauthorizedError) {
            handleUnauthorized();
            return;
          }
          if (error instanceof ForbiddenError) {
            set((state) => ({
              audit: {
                ...state.audit,
                items: null,
                status: 'ready',
                accessDenied: true,
                error: ACCESS_DENIED_MESSAGE,
              },
            }));
            return;
          }
          set((state) => ({
            audit: {
              ...state.audit,
              status: 'error',
              error: GENERIC_ERROR,
            },
          }));
        }
      },

      async verifyAuditChain(): Promise<void> {
        const { session } = get();
        if (!isTokenUsable(session) || session.token === null) {
          set((state) => ({
            audit: {
              ...state.audit,
              verificationError: ACCESS_DENIED_MESSAGE,
            },
          }));
          return;
        }
        const roles = session.user?.roles ?? [];
        if (!canReadAudit(roles)) {
          set((state) => ({
            audit: {
              ...state.audit,
              verificationError: ACCESS_DENIED_MESSAGE,
            },
          }));
          return;
        }
        if (get().audit.verifying) {
          return;
        }

        set((state) => ({
          audit: {
            ...state.audit,
            verifying: true,
            verificationError: null,
          },
        }));

        try {
          const verification = await deps.api.verifyAuditChain(session.token);
          set((state) => ({
            audit: {
              ...state.audit,
              verifying: false,
              verification,
              verificationError: null,
            },
          }));
        } catch (error) {
          if (error instanceof UnauthorizedError) {
            handleUnauthorized();
            return;
          }
          set((state) => ({
            audit: {
              ...state.audit,
              verifying: false,
              verificationError:
                error instanceof ForbiddenError
                  ? ACCESS_DENIED_MESSAGE
                  : GENERIC_ERROR,
            },
          }));
        }
      },

      connectTelemetry(): void {
        if (get().session.token === null) {
          return;
        }
        socket.connect(() => get().session.token);
      },

      disconnectTelemetry(): void {
        socket.disconnect();
      },
    };
  });
}
