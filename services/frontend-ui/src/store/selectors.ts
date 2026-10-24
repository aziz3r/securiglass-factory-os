/**
 * Sélecteurs typés — point d'accès unique des composants aux slices.
 *
 * Les sélecteurs de données sensibles réappliquent le contrôle de rôle : même
 * si un état corrompu contenait des clients, un opérateur OT ne pourrait pas
 * les lire depuis l'UI. (Le store purge aussi ces données à la déconnexion.)
 */

import type { AuditLog, CurrentUser, Customer } from '../api/types';
import type { Role } from '../security/roles';
import {
  canCreateCustomer,
  canReadAudit,
  canReadCustomers,
} from '../security/roles';
import type { AppStore } from './createAppStore';

const EMPTY_ROLES: readonly Role[] = Object.freeze([]);

export function selectIsAuthenticated(state: AppStore): boolean {
  return state.session.token !== null && state.session.user !== null;
}

export function selectToken(state: AppStore): string | null {
  return state.session.token;
}

export function selectUser(state: AppStore): CurrentUser | null {
  return state.session.user;
}

export function selectRoles(state: AppStore): readonly Role[] {
  return state.session.user?.roles ?? EMPTY_ROLES;
}

export function selectCanReadCustomers(state: AppStore): boolean {
  return selectIsAuthenticated(state) && canReadCustomers(selectRoles(state));
}

export function selectCanCreateCustomer(state: AppStore): boolean {
  return selectIsAuthenticated(state) && canCreateCustomer(selectRoles(state));
}

export function selectCanReadAudit(state: AppStore): boolean {
  return selectIsAuthenticated(state) && canReadAudit(selectRoles(state));
}

/**
 * Retourne null si le rôle courant n'a pas le droit de lire les clients.
 * C'est le seul sélecteur autorisé pour afficher la liste clients.
 */
export function selectVisibleCustomers(state: AppStore): Customer[] | null {
  if (!selectCanReadCustomers(state)) {
    return null;
  }
  return state.customers.items;
}

export function selectVisibleAuditLogs(state: AppStore): AuditLog[] | null {
  if (!selectCanReadAudit(state)) {
    return null;
  }
  return state.audit.items;
}
