/**
 * Rôles et capacités côté client.
 *
 * Le client ne fait JAMAIS autorité : le backend applique `require_roles`.
 * Ces helpers servent uniquement à masquer les écrans et à empêcher les appels
 * réseau inutiles (défense en profondeur + UX). Toute action reste revérifiée
 * côté serveur (403).
 */

import { translate, type Locale } from '../i18n/i18n';

export const ROLES = [
  'SUPER_ADMIN',
  'SECURITY_AUDITOR',
  'PLANT_MANAGER',
  'OT_OPERATOR',
  'QUALITY_INSPECTOR',
  'SERVICE_ACCOUNT_EDGE',
] as const;

export type Role = (typeof ROLES)[number];

export const ROLE_DESCRIPTIONS: Readonly<Record<Role, string>> = {
  SUPER_ADMIN: 'Vous avez accès à l’ensemble de la console, y compris la sécurité.',
  SECURITY_AUDITOR: 'Vous contrôlez la sécurité : alertes, conformité et journal d’audit.',
  PLANT_MANAGER: 'Vous pilotez l’usine : production, stocks, commandes et clients.',
  OT_OPERATOR: 'Vous conduisez la ligne : suivi du four, stocks et assistant technique.',
  QUALITY_INSPECTOR: 'Vous contrôlez la qualité : suivi du four et de ses anomalies.',
  SERVICE_ACCOUNT_EDGE: 'Compte technique de la passerelle : aucun accès à la console.',
};

export const ROLE_LABELS: Readonly<Record<Role, string>> = {
  SUPER_ADMIN: 'Super administrateur',
  SECURITY_AUDITOR: 'Auditeur sécurité',
  PLANT_MANAGER: 'Responsable usine',
  OT_OPERATOR: 'Opérateur OT',
  QUALITY_INSPECTOR: 'Inspecteur qualité',
  SERVICE_ACCOUNT_EDGE: 'Compte de service Edge',
};

const CUSTOMER_READERS: ReadonlySet<Role> = new Set<Role>([
  'PLANT_MANAGER',
  'SUPER_ADMIN',
  'SECURITY_AUDITOR',
]);

const AUDIT_READERS: ReadonlySet<Role> = new Set<Role>([
  'SUPER_ADMIN',
  'SECURITY_AUDITOR',
]);

/** Libellé du rôle dans la langue courante (FR par défaut via `ROLE_LABELS`). */
export function getRoleLabel(locale: Locale, role: Role): string {
  return translate(locale, `role.${role}.label`);
}

/** Description du rôle dans la langue courante. */
export function getRoleDescription(locale: Locale, role: Role): string {
  return translate(locale, `role.${role}.description`);
}

export function isRole(value: string): value is Role {
  return (ROLES as readonly string[]).includes(value);
}

/**
 * Filtre les rôles inconnus renvoyés par le serveur et déduplique.
 * Un rôle non reconnu est ignoré (fail-closed : il n'ouvre aucun droit).
 */
export function normalizeRoles(raw: readonly unknown[]): Role[] {
  const roles: Role[] = [];
  for (const value of raw) {
    if (typeof value === 'string' && isRole(value) && !roles.includes(value)) {
      roles.push(value);
    }
  }
  return roles;
}

export function hasAnyRole(
  roles: readonly Role[],
  allowed: readonly Role[],
): boolean {
  return roles.some((role) => allowed.includes(role));
}

export function canReadCustomers(roles: readonly Role[]): boolean {
  return roles.some((role) => CUSTOMER_READERS.has(role));
}

export function canCreateCustomer(roles: readonly Role[]): boolean {
  return roles.includes('PLANT_MANAGER');
}

export function canReadAudit(roles: readonly Role[]): boolean {
  return roles.some((role) => AUDIT_READERS.has(role));
}

const PRODUCTION_VIEWERS: ReadonlySet<Role> = new Set<Role>([
  'SUPER_ADMIN',
  'PLANT_MANAGER',
  'OT_OPERATOR',
  'QUALITY_INSPECTOR',
]);
const STOCK_VIEWERS: ReadonlySet<Role> = new Set<Role>([
  'SUPER_ADMIN',
  'PLANT_MANAGER',
  'OT_OPERATOR',
]);
const SALES_VIEWERS: ReadonlySet<Role> = new Set<Role>(['SUPER_ADMIN', 'PLANT_MANAGER']);
const ASSISTANT_USERS: ReadonlySet<Role> = new Set<Role>([
  'SUPER_ADMIN',
  'PLANT_MANAGER',
  'OT_OPERATOR',
]);
const SECURITY_VIEWERS: ReadonlySet<Role> = new Set<Role>(['SUPER_ADMIN', 'SECURITY_AUDITOR']);

/** Suivi du four : courbes, jauges, diagnostic. */
export function canViewProduction(roles: readonly Role[]): boolean {
  return roles.some((role) => PRODUCTION_VIEWERS.has(role));
}

export function canViewStock(roles: readonly Role[]): boolean {
  return roles.some((role) => STOCK_VIEWERS.has(role));
}

/** Commandes et prise de commande. */
export function canViewSales(roles: readonly Role[]): boolean {
  return roles.some((role) => SALES_VIEWERS.has(role));
}

export function canUseAssistant(roles: readonly Role[]): boolean {
  return roles.some((role) => ASSISTANT_USERS.has(role));
}

/** Alertes SOC, conformité, cartographie réseau. */
export function canViewSecurity(roles: readonly Role[]): boolean {
  return roles.some((role) => SECURITY_VIEWERS.has(role));
}

export function canAccessDashboard(roles: readonly Role[]): boolean {
  return roles.length > 0;
}
