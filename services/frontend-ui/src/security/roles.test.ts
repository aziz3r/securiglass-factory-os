import { describe, expect, it } from 'vitest';

import {
  canAccessDashboard,
  canCreateCustomer,
  canReadAudit,
  canReadCustomers,
  hasAnyRole,
  isRole,
  normalizeRoles,
  ROLE_LABELS,
  ROLES,
} from './roles';

describe('rôles et capacités', () => {
  it('reconnaît uniquement les rôles connus', () => {
    for (const role of ROLES) {
      expect(isRole(role)).toBe(true);
      expect(ROLE_LABELS[role].length).toBeGreaterThan(0);
    }
    expect(isRole('ROOT')).toBe(false);
  });

  it('filtre et déduplique les rôles serveur (fail-closed)', () => {
    expect(
      normalizeRoles(['PLANT_MANAGER', 'PLANT_MANAGER', 'HACKER', 42, null, 'OT_OPERATOR']),
    ).toEqual(['PLANT_MANAGER', 'OT_OPERATOR']);
    expect(normalizeRoles(['inconnu'])).toEqual([]);
  });

  it('applique la matrice de lecture clients', () => {
    expect(canReadCustomers(['PLANT_MANAGER'])).toBe(true);
    expect(canReadCustomers(['SUPER_ADMIN'])).toBe(true);
    expect(canReadCustomers(['SECURITY_AUDITOR'])).toBe(true);
    expect(canReadCustomers(['OT_OPERATOR'])).toBe(false);
    expect(canReadCustomers(['QUALITY_INSPECTOR'])).toBe(false);
    expect(canReadCustomers(['SERVICE_ACCOUNT_EDGE'])).toBe(false);
  });

  it('réserve la création au PLANT_MANAGER', () => {
    expect(canCreateCustomer(['PLANT_MANAGER'])).toBe(true);
    expect(canCreateCustomer(['SUPER_ADMIN'])).toBe(false);
  });

  it('réserve l’audit aux auditeurs et super-admins', () => {
    expect(canReadAudit(['SECURITY_AUDITOR'])).toBe(true);
    expect(canReadAudit(['SUPER_ADMIN'])).toBe(true);
    expect(canReadAudit(['PLANT_MANAGER'])).toBe(false);
  });

  it('vérifie l’intersection de rôles et l’accès au tableau de bord', () => {
    expect(hasAnyRole(['OT_OPERATOR'], ['SUPER_ADMIN', 'OT_OPERATOR'])).toBe(true);
    expect(hasAnyRole([], ['SUPER_ADMIN'])).toBe(false);
    expect(canAccessDashboard(['OT_OPERATOR'])).toBe(true);
    expect(canAccessDashboard([])).toBe(false);
  });
});

describe('accès par rubrique (besoin d’en connaître)', () => {
  it('limite chaque rubrique aux rôles qui en ont besoin', async () => {
    const r = await import('./roles');
    expect(r.canViewProduction(['QUALITY_INSPECTOR'])).toBe(true);
    expect(r.canViewProduction(['SECURITY_AUDITOR'])).toBe(false);
    expect(r.canViewStock(['OT_OPERATOR'])).toBe(true);
    expect(r.canViewStock(['QUALITY_INSPECTOR'])).toBe(false);
    expect(r.canViewSales(['PLANT_MANAGER'])).toBe(true);
    expect(r.canViewSales(['OT_OPERATOR'])).toBe(false);
    expect(r.canUseAssistant(['OT_OPERATOR'])).toBe(true);
    expect(r.canUseAssistant(['SECURITY_AUDITOR'])).toBe(false);
    expect(r.canViewSecurity(['SECURITY_AUDITOR'])).toBe(true);
    expect(r.canViewSecurity(['PLANT_MANAGER'])).toBe(false);
    for (const role of ROLES) {
      expect(r.ROLE_DESCRIPTIONS[role].length).toBeGreaterThan(0);
    }
  });

  it('le compte de service n’a accès à aucune rubrique', async () => {
    const r = await import('./roles');
    const edge = ['SERVICE_ACCOUNT_EDGE'] as const;
    expect(
      [r.canViewProduction, r.canViewStock, r.canViewSales, r.canUseAssistant, r.canViewSecurity].some(
        (check) => check(edge),
      ),
    ).toBe(false);
  });
});
