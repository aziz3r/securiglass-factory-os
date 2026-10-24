import { describe, expect, it } from 'vitest';

import {
  EMPTY_VALUE,
  formatBoolean,
  formatDateTime,
  formatDetails,
  formatNumber,
  formatRoleList,
  truncateMiddle,
} from './format';

describe('formatage', () => {
  it('formate les dates valides et signale les invalides', () => {
    expect(formatDateTime('2026-10-24T10:20:00Z')).toContain('24/10/2026');
    expect(formatDateTime(null)).toBe(EMPTY_VALUE);
    expect(formatDateTime('')).toBe(EMPTY_VALUE);
    expect(formatDateTime('pas-une-date')).toBe(EMPTY_VALUE);
  });

  it('formate les nombres avec unité', () => {
    expect(formatNumber(712.5, '°C')).toContain('712,5');
    expect(formatNumber(712.5, '°C')).toContain('°C');
    expect(formatNumber(null)).toBe(EMPTY_VALUE);
    expect(formatNumber(Number.POSITIVE_INFINITY)).toBe(EMPTY_VALUE);
  });

  it('tronque au milieu sans dépasser la taille', () => {
    expect(truncateMiddle('abcdef', 20)).toBe('abcdef');
    const truncated = truncateMiddle('a'.repeat(64), 18);
    expect(truncated.length).toBeLessThanOrEqual(18);
    expect(truncated).toContain('…');
  });

  it('sérialise les détails en texte et borne la taille', () => {
    expect(formatDetails(null)).toBe(EMPTY_VALUE);
    expect(formatDetails({ a: 1 })).toBe('{"a":1}');
    expect(formatDetails({ long: 'x'.repeat(300) }, 20).length).toBe(21);
    const circular: Record<string, unknown> = {};
    circular['self'] = circular;
    expect(formatDetails(circular)).toBe('Détails illisibles');
  });

  it('formate les rôles et booléens', () => {
    expect(formatRoleList([])).toBe('Aucun rôle');
    expect(formatRoleList(['SUPER_ADMIN', 'SECURITY_AUDITOR'])).toBe(
      'SUPER_ADMIN, SECURITY_AUDITOR',
    );
    expect(formatBoolean(true)).toBe('Actif');
    expect(formatBoolean(false)).toBe('Inactif');
  });
});
