/** Formatage d'affichage (les données restent rendues comme texte par React). */

import type { Locale } from '../i18n/i18n';

const INTL_LOCALE: Readonly<Record<Locale, string>> = { fr: 'fr-FR', en: 'en-GB' };

const DATE_TIME_FORMATTERS: Readonly<Record<Locale, Intl.DateTimeFormat>> = {
  fr: new Intl.DateTimeFormat(INTL_LOCALE.fr, { dateStyle: 'short', timeStyle: 'medium' }),
  en: new Intl.DateTimeFormat(INTL_LOCALE.en, { dateStyle: 'short', timeStyle: 'medium' }),
};

const NUMBER_FORMATTERS: Readonly<Record<Locale, Intl.NumberFormat>> = {
  fr: new Intl.NumberFormat(INTL_LOCALE.fr, { maximumFractionDigits: 2 }),
  en: new Intl.NumberFormat(INTL_LOCALE.en, { maximumFractionDigits: 2 }),
};

export const EMPTY_VALUE = '—';

export function formatDateTime(value: string | null, locale: Locale = 'fr'): string {
  if (value === null || value.length === 0) {
    return EMPTY_VALUE;
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return EMPTY_VALUE;
  }
  return DATE_TIME_FORMATTERS[locale].format(date);
}

export function formatNumber(value: number | null, unit = '', locale: Locale = 'fr'): string {
  if (value === null || !Number.isFinite(value)) {
    return EMPTY_VALUE;
  }
  const formatted = NUMBER_FORMATTERS[locale].format(value);
  return unit.length > 0 ? `${formatted} ${unit}` : formatted;
}

/** Formate un nombre entier localisé (ex. quantités de vitres commandées). */
export function formatInteger(value: number, locale: Locale = 'fr'): string {
  return new Intl.NumberFormat(INTL_LOCALE[locale], { maximumFractionDigits: 0 }).format(value);
}

export function truncateMiddle(value: string, maxLength = 20): string {
  if (value.length <= maxLength) {
    return value;
  }
  const half = Math.floor((maxLength - 1) / 2);
  return `${value.slice(0, half)}…${value.slice(value.length - half)}`;
}

export function formatDetails(
  details: Record<string, unknown> | null,
  maxLength = 180,
  locale: Locale = 'fr',
): string {
  if (details === null) {
    return EMPTY_VALUE;
  }
  let serialized: string;
  try {
    serialized = JSON.stringify(details) ?? EMPTY_VALUE;
  } catch {
    return locale === 'fr' ? 'Détails illisibles' : 'Unreadable details';
  }
  return serialized.length > maxLength
    ? `${serialized.slice(0, maxLength)}…`
    : serialized;
}

export function formatRoleList(roles: readonly string[], locale: Locale = 'fr'): string {
  if (roles.length > 0) {
    return roles.join(', ');
  }
  return locale === 'fr' ? 'Aucun rôle' : 'No role';
}

export function formatBoolean(value: boolean, locale: Locale = 'fr'): string {
  if (locale === 'fr') {
    return value ? 'Actif' : 'Inactif';
  }
  return value ? 'Active' : 'Inactive';
}
