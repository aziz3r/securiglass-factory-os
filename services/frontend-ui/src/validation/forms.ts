/**
 * Validation de formulaires côté client.
 *
 * Ces règles reproduisent (sans les remplacer) les contraintes Pydantic du
 * backend. Le serveur reste l'autorité : une erreur 422 est remappée par champ.
 * Aucune valeur n'est interprétée comme du HTML.
 */

import type { CustomerCreateInput } from '../api/types';
import { translate, type Locale } from '../i18n/i18n';

export interface CustomerFormValues {
  company_name: string;
  contact_name: string;
  email: string;
  phone: string;
  vat_number: string;
  country_code: string;
}

export type CustomerFormField =
  | 'company_name'
  | 'contact_name'
  | 'email'
  | 'phone'
  | 'vat_number'
  | 'country_code';

export type CustomerFormErrors = Partial<Record<CustomerFormField, string>>;

export interface LoginFormValues {
  username: string;
  password: string;
}

export type LoginFormErrors = Partial<Record<'username' | 'password', string>>;

export const EMPTY_CUSTOMER_FORM: CustomerFormValues = {
  company_name: '',
  contact_name: '',
  email: '',
  phone: '',
  vat_number: '',
  country_code: 'FR',
};

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const PHONE_PATTERN = /^\+?[0-9 .\-()]{6,32}$/;
const COUNTRY_PATTERN = /^[A-Z]{2}$/;

function trimmed(value: string): string {
  return value.trim();
}

export function validateCustomerForm(
  values: CustomerFormValues,
  locale: Locale = 'fr',
): CustomerFormErrors {
  const errors: CustomerFormErrors = {};
  const company = trimmed(values.company_name);
  const contact = trimmed(values.contact_name);
  const email = trimmed(values.email);
  const phone = trimmed(values.phone);
  const vat = trimmed(values.vat_number);
  const country = trimmed(values.country_code).toUpperCase();

  if (company.length < 1 || company.length > 128) {
    errors.company_name = translate(locale, 'customers.form.companyName.error');
  }
  if (contact.length < 1 || contact.length > 128) {
    errors.contact_name = translate(locale, 'customers.form.contactName.error');
  }
  if (email.length > 254 || !EMAIL_PATTERN.test(email)) {
    errors.email = translate(locale, 'customers.form.email.error');
  }
  if (phone.length > 0 && !PHONE_PATTERN.test(phone)) {
    errors.phone = translate(locale, 'customers.form.phone.error');
  }
  if (vat.length > 32) {
    errors.vat_number = translate(locale, 'customers.form.vat.error');
  }
  if (!COUNTRY_PATTERN.test(country)) {
    errors.country_code = translate(locale, 'customers.form.country.error');
  }

  return errors;
}

export function validateLoginForm(
  values: LoginFormValues,
  locale: Locale = 'fr',
): LoginFormErrors {
  const errors: LoginFormErrors = {};
  const username = trimmed(values.username);
  if (username.length < 3 || username.length > 64) {
    errors.username = translate(locale, 'validation.username');
  }
  if (values.password.length < 1 || values.password.length > 256) {
    errors.password = translate(locale, 'validation.password');
  }
  return errors;
}

export function hasErrors(errors: object): boolean {
  return Object.keys(errors).length > 0;
}

export function toCustomerCreateInput(
  values: CustomerFormValues,
): CustomerCreateInput {
  const input: CustomerCreateInput = {
    company_name: trimmed(values.company_name),
    contact_name: trimmed(values.contact_name),
    email: trimmed(values.email),
    country_code: trimmed(values.country_code).toUpperCase(),
  };
  const phone = trimmed(values.phone);
  if (phone.length > 0) {
    input.phone = phone;
  }
  const vat = trimmed(values.vat_number);
  if (vat.length > 0) {
    input.vat_number = vat;
  }
  return input;
}

const SERVER_FIELD_ALIASES: Readonly<Record<string, CustomerFormField>> = {
  company_name: 'company_name',
  contact_name: 'contact_name',
  email: 'email',
  phone: 'phone',
  vat_number: 'vat_number',
  country_code: 'country_code',
};

/** Remappe les erreurs 422 du backend (clés snake_case) vers le formulaire. */
export function mapServerFieldErrors(
  serverErrors: Readonly<Record<string, string>> | null,
): CustomerFormErrors {
  const errors: CustomerFormErrors = {};
  if (serverErrors === null) {
    return errors;
  }
  for (const [key, message] of Object.entries(serverErrors)) {
    const field = SERVER_FIELD_ALIASES[key];
    if (field !== undefined) {
      errors[field] = message;
    }
  }
  return errors;
}
