import { describe, expect, it } from 'vitest';

import {
  EMPTY_CUSTOMER_FORM,
  hasErrors,
  mapServerFieldErrors,
  toCustomerCreateInput,
  validateCustomerForm,
  validateLoginForm,
  type CustomerFormValues,
} from './forms';

const VALID: CustomerFormValues = {
  company_name: '  Vitrerie du Rhône  ',
  contact_name: 'Camille Martin',
  email: 'camille@vitrerie.example',
  phone: '+33 4 72 00 00 00',
  vat_number: 'FR12345678901',
  country_code: 'fr',
};

describe('validation du formulaire client', () => {
  it('accepte un formulaire valide et normalise les valeurs', () => {
    expect(validateCustomerForm(VALID)).toEqual({});
    const input = toCustomerCreateInput(VALID);
    expect(input).toEqual({
      company_name: 'Vitrerie du Rhône',
      contact_name: 'Camille Martin',
      email: 'camille@vitrerie.example',
      phone: '+33 4 72 00 00 00',
      vat_number: 'FR12345678901',
      country_code: 'FR',
    });
  });

  it('omet les champs optionnels vides', () => {
    const input = toCustomerCreateInput({
      ...VALID,
      phone: '   ',
      vat_number: '',
    });
    expect(input.phone).toBeUndefined();
    expect(input.vat_number).toBeUndefined();
  });

  it('signale les champs requis vides ou trop longs', () => {
    const errors = validateCustomerForm({
      ...EMPTY_CUSTOMER_FORM,
      company_name: '   ',
      contact_name: 'x'.repeat(129),
    });
    expect(errors.company_name).toBeDefined();
    expect(errors.contact_name).toBeDefined();
    expect(errors.email).toBeDefined();
  });

  it('rejette un e-mail invalide', () => {
    expect(validateCustomerForm({ ...VALID, email: 'nope' }).email).toBeDefined();
    expect(
      validateCustomerForm({ ...VALID, email: 'a@b' }).email,
    ).toBeDefined();
    expect(
      validateCustomerForm({ ...VALID, email: `${'a'.repeat(250)}@x.test` }).email,
    ).toBeDefined();
  });

  it('rejette un téléphone hors format', () => {
    expect(validateCustomerForm({ ...VALID, phone: 'abc' }).phone).toBeDefined();
    expect(
      validateCustomerForm({ ...VALID, phone: '123' }).phone,
    ).toBeDefined();
  });

  it('rejette un code pays non ISO-2 et une TVA trop longue', () => {
    const errors = validateCustomerForm({
      ...VALID,
      country_code: 'FRA',
      vat_number: 'x'.repeat(33),
    });
    expect(errors.country_code).toBeDefined();
    expect(errors.vat_number).toBeDefined();
  });

  it('hasErrors détecte un objet vide', () => {
    expect(hasErrors({})).toBe(false);
    expect(hasErrors({ email: 'x' })).toBe(true);
  });
});

describe('validation du formulaire de connexion', () => {
  it('accepte des identifiants conformes', () => {
    expect(validateLoginForm({ username: 'manager', password: 'x' })).toEqual({});
  });

  it('rejette un identifiant trop court et un mot de passe vide', () => {
    const errors = validateLoginForm({ username: ' ab ', password: '' });
    expect(errors.username).toBeDefined();
    expect(errors.password).toBeDefined();
  });

  it('rejette un mot de passe trop long', () => {
    expect(
      validateLoginForm({ username: 'manager', password: 'x'.repeat(257) }).password,
    ).toBeDefined();
  });
});

describe('remappage des erreurs serveur', () => {
  it('convertit les clés Pydantic connues', () => {
    expect(
      mapServerFieldErrors({
        email: 'invalide',
        company_name: 'requis',
        champ_inconnu: 'ignoré',
      }),
    ).toEqual({ email: 'invalide', company_name: 'requis' });
  });

  it('retourne un objet vide sans erreurs', () => {
    expect(mapServerFieldErrors(null)).toEqual({});
  });
});
