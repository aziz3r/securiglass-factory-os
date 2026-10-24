import { useEffect, useState, type FormEvent } from 'react';

import { PageHeader } from '../components/PageHeader';
import { StatusBadge } from '../components/StatusBadge';
import { useLocale } from '../i18n/i18n';
import { useAppStore } from '../store/StoreProvider';
import {
  selectCanCreateCustomer,
  selectVisibleCustomers,
} from '../store/selectors';
import {
  EMPTY_CUSTOMER_FORM,
  hasErrors,
  toCustomerCreateInput,
  validateCustomerForm,
  type CustomerFormErrors,
  type CustomerFormField,
  type CustomerFormValues,
} from '../validation/forms';
import { EMPTY_VALUE, formatBoolean, formatDateTime } from '../utils/format';

const FIELD_LABEL_KEYS: Readonly<Record<CustomerFormField, string>> = {
  company_name: 'customers.form.companyName',
  contact_name: 'customers.form.contactName',
  email: 'customers.form.email',
  phone: 'customers.form.phone',
  vat_number: 'customers.form.vat',
  country_code: 'customers.form.country',
};

export function CustomersPage() {
  const { t, locale } = useLocale();
  const canCreate = useAppStore(selectCanCreateCustomer);
  const customers = useAppStore(selectVisibleCustomers);
  const status = useAppStore((state) => state.customers.status);
  const error = useAppStore((state) => state.customers.error);
  const accessDenied = useAppStore((state) => state.customers.accessDenied);
  const creating = useAppStore((state) => state.customers.creating);
  const createError = useAppStore((state) => state.customers.createError);
  const serverErrors = useAppStore((state) => state.customers.fieldErrors);
  const loadCustomers = useAppStore((state) => state.loadCustomers);
  const createCustomer = useAppStore((state) => state.createCustomer);

  const [values, setValues] = useState<CustomerFormValues>({
    ...EMPTY_CUSTOMER_FORM,
  });
  const [errors, setErrors] = useState<CustomerFormErrors>({});
  const [success, setSuccess] = useState<string | null>(null);

  useEffect(() => {
    void loadCustomers();
  }, [loadCustomers]);

  function updateField(field: CustomerFormField, value: string): void {
    setValues((current) => ({ ...current, [field]: value }));
    setErrors((current) => {
      if (current[field] === undefined) {
        return current;
      }
      const next = { ...current };
      delete next[field];
      return next;
    });
    setSuccess(null);
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const validation = validateCustomerForm(values, locale);
    setErrors(validation);
    setSuccess(null);
    if (hasErrors(validation)) {
      return;
    }
    const created = await createCustomer(toCustomerCreateInput(values));
    if (created !== null) {
      setValues({ ...EMPTY_CUSTOMER_FORM });
      setSuccess(t('customers.form.created', { name: created.company_name }));
    }
  }

  function displayError(field: CustomerFormField): string | undefined {
    return errors[field] ?? serverErrors[field];
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow={t('customers.eyebrow')}
        title={t('customers.title')}
        description={t('customers.description')}
        actions={
          <button
            type="button"
            className="button button--ghost"
            onClick={() => void loadCustomers()}
            disabled={status === 'loading'}
          >
            {status === 'loading' ? t('customers.loading') : t('customers.refresh')}
          </button>
        }
      />

      {accessDenied ? (
        <div className="alert alert--danger" role="alert">
          {error ?? t('customers.accessDenied')}
        </div>
      ) : null}

      {success !== null ? (
        <div className="alert alert--success" role="status">
          {success}
        </div>
      ) : null}

      <div className="split-layout">
        <section className="panel" aria-labelledby="customer-list-title">
          <div className="panel-heading">
            <h2 id="customer-list-title">{t('customers.list.title')}</h2>
            <span className="muted small">
              {customers !== null ? t('customers.list.count', { count: customers.length }) : EMPTY_VALUE}
            </span>
          </div>

          {status === 'error' ? (
            <div className="alert alert--danger" role="alert">
              {error ?? t('customers.loadFailed')}
            </div>
          ) : null}

          {status === 'loading' && customers === null ? (
            <p className="muted" role="status">
              {t('customers.loadingList')}
            </p>
          ) : null}

          {customers !== null && customers.length === 0 ? (
            <p className="muted">{t('customers.none')}</p>
          ) : null}

          {customers !== null && customers.length > 0 ? (
            <div className="table-wrapper">
              <table className="data-table">
                <caption className="sr-only">{t('customers.list.caption')}</caption>
                <thead>
                  <tr>
                    <th scope="col">{t('customers.table.company')}</th>
                    <th scope="col">{t('customers.table.contact')}</th>
                    <th scope="col">{t('customers.table.email')}</th>
                    <th scope="col">{t('customers.table.phone')}</th>
                    <th scope="col">{t('customers.table.country')}</th>
                    <th scope="col">{t('customers.table.state')}</th>
                    <th scope="col">{t('customers.table.createdAt')}</th>
                  </tr>
                </thead>
                <tbody>
                  {customers.map((customer) => (
                    <tr key={customer.id}>
                      <th scope="row">{customer.company_name}</th>
                      <td>{customer.contact_name}</td>
                      <td className="mono">{customer.email}</td>
                      <td className="mono">{customer.phone ?? EMPTY_VALUE}</td>
                      <td>{customer.country_code}</td>
                      <td>
                        <StatusBadge tone={customer.is_active ? 'ok' : 'neutral'}>
                          {formatBoolean(customer.is_active, locale)}
                        </StatusBadge>
                      </td>
                      <td>{formatDateTime(customer.created_at, locale)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </section>

        <section className="panel" aria-labelledby="customer-create-title">
          <div className="panel-heading">
            <h2 id="customer-create-title">{t('customers.new.title')}</h2>
            <StatusBadge tone={canCreate ? 'info' : 'neutral'}>
              {canCreate ? 'PLANT_MANAGER' : t('role.readOnly')}
            </StatusBadge>
          </div>

          {!canCreate ? (
            <p className="muted">{t('customers.new.readOnly')}</p>
          ) : (
            <>
              {createError !== null ? (
                <div className="alert alert--danger" role="alert">
                  {createError}
                </div>
              ) : null}

              <form className="form form--grid" onSubmit={(event) => void handleSubmit(event)} noValidate>
                <div className="field field--full">
                  <label htmlFor="company_name">{t(FIELD_LABEL_KEYS.company_name)}</label>
                  <input
                    id="company_name"
                    name="company_name"
                    type="text"
                    maxLength={128}
                    value={values.company_name}
                    onChange={(event) => updateField('company_name', event.target.value)}
                    aria-invalid={displayError('company_name') !== undefined}
                    aria-describedby={
                      displayError('company_name') !== undefined
                        ? 'company_name-error'
                        : undefined
                    }
                    disabled={creating}
                    required
                  />
                  {displayError('company_name') !== undefined ? (
                    <p className="field-error" id="company_name-error">
                      {displayError('company_name')}
                    </p>
                  ) : null}
                </div>

                <div className="field">
                  <label htmlFor="contact_name">{t(FIELD_LABEL_KEYS.contact_name)}</label>
                  <input
                    id="contact_name"
                    name="contact_name"
                    type="text"
                    maxLength={128}
                    value={values.contact_name}
                    onChange={(event) => updateField('contact_name', event.target.value)}
                    aria-invalid={displayError('contact_name') !== undefined}
                    disabled={creating}
                    required
                  />
                  {displayError('contact_name') !== undefined ? (
                    <p className="field-error">{displayError('contact_name')}</p>
                  ) : null}
                </div>

                <div className="field">
                  <label htmlFor="email">{t(FIELD_LABEL_KEYS.email)}</label>
                  <input
                    id="email"
                    name="email"
                    type="email"
                    autoComplete="email"
                    maxLength={254}
                    value={values.email}
                    onChange={(event) => updateField('email', event.target.value)}
                    aria-invalid={displayError('email') !== undefined}
                    disabled={creating}
                    required
                  />
                  {displayError('email') !== undefined ? (
                    <p className="field-error">{displayError('email')}</p>
                  ) : null}
                </div>

                <div className="field">
                  <label htmlFor="phone">{t(FIELD_LABEL_KEYS.phone)}</label>
                  <input
                    id="phone"
                    name="phone"
                    type="tel"
                    maxLength={32}
                    value={values.phone}
                    onChange={(event) => updateField('phone', event.target.value)}
                    aria-invalid={displayError('phone') !== undefined}
                    disabled={creating}
                  />
                  {displayError('phone') !== undefined ? (
                    <p className="field-error">{displayError('phone')}</p>
                  ) : null}
                </div>

                <div className="field">
                  <label htmlFor="vat_number">{t(FIELD_LABEL_KEYS.vat_number)}</label>
                  <input
                    id="vat_number"
                    name="vat_number"
                    type="text"
                    maxLength={32}
                    value={values.vat_number}
                    onChange={(event) => updateField('vat_number', event.target.value)}
                    aria-invalid={displayError('vat_number') !== undefined}
                    disabled={creating}
                  />
                  {displayError('vat_number') !== undefined ? (
                    <p className="field-error">{displayError('vat_number')}</p>
                  ) : null}
                </div>

                <div className="field">
                  <label htmlFor="country_code">{t(FIELD_LABEL_KEYS.country_code)}</label>
                  <input
                    id="country_code"
                    name="country_code"
                    type="text"
                    maxLength={2}
                    value={values.country_code}
                    onChange={(event) =>
                      updateField('country_code', event.target.value.toUpperCase())
                    }
                    aria-invalid={displayError('country_code') !== undefined}
                    disabled={creating}
                    required
                  />
                  {displayError('country_code') !== undefined ? (
                    <p className="field-error">{displayError('country_code')}</p>
                  ) : null}
                </div>

                <div className="form-actions field--full">
                  <button type="submit" className="button button--primary" disabled={creating}>
                    {creating ? t('customers.form.submitting') : t('customers.form.submit')}
                  </button>
                  <p className="muted small">{t('customers.form.encryptedNote')}</p>
                </div>
              </form>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
