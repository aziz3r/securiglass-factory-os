import { useState, type FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router-dom';

import { translateNotice, useLocale } from '../i18n/i18n';
import { useAppStore } from '../store/StoreProvider';
import { selectIsAuthenticated } from '../store/selectors';
import {
  hasErrors,
  validateLoginForm,
  type LoginFormErrors,
  type LoginFormValues,
} from '../validation/forms';

export function LoginPage() {
  const { t, locale } = useLocale();
  const authenticated = useAppStore(selectIsAuthenticated);
  const authStatus = useAppStore((state) => state.session.status);
  const authError = useAppStore((state) => state.session.error);
  const notice = useAppStore((state) => state.session.notice);
  const login = useAppStore((state) => state.login);
  const navigate = useNavigate();

  const [values, setValues] = useState<LoginFormValues>({
    username: '',
    password: '',
  });
  const [errors, setErrors] = useState<LoginFormErrors>({});

  if (authenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const submitting = authStatus === 'authenticating';

  async function handleSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const nextErrors = validateLoginForm(values, locale);
    setErrors(nextErrors);
    if (hasErrors(nextErrors)) {
      return;
    }
    const success = await login({
      username: values.username.trim(),
      password: values.password,
    });
    if (success) {
      navigate('/dashboard', { replace: true });
    }
  }

  return (
    <div className="login-page">
      <section className="login-card" aria-labelledby="login-title">
        <div className="login-brand">
          <span className="brand-mark brand-mark--large" aria-hidden="true">
            SG
          </span>
          <div>
            <p className="eyebrow">{t('login.eyebrow')}</p>
            <h1 id="login-title">{t('login.title')}</h1>
            <p className="login-subtitle">{t('login.subtitle')}</p>
          </div>
        </div>

        {notice !== null ? (
          <div className="alert alert--warning" role="status">
            {translateNotice(notice, locale)}
          </div>
        ) : null}

        {authError !== null ? (
          <div className="alert alert--danger" role="alert">
            {translateNotice(authError, locale)}
          </div>
        ) : null}

        <form className="form" onSubmit={(event) => void handleSubmit(event)} noValidate>
          <div className="field">
            <label htmlFor="username">{t('login.username')}</label>
            <input
              id="username"
              name="username"
              type="text"
              autoComplete="username"
              spellCheck={false}
              maxLength={64}
              value={values.username}
              onChange={(event) => {
                setValues((current) => ({ ...current, username: event.target.value }));
                setErrors((current) => {
                  const next = { ...current };
                  delete next.username;
                  return next;
                });
              }}
              aria-invalid={errors.username !== undefined}
              aria-describedby={errors.username !== undefined ? 'username-error' : undefined}
              disabled={submitting}
              required
            />
            {errors.username !== undefined ? (
              <p className="field-error" id="username-error">
                {errors.username}
              </p>
            ) : null}
          </div>

          <div className="field">
            <label htmlFor="password">{t('login.password')}</label>
            <input
              id="password"
              name="password"
              type="password"
              autoComplete="current-password"
              maxLength={256}
              value={values.password}
              onChange={(event) => {
                setValues((current) => ({ ...current, password: event.target.value }));
                setErrors((current) => {
                  const next = { ...current };
                  delete next.password;
                  return next;
                });
              }}
              aria-invalid={errors.password !== undefined}
              aria-describedby={errors.password !== undefined ? 'password-error' : undefined}
              disabled={submitting}
              required
            />
            {errors.password !== undefined ? (
              <p className="field-error" id="password-error">
                {errors.password}
              </p>
            ) : null}
          </div>

          <button type="submit" className="button button--primary button--block" disabled={submitting}>
            {submitting ? t('login.submitting') : t('login.submit')}
          </button>
        </form>

        <div className="login-security">
          <p>
            <strong>{t('login.sessionNote.title')}</strong> {t('login.sessionNote.body')}
          </p>
          <p className="muted">{t('login.transport')}</p>
        </div>
      </section>

      <aside className="login-aside" aria-label={t('login.aside.label')}>
        <p className="eyebrow">{t('login.aside.eyebrow')}</p>
        <h2>{t('login.aside.title')}</h2>
        <ul className="security-list">
          <li>{t('login.aside.item1')}</li>
          <li>{t('login.aside.item2')}</li>
          <li>{t('login.aside.item3')}</li>
          <li>{t('login.aside.item4')}</li>
        </ul>
        <p className="login-aside-footer">{t('login.aside.footer')}</p>
      </aside>
    </div>
  );
}
