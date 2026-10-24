import { Link } from 'react-router-dom';

import { useLocale } from '../i18n/i18n';
import { getRoleLabel } from '../security/roles';
import { useAppStore } from '../store/StoreProvider';
import { selectRoles } from '../store/selectors';

export function AccessDeniedPage() {
  const { t, locale } = useLocale();
  const roles = useAppStore(selectRoles);

  return (
    <div className="page page--centered">
      <section className="state-card state-card--danger" aria-labelledby="denied-title">
        <p className="eyebrow">{t('error403.eyebrow')}</p>
        <h1 id="denied-title">{t('error403.title')}</h1>
        <p>{t('error403.body')}</p>
        <p className="muted">
          {t('error403.roles', {
            roles:
              roles.length > 0
                ? roles.map((role) => getRoleLabel(locale, role)).join(', ')
                : t('role.none'),
          })}
        </p>
        <Link className="button button--primary" to="/dashboard">
          {t('error403.back')}
        </Link>
      </section>
    </div>
  );
}
