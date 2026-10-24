import { Link } from 'react-router-dom';

import { useLocale } from '../i18n/i18n';

export function NotFoundPage() {
  const { t } = useLocale();
  return (
    <div className="page page--centered">
      <section className="state-card" aria-labelledby="notfound-title">
        <p className="eyebrow">{t('error404.eyebrow')}</p>
        <h1 id="notfound-title">{t('error404.title')}</h1>
        <p>{t('error404.body')}</p>
        <Link className="button button--primary" to="/dashboard">
          {t('error404.back')}
        </Link>
      </section>
    </div>
  );
}
