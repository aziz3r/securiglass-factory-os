import { Link } from 'react-router-dom';

import { PageHeader } from '../components/PageHeader';
import { useLocale } from '../i18n/i18n';
import {
  canUseAssistant,
  canViewProduction,
  canViewSales,
  canViewSecurity,
  canViewStock,
  getRoleDescription,
  getRoleLabel,
  canReadAudit,
  canReadCustomers,
  type Role,
} from '../security/roles';
import { useAppStore } from '../store/StoreProvider';
import { selectRoles, selectUser } from '../store/selectors';
import { formatInteger, formatNumber } from '../utils/format';
import { Kpi } from './dashboard/Kpi';
import { useOpsData } from './dashboard/useOps';

interface Shortcut {
  to: string;
  titleKey: string;
  textKey: string;
}

function shortcutsFor(roles: readonly Role[]): Shortcut[] {
  const list: Shortcut[] = [];
  if (canViewProduction(roles)) {
    list.push({ to: '/production', titleKey: 'nav.production', textKey: 'home.goto.production.text' });
  }
  if (canViewStock(roles)) {
    list.push({ to: '/stock', titleKey: 'nav.stock', textKey: 'home.goto.stock.text' });
  }
  if (canViewSales(roles)) {
    list.push({ to: '/sales', titleKey: 'nav.sales', textKey: 'home.goto.sales.text' });
  }
  if (canReadCustomers(roles)) {
    list.push({ to: '/customers', titleKey: 'nav.customers', textKey: 'home.goto.customers.text' });
  }
  if (canUseAssistant(roles)) {
    list.push({ to: '/assistant', titleKey: 'nav.assistant', textKey: 'home.goto.assistant.text' });
  }
  if (canViewSecurity(roles)) {
    list.push({ to: '/security', titleKey: 'nav.security', textKey: 'home.goto.security.text' });
  }
  if (canReadAudit(roles)) {
    list.push({ to: '/audit', titleKey: 'nav.audit', textKey: 'home.goto.audit.text' });
  }
  return list;
}

export function HomePage() {
  const { t, locale } = useLocale();
  const user = useAppStore(selectUser);
  const roles = useAppStore(selectRoles);
  const sample = useAppStore((state) => state.telemetry.sample);
  const { overview } = useOpsData({ history: false });

  const production = canViewProduction(roles);
  const severity = sample?.anomaly?.severity ?? null;
  const lowStock = overview?.inventory?.filter((i) => i.low).length ?? null;
  const batch = overview?.production?.batch ?? null;

  return (
    <div className="page">
      <PageHeader
        eyebrow={t('nav.home')}
        title={t('home.hello', { name: user?.username.replace(/^demo_/, '').replace(/_/g, ' ') ?? '' })}
        description={
          roles.length > 0
            ? `${roles.map((r) => getRoleLabel(locale, r)).join(', ')}. ${roles
                .map((r) => getRoleDescription(locale, r))
                .join(' ')}`
            : t('home.noRole')
        }
      />

      <section className="kpis" aria-label={t('home.goto.title')}>
        {production ? (
          <>
            <Kpi
              label={t('home.kpi.furnaceTemp')}
              value={formatNumber(sample?.furnaceTempC ?? null, '°C', locale)}
              hint={t('home.kpi.furnaceTemp.hint')}
              info={t('home.kpi.furnaceTemp.info')}
            />
            <Kpi
              label={t('home.kpi.furnaceState')}
              value={
                severity === null
                  ? t('home.kpi.furnaceState.unknown')
                  : severity === 'NORMAL'
                    ? t('home.kpi.furnaceState.normal')
                    : severity === 'WARNING'
                      ? t('home.kpi.furnaceState.warning')
                      : t('home.kpi.furnaceState.critical')
              }
              tone={
                severity === 'CRITICAL' ? 'danger' : severity === 'WARNING' ? 'warn' : undefined
              }
              hint={t('home.kpi.furnaceState.hint')}
              info={t('home.kpi.furnaceState.info')}
            />
            <Kpi
              label={t('home.kpi.batch')}
              value={batch !== null ? `${batch.produced} / ${batch.planned}` : '—'}
              hint={batch !== null ? t('home.kpi.batch.hint', { code: batch.code }) : t('home.kpi.batch.none')}
            />
          </>
        ) : null}
        {lowStock !== null ? (
          <Kpi
            label={t('home.kpi.lowStock')}
            value={String(lowStock)}
            tone={lowStock > 0 ? 'danger' : 'ok'}
            hint={lowStock > 0 ? t('home.kpi.lowStock.hintLow') : t('home.kpi.lowStock.hintOk')}
          />
        ) : null}
        {overview?.sales != null ? (
          <Kpi
            label={t('home.kpi.ordersOpen')}
            value={String(overview.sales.ordersOpen)}
            hint={t('home.kpi.ordersOpen.hint', { count: formatInteger(overview.sales.panesOrdered, locale) })}
          />
        ) : null}
        {overview?.compliance != null ? (
          <>
            <Kpi
              label={t('home.kpi.compliance')}
              value={`${overview.compliance.score} / 100`}
              tone={overview.compliance.score >= 90 ? 'ok' : 'warn'}
              info={t('home.kpi.compliance.info')}
            />
            <Kpi
              label={t('home.kpi.threats')}
              value={String(overview.compliance.threatsBlocked24h)}
              hint={t('home.kpi.threats.hint')}
            />
          </>
        ) : null}
      </section>

      <section aria-labelledby="goto-title" className="goto">
        <h2 id="goto-title">{t('home.goto.title')}</h2>
        <ul className="goto-list">
          {shortcutsFor(roles).map((s) => (
            <li key={s.to}>
              <Link to={s.to}>
                <strong>{t(s.titleKey)}</strong>
                <span>{t(s.textKey)}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}
