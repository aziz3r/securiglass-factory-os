import { PageHeader } from '../components/PageHeader';
import { useLocale } from '../i18n/i18n';
import { useAppStore } from '../store/StoreProvider';
import { formatNumber } from '../utils/format';
import { Kpi } from './dashboard/Kpi';
import { FurnacePanel } from './dashboard/panels';
import { useOpsData } from './dashboard/useOps';

export function ProductionPage() {
  const { t, locale } = useLocale();
  const telemetry = useAppStore((state) => state.telemetry);
  const { overview, samples } = useOpsData();
  const last = samples[samples.length - 1] ?? telemetry.sample;
  const batch = overview?.production?.batch ?? null;
  const pct =
    batch !== null && batch.planned > 0
      ? Math.round((batch.produced / batch.planned) * 100)
      : null;

  return (
    <div className="page">
      <PageHeader
        eyebrow={t('production.eyebrow')}
        title={t('production.title')}
        description={t('production.description')}
      />

      {telemetry.status === 'error' ? (
        <p className="banner banner--danger" role="alert">
          <strong>{t('production.streamDown')}</strong>{' '}
          {telemetry.error ?? t('production.reconnecting')}
        </p>
      ) : null}

      <section className="kpis" aria-label={t('production.title')}>
        <Kpi
          label={t('home.kpi.furnaceTemp')}
          value={formatNumber(last?.furnaceTempC ?? null, '°C', locale)}
          hint={t('production.kpi.furnaceTemp.hint')}
          info={t('production.kpi.furnaceTemp.info')}
        />
        <Kpi
          label={t('production.kpi.thickness')}
          value={formatNumber(last?.glassThicknessMm ?? null, 'mm', locale)}
          hint={t('production.kpi.thickness.hint')}
          info={t('production.kpi.thickness.info')}
        />
        <Kpi
          label={t('production.kpi.speed')}
          value={formatNumber(last?.lineSpeedMps ?? null, 'm/s', locale)}
          hint={t('production.kpi.speed.hint')}
          info={t('production.kpi.speed.info')}
        />
        <Kpi
          label={t('production.kpi.panes')}
          value={batch !== null ? `${batch.produced} / ${batch.planned}` : '—'}
          hint={
            batch !== null
              ? `${batch.code}${pct !== null ? ` · ${pct} %` : ''}`
              : t('home.kpi.batch.none')
          }
        />
      </section>

      <FurnacePanel samples={samples} />
    </div>
  );
}
