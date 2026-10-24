import { PageHeader } from '../components/PageHeader';
import { useLocale } from '../i18n/i18n';
import { InventoryPanel } from './dashboard/panels';
import { useOpsData } from './dashboard/useOps';

export function StockPage() {
  const { t } = useLocale();
  const { overview } = useOpsData({ history: false });
  return (
    <div className="page">
      <PageHeader eyebrow={t('stock.eyebrow')} title={t('stock.title')} description={t('stock.description')} />
      {overview?.inventory != null ? (
        <InventoryPanel items={overview.inventory} />
      ) : (
        <p className="muted">{t('stock.loading')}</p>
      )}
    </div>
  );
}
