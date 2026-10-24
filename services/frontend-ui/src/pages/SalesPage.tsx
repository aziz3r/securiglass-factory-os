import { useEffect } from 'react';
import { Link } from 'react-router-dom';

import { PageHeader } from '../components/PageHeader';
import { useLocale } from '../i18n/i18n';
import { useAppStore } from '../store/StoreProvider';
import { selectCanCreateCustomer, selectVisibleCustomers } from '../store/selectors';
import { SalesPanel } from './dashboard/panels';
import { useOpsData } from './dashboard/useOps';

export function SalesPage() {
  const { t } = useLocale();
  const canOrder = useAppStore(selectCanCreateCustomer);
  const customers = useAppStore(selectVisibleCustomers);
  const loadCustomers = useAppStore((state) => state.loadCustomers);
  const { overview, refresh } = useOpsData({ history: false });

  useEffect(() => {
    if (canOrder) {
      void loadCustomers();
    }
  }, [canOrder, loadCustomers]);

  return (
    <div className="page">
      <PageHeader
        eyebrow={t('sales.eyebrow')}
        title={t('sales.title')}
        description={t('sales.description')}
        actions={
          <Link className="secondary-button" to="/customers">
            {t('sales.viewCustomers')}
          </Link>
        }
      />
      {overview?.sales != null ? (
        <SalesPanel
          sales={overview.sales}
          customers={customers}
          canOrder={canOrder}
          onOrdered={refresh}
        />
      ) : (
        <p className="muted">{t('sales.loading')}</p>
      )}
    </div>
  );
}
