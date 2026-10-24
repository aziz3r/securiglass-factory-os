import { PageHeader } from '../components/PageHeader';
import { UnauthorizedError } from '../api/errors';
import { useLocale } from '../i18n/i18n';
import { useAppStore } from '../store/StoreProvider';
import { selectRoles, selectToken } from '../store/selectors';
import { AlertsPanel, CompliancePanel, NetworkPanel } from './dashboard/panels';
import { getOpsApi, useOpsData } from './dashboard/useOps';

export function SecurityPage() {
  const { t } = useLocale();
  const token = useAppStore(selectToken);
  const roles = useAppStore(selectRoles);
  const expireSession = useAppStore((state) => state.expireSession);
  const { overview, refresh } = useOpsData({ history: false });

  async function simulateAttack(): Promise<string> {
    if (token === null) {
      return t('security.sessionExpired');
    }
    try {
      const detail = await getOpsApi().attemptSetpoint(token, 900);
      await refresh();
      return t('security.attackResult', { detail });
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        expireSession();
      }
      throw error;
    }
  }

  return (
    <div className="page">
      <PageHeader
        eyebrow={t('security.eyebrow')}
        title={t('security.title')}
        description={t('security.description')}
      />
      {overview?.compliance != null && overview.alerts != null && overview.network != null ? (
        <div className="stack">
          <CompliancePanel compliance={overview.compliance} />
          <AlertsPanel
            alerts={overview.alerts}
            onSimulate={roles.includes('SUPER_ADMIN') ? simulateAttack : undefined}
          />
          <NetworkPanel nodes={overview.network.nodes} links={overview.network.links} />
        </div>
      ) : (
        <p className="muted">{t('security.loading')}</p>
      )}
    </div>
  );
}
