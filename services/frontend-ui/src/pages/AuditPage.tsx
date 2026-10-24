import { useEffect } from 'react';

import { PageHeader } from '../components/PageHeader';
import { StatusBadge, type BadgeTone } from '../components/StatusBadge';
import { useLocale } from '../i18n/i18n';
import { useAppStore } from '../store/StoreProvider';
import { selectVisibleAuditLogs } from '../store/selectors';
import {
  EMPTY_VALUE,
  formatDateTime,
  formatDetails,
  truncateMiddle,
} from '../utils/format';

function outcomeTone(outcome: string): BadgeTone {
  switch (outcome.toUpperCase()) {
    case 'SUCCESS':
      return 'ok';
    case 'FAILURE':
      return 'danger';
    case 'DENIED':
    case 'BLOCKED':
      return 'warn';
    default:
      return 'neutral';
  }
}

export function AuditPage() {
  const { t, locale } = useLocale();
  const logs = useAppStore(selectVisibleAuditLogs);
  const status = useAppStore((state) => state.audit.status);
  const error = useAppStore((state) => state.audit.error);
  const accessDenied = useAppStore((state) => state.audit.accessDenied);
  const hasMore = useAppStore((state) => state.audit.hasMore);
  const offset = useAppStore((state) => state.audit.offset);
  const verifying = useAppStore((state) => state.audit.verifying);
  const verification = useAppStore((state) => state.audit.verification);
  const verificationError = useAppStore((state) => state.audit.verificationError);
  const loadAuditLogs = useAppStore((state) => state.loadAuditLogs);
  const verifyAuditChain = useAppStore((state) => state.verifyAuditChain);

  useEffect(() => {
    void loadAuditLogs(0);
  }, [loadAuditLogs]);

  return (
    <div className="page">
      <PageHeader
        eyebrow={t('audit.eyebrow')}
        title={t('audit.title')}
        description={t('audit.description')}
        actions={
          <div className="button-row">
            <button
              type="button"
              className="button button--ghost"
              onClick={() => void loadAuditLogs(0)}
              disabled={status === 'loading'}
            >
              {status === 'loading' ? t('customers.loading') : t('audit.refresh')}
            </button>
            <button
              type="button"
              className="button button--primary"
              onClick={() => void verifyAuditChain()}
              disabled={verifying}
            >
              {verifying ? t('audit.verifying') : t('audit.verify')}
            </button>
          </div>
        }
      />

      {accessDenied ? (
        <div className="alert alert--danger" role="alert">
          {error ?? t('audit.accessDenied')}
        </div>
      ) : null}

      {verificationError !== null ? (
        <div className="alert alert--danger" role="alert">
          {verificationError}
        </div>
      ) : null}

      {verification !== null ? (
        <section
          className={
            verification.chain_valid
              ? 'verification verification--valid'
              : 'verification verification--invalid'
          }
          aria-labelledby="verification-title"
          role="status"
        >
          <div className="verification-heading">
            <h2 id="verification-title">
              {verification.chain_valid ? t('audit.chainIntact') : t('audit.chainBroken')}
            </h2>
            <StatusBadge tone={verification.chain_valid ? 'ok' : 'danger'}>
              {verification.chain_valid ? t('audit.chainValid') : t('audit.chainInvalid')}
            </StatusBadge>
          </div>
          <dl className="verification-metrics">
            <div>
              <dt>chain_valid</dt>
              <dd>{String(verification.chain_valid)}</dd>
            </div>
            <div>
              <dt>total_records_checked</dt>
              <dd>{verification.total_records_checked}</dd>
            </div>
            <div>
              <dt>first_broken_id</dt>
              <dd className="mono">{verification.first_broken_id ?? t('audit.none')}</dd>
            </div>
          </dl>
          <p className="muted small">{t('audit.serverNote')}</p>
        </section>
      ) : null}

      <section className="panel" aria-labelledby="audit-list-title">
        <div className="panel-heading">
          <h2 id="audit-list-title">{t('audit.events.title')}</h2>
          <span className="muted small">
            {logs !== null ? t('audit.events.count', { count: logs.length }) : EMPTY_VALUE}
          </span>
        </div>

        {status === 'error' ? (
          <div className="alert alert--danger" role="alert">
            {error ?? t('audit.loadFailed')}
          </div>
        ) : null}

        {status === 'loading' && logs === null ? (
          <p className="muted" role="status">
            {t('audit.loading')}
          </p>
        ) : null}

        {logs !== null && logs.length === 0 ? (
          <p className="muted">{t('audit.none2')}</p>
        ) : null}

        {logs !== null && logs.length > 0 ? (
          <div className="table-wrapper">
            <table className="data-table data-table--audit">
              <caption className="sr-only">{t('audit.caption')}</caption>
              <thead>
                <tr>
                  <th scope="col">{t('audit.table.time')}</th>
                  <th scope="col">{t('audit.table.event')}</th>
                  <th scope="col">{t('audit.table.actor')}</th>
                  <th scope="col">{t('audit.table.action')}</th>
                  <th scope="col">{t('audit.table.resource')}</th>
                  <th scope="col">{t('audit.table.outcome')}</th>
                  <th scope="col">{t('audit.table.hash')}</th>
                  <th scope="col">{t('audit.table.details')}</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log) => (
                  <tr key={log.id}>
                    <td className="nowrap">{formatDateTime(log.event_time, locale)}</td>
                    <th scope="row" className="mono">
                      {log.event_type}
                    </th>
                    <td>{log.actor_username}</td>
                    <td className="mono">{log.action}</td>
                    <td className="mono wrap-anywhere">{log.resource}</td>
                    <td>
                      <StatusBadge tone={outcomeTone(log.outcome)}>
                        {log.outcome}
                      </StatusBadge>
                    </td>
                    <td>
                      <code title={log.current_hash} className="hash">
                        {truncateMiddle(log.current_hash, 18)}
                      </code>
                    </td>
                    <td>
                      <span className="details" title={formatDetails(log.details, 1000, locale)}>
                        {formatDetails(log.details, 180, locale)}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}

        {hasMore ? (
          <div className="load-more">
            <button
              type="button"
              className="button button--ghost"
              onClick={() => void loadAuditLogs(offset)}
              disabled={status === 'loading'}
            >
              {status === 'loading' ? t('customers.loading') : t('audit.loadMore')}
            </button>
          </div>
        ) : null}
      </section>
    </div>
  );
}
