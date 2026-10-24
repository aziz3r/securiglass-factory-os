import { useEffect, useId, useRef, useState, type FormEvent } from 'react';

import { ApiError, RateLimitError, UnauthorizedError } from '../../api/errors';
import type {
  ComplianceOverview,
  InventoryItem,
  NetworkLink,
  NetworkNode,
  SalesOverview,
  SocAlert,
} from '../../api/ops';
import type { Customer } from '../../api/types';
import {
  Gauge,
  LiveChart,
  NetworkMap,
  Ring,
  ZoneBars,
  type ChartPoint,
} from '../../components/charts';
import { InfoTip } from '../../components/InfoTip';
import { useLocale, type Locale } from '../../i18n/i18n';
import type { TelemetrySample } from '../../realtime/telemetrySocket';
import { useAppStore } from '../../store/StoreProvider';
import { selectToken } from '../../store/selectors';
import { formatDateTime, formatInteger } from '../../utils/format';
import { getOpsApi } from './useOps';

const DIAGNOSIS_KEYS: Readonly<Record<string, string>> = {
  OVERHEAT_CRITICAL: 'diagnosis.OVERHEAT_CRITICAL',
  QUENCH_PRESSURE_LOSS: 'diagnosis.QUENCH_PRESSURE_LOSS',
  CONVEYOR_STALL: 'diagnosis.CONVEYOR_STALL',
  CONVEYOR_BLOCKED: 'diagnosis.CONVEYOR_BLOCKED',
  THERMAL_SHOCK_RISK: 'diagnosis.THERMAL_SHOCK_RISK',
  HEATER_ELEMENT_FAILURE: 'diagnosis.HEATER_ELEMENT_FAILURE',
  STATISTICAL_OUTLIER: 'diagnosis.STATISTICAL_OUTLIER',
};

export function describeDiagnosis(diagnosis: string | null, t: (key: string, vars?: Record<string, string | number>) => string): string {
  if (diagnosis === null || diagnosis === '') {
    return t('diagnosis.none');
  }
  return diagnosis
    .split(', ')
    .map((code) => {
      if (code.startsWith('ENVELOPE_VIOLATION:')) {
        return t('diagnosis.envelope', { detail: code.slice('ENVELOPE_VIOLATION:'.length) });
      }
      const key = DIAGNOSIS_KEYS[code];
      return key !== undefined ? t(key) : code;
    })
    .filter((label, i, all) => all.indexOf(label) === i)
    .join(' · ');
}

function Section({
  title,
  info,
  aside,
  className,
  children,
}: {
  title: string;
  info?: React.ReactNode;
  aside?: React.ReactNode;
  className?: string;
  children: React.ReactNode;
}) {
  const id = useId();
  return (
    <section className={`zone ${className ?? ''}`} aria-labelledby={id}>
      <header className="zone-head">
        <h2 id={id}>
          {title}
          {info !== undefined ? <InfoTip label={title}>{info}</InfoTip> : null}
        </h2>
        {aside !== undefined ? <div className="zone-aside">{aside}</div> : null}
      </header>
      {children}
    </section>
  );
}

// ---------------------------------------------------------------- Fours
export function FurnacePanel({ samples }: { samples: readonly TelemetrySample[] }) {
  const { t, locale } = useLocale();
  const last = samples[samples.length - 1];
  const points: ChartPoint[] = samples.map((s) => ({
    value: s.furnaceTempC ?? 0,
    severity: s.anomaly?.severity ?? null,
  }));
  const anomaly = last?.anomaly ?? null;
  const tone =
    anomaly === null
      ? 'neutral'
      : anomaly.severity === 'CRITICAL'
        ? 'danger'
        : anomaly.severity === 'WARNING'
          ? 'warn'
          : 'ok';
  return (
    <Section
      title={t('furnace.title')}
      className="zone--furnace"
      info={
        <>
          {t('furnace.info.pre')}
          <strong>{t('furnace.info.normal')}</strong>
          {t('furnace.info.mid1')}
          <strong>{t('furnace.info.warning')}</strong>
          {t('furnace.info.mid2')}
          <strong>{t('furnace.info.critical')}</strong>
          {t('furnace.info.post')}
        </>
      }
      aside={
        <span className={`pill pill--${tone}`} role="status">
          {anomaly === null
            ? t('furnace.status.unavailable')
            : anomaly.severity === 'NORMAL'
              ? t('furnace.status.normal')
              : anomaly.severity === 'CRITICAL'
                ? t('furnace.status.critical')
                : t('furnace.status.warning')}
        </span>
      }
    >
      <div className="furnace-layout">
        <div className="furnace-chart">
          {points.length > 1 ? (
            <LiveChart
              points={points}
              min={0}
              max={800}
              unit="°C"
              label={t('furnace.chart.label')}
              guides={[620, 730]}
            />
          ) : (
            <p className="muted empty">{t('furnace.waiting')}</p>
          )}
          {last?.zonesC !== undefined && last.zonesC.length > 0 ? (
            <ZoneBars zonesC={last.zonesC} min={0} max={800} guides={[620, 730]} locale={locale} />
          ) : null}
          <p className={`diagnosis diagnosis--${tone}`}>
            {anomaly === null ? t('furnace.noAnalysis') : describeDiagnosis(anomaly.diagnosis, t)}
          </p>
          <ul className="legend" aria-label={t('furnace.legend.label')}>
            <li className="legend-normal">{t('furnace.legend.normal')}</li>
            <li className="legend-warning">{t('furnace.legend.warning')}</li>
            <li className="legend-critical">{t('furnace.legend.critical')}</li>
            <li className="legend-guide">{t('furnace.legend.guide')}</li>
          </ul>
        </div>
        <div className="furnace-dials">
          <Gauge
            value={last?.furnaceTempC ?? null}
            min={0}
            max={800}
            unit="°C"
            label={t('furnace.gauge.temp')}
            warnFrom={0.9}
            locale={locale}
          />
          <Gauge
            value={last?.quenchPressureBar ?? null}
            min={0}
            max={6.5}
            unit="bar"
            label={t('furnace.gauge.pressure')}
            decimals={1}
            warnFrom={0.95}
            locale={locale}
          />
        </div>
      </div>
    </Section>
  );
}

// -------------------------------------------------------------- Stocks
function StockBar({ item, locale }: { item: InventoryItem; locale: Locale }) {
  const { t } = useLocale();
  return (
    <li className={item.low ? 'stock stock--low' : 'stock'}>
      <div className="stock-head">
        <span>{item.name}</span>
        <strong>
          {formatInteger(item.stock, locale)} {item.unit}
          <span className="stock-state">
            {item.low ? ` · ${t('stockPanel.toReorder')}` : ` · ${item.levelPct} %`}
          </span>
        </strong>
      </div>
      <svg
        className="stock-bar"
        viewBox="0 0 100 6"
        preserveAspectRatio="none"
        role="img"
        aria-label={`${item.name} : ${item.levelPct} %`}
      >
        <rect x="0" y="0" width="100" height="6" rx="3" className="stock-track" />
        <rect
          x="0"
          y="0"
          width={Math.max(item.levelPct, 2)}
          height="6"
          rx="3"
          className="stock-fill"
        />
      </svg>
    </li>
  );
}

export function InventoryPanel({ items }: { items: readonly InventoryItem[] }) {
  const { t, locale } = useLocale();
  const low = items.filter((i) => i.low);
  return (
    <Section
      title={t('stockPanel.title')}
      className="zone--stock"
      info={t('stockPanel.info')}
      aside={
        low.length === 0 ? (
          <span className="pill pill--ok">{t('stockPanel.allOk')}</span>
        ) : (
          <span className="pill pill--danger">
            {t(low.length === 1 ? 'stockPanel.reorder' : 'stockPanel.reorder_plural', {
              count: low.length,
            })}
          </span>
        )
      }
    >
      <ul className="stock-list">
        {items.map((item) => (
          <StockBar key={item.code} item={item} locale={locale} />
        ))}
      </ul>
    </Section>
  );
}

// ------------------------------------------------------------- Réseau
export function NetworkPanel({
  nodes,
  links,
}: {
  nodes: readonly NetworkNode[];
  links: readonly NetworkLink[];
}) {
  const { t, locale } = useLocale();
  const down = nodes.filter((n) => !n.up);
  return (
    <Section
      title={t('network.title')}
      className="zone--network"
      info={t('network.info')}
      aside={
        down.length === 0 ? (
          <span className="pill pill--ok">
            <span className="pill-dot" aria-hidden="true" />
            {t('network.allUp')}
          </span>
        ) : (
          <span className="pill pill--danger">
            <span className="pill-dot" aria-hidden="true" />
            {t('network.down', { names: down.map((n) => n.label).join(', ') })}
          </span>
        )
      }
    >
      <NetworkMap nodes={nodes} links={links} locale={locale} />
    </Section>
  );
}

// ------------------------------------------------------------- Alertes
interface AlertsPanelProps {
  alerts: readonly SocAlert[];
  onSimulate?: (() => Promise<string>) | undefined;
}

export function AlertsPanel({ alerts, onSimulate }: AlertsPanelProps) {
  const { t } = useLocale();
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  async function simulate(): Promise<void> {
    setBusy(true);
    try {
      setNotice((await onSimulate?.()) ?? null);
    } catch {
      setNotice(t('alerts.simulationFailed'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section
      title={t('alerts.title')}
      className="zone--alerts"
      info={
        <>
          {t('alerts.info.pre')}
          <em>T0836</em>
          {t('alerts.info.post')}
        </>
      }
      aside={
        onSimulate !== undefined ? (
          <button
            type="button"
            className="secondary-button"
            onClick={() => void simulate()}
            disabled={busy}
          >
            {busy ? t('alerts.sending') : t('alerts.test')}
          </button>
        ) : undefined
      }
    >
      {notice !== null ? (
        <p className="notice" role="status">
          {notice}
        </p>
      ) : null}
      {alerts.length === 0 ? (
        <p className="muted empty">{t('alerts.none')}</p>
      ) : (
        <ul className="alert-feed">
          {alerts.map((a) => (
            <li key={a.id} className={`alert-item alert-item--${a.severity.toLowerCase()}`}>
              <span className="alert-dot" aria-hidden="true" />
              <div className="alert-body">
                <p className="alert-title">
                  <span className="mitre-tag" title={`${a.mitre.framework} · ${a.mitre.tactic}`}>
                    {a.mitre.id}
                  </span>
                  {a.mitre.name}
                </p>
                <p className="alert-meta">
                  {a.actor} · {a.sourceIp} · {formatDateTime(a.time)} · {a.mitre.tactic}
                </p>
              </div>
              <span className="alert-state">
                {a.blocked ? t('alerts.blocked') : t('alerts.detected')} ·{' '}
                {t(`severity.${a.severity}`)}
              </span>
            </li>
          ))}
        </ul>
      )}
    </Section>
  );
}

// ---------------------------------------------------------- Conformité
export function CompliancePanel({ compliance }: { compliance: ComplianceOverview }) {
  const { t } = useLocale();
  const tone = compliance.score >= 90 ? 'ok' : compliance.score >= 70 ? 'warn' : 'danger';
  return (
    <Section title={t('compliance.title')} className="zone--compliance" info={t('compliance.info')}>
      <div className="compliance-layout">
        <Ring pct={compliance.score} label={t('compliance.scoreLabel')} tone={tone} />
        <div className="compliance-facts">
          <p>
            <strong>{compliance.threatsBlocked24h}</strong>
            <span>{t('compliance.threats')}</span>
          </p>
          <p>
            <strong>{compliance.ciJobs.length}</strong>
            <span>{t('compliance.ciSteps')}</span>
          </p>
        </div>
      </div>
      <ul className="control-list">
        {compliance.controls.map((c) => (
          <li key={c.name} className={c.ok ? 'control control--ok' : 'control control--ko'}>
            <span className="control-mark" aria-hidden="true">
              {c.ok ? '✓' : '✕'}
            </span>
            <span>{c.name}</span>
            <em>{c.detail}</em>
          </li>
        ))}
      </ul>
    </Section>
  );
}

// -------------------------------------------------------------- Ventes
interface SalesPanelProps {
  sales: SalesOverview;
  customers: readonly Customer[] | null;
  canOrder: boolean;
  onOrdered: () => Promise<void>;
}

export function SalesPanel({ sales, customers, canOrder, onOrdered }: SalesPanelProps) {
  const { t, locale } = useLocale();
  const token = useAppStore(selectToken);
  const expireSession = useAppStore((state) => state.expireSession);
  const [customerId, setCustomerId] = useState('');
  const [recipeCode, setRecipeCode] = useState('');
  const [quantity, setQuantity] = useState('100');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  const effectiveCustomer = customerId !== '' ? customerId : (customers?.[0]?.id ?? '');
  const effectiveRecipe = recipeCode !== '' ? recipeCode : (sales.recipes[0]?.code ?? '');

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    const qty = Number.parseInt(quantity, 10);
    if (token === null || !Number.isInteger(qty) || qty < 1 || qty > 10000) {
      setResult({ ok: false, text: t('sales.form.invalidQuantity') });
      return;
    }
    setBusy(true);
    try {
      const order = await getOpsApi().createOrder(token, {
        customerId: effectiveCustomer,
        recipeCode: effectiveRecipe,
        quantity: qty,
        widthMm: 1200,
        heightMm: 800,
      });
      const used = Object.entries(order.materialsConsumed)
        .filter(([, v]) => v >= 1)
        .map(([k, v]) => `${k} −${Math.round(v)}`)
        .join(' · ');
      setResult({
        ok: true,
        text: t('sales.form.success', {
          ref: order.orderRef,
          quantity: order.quantity,
          area: order.areaM2,
          used,
        }),
      });
      await onOrdered();
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        expireSession();
        return;
      }
      setResult({
        ok: false,
        text:
          error instanceof RateLimitError
            ? t('sales.form.rateLimited')
            : error instanceof ApiError && error.message !== 'Requête refusée'
              ? error.message
              : t('sales.form.refused'),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section
      title={t('sales.panel.title')}
      className="zone--sales"
      info={t('sales.panel.info')}
      aside={
        <span className="muted small">
          {t('sales.panel.summary', {
            open: sales.ordersOpen,
            panes: formatInteger(sales.panesOrdered, locale),
          })}
        </span>
      }
    >
      {canOrder ? (
        <form className="order-form" onSubmit={(e) => void submit(e)}>
          <label>
            <span>{t('sales.form.customer')}</span>
            <select
              value={effectiveCustomer}
              onChange={(e) => setCustomerId(e.target.value)}
              required
            >
              {(customers ?? []).map((c) => (
                <option key={c.id} value={c.id}>
                  {c.company_name}
                </option>
              ))}
            </select>
          </label>
          <label>
            <span>{t('sales.form.recipe')}</span>
            <select value={effectiveRecipe} onChange={(e) => setRecipeCode(e.target.value)} required>
              {sales.recipes.map((r) => (
                <option key={r.code} value={r.code}>
                  {r.name}
                </option>
              ))}
            </select>
          </label>
          <label className="order-qty">
            <span>{t('sales.form.quantity')}</span>
            <input
              type="number"
              min={1}
              max={10000}
              value={quantity}
              onChange={(e) => setQuantity(e.target.value)}
              required
            />
          </label>
          <button
            type="submit"
            className="cta"
            disabled={busy || effectiveCustomer === '' || effectiveRecipe === ''}
          >
            {busy ? t('sales.form.submitting') : t('sales.form.submit')}
          </button>
        </form>
      ) : null}
      {result !== null ? (
        <p className={result.ok ? 'notice notice--ok' : 'notice notice--danger'} role="status">
          {result.text}
        </p>
      ) : null}
      <ul className="order-list">
        {sales.recent.map((o) => (
          <li key={o.orderRef}>
            <span className="order-ref">{o.orderRef}</span>
            <span>{o.customer}</span>
            <span>{t('sales.list.panes', { count: o.quantity })}</span>
            <span className="order-status">{o.status}</span>
          </li>
        ))}
        {sales.recent.length === 0 ? <li className="muted">{t('sales.list.empty')}</li> : null}
      </ul>
    </Section>
  );
}

// ----------------------------------------------------------- Assistant
interface ChatMessage {
  id: number;
  from: 'user' | 'bot';
  text: string;
  tone?: 'blocked';
  sources?: string[];
}

export function AssistantPanel() {
  const { t } = useLocale();
  const token = useAppStore(selectToken);
  const expireSession = useAppStore((state) => state.expireSession);
  const [messages, setMessages] = useState<ChatMessage[]>([
    { id: 0, from: 'bot', text: t('assistant.greeting') },
  ]);
  const [draft, setDraft] = useState('');
  const [busy, setBusy] = useState(false);
  const nextId = useRef(1);
  const endRef = useRef<HTMLDivElement | null>(null);

  const suggestions = [
    t('assistant.suggestion1'),
    t('assistant.suggestion2'),
    t('assistant.suggestion3'),
  ];

  useEffect(() => {
    endRef.current?.scrollIntoView?.({ block: 'end' });
  }, [messages]);

  function push(message: Omit<ChatMessage, 'id'>): void {
    const id = nextId.current;
    nextId.current += 1;
    setMessages((current) => [...current, { ...message, id }]);
  }

  async function send(raw: string): Promise<void> {
    const prompt = raw.trim();
    if (prompt === '' || token === null || busy) {
      return;
    }
    push({ from: 'user', text: prompt });
    setDraft('');
    setBusy(true);
    try {
      const reply = await getOpsApi().askAssistant(token, prompt);
      if (reply.kind === 'blocked') {
        push({ from: 'bot', text: reply.detail, tone: 'blocked' });
      } else {
        push({ from: 'bot', text: reply.answer, sources: reply.sources });
      }
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        expireSession();
        return;
      }
      push({
        from: 'bot',
        tone: 'blocked',
        text: error instanceof RateLimitError ? t('assistant.rateLimited') : t('assistant.unavailable'),
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <Section title={t('assistant.title')} className="zone--assistant" info={t('assistant.description')}>
      <div className="chat-log" role="log" aria-live="polite">
        {messages.map((m) => (
          <div key={m.id} className={`bubble bubble--${m.from}${m.tone ? ` bubble--${m.tone}` : ''}`}>
            <p>{m.text}</p>
            {m.sources !== undefined && m.sources.length > 0 ? (
              <small>{t('assistant.sources', { sources: m.sources.join(' · ') })}</small>
            ) : null}
          </div>
        ))}
        {busy ? <div className="bubble bubble--bot bubble--typing">…</div> : null}
        <div ref={endRef} />
      </div>
      <div className="chat-suggestions">
        {suggestions.map((s) => (
          <button key={s} type="button" className="suggestion" onClick={() => void send(s)} disabled={busy}>
            {s}
          </button>
        ))}
      </div>
      <form
        className="chat-input"
        onSubmit={(e) => {
          e.preventDefault();
          void send(draft);
        }}
      >
        <input
          type="text"
          value={draft}
          maxLength={2000}
          onChange={(e) => setDraft(e.target.value)}
          placeholder={t('assistant.placeholder')}
          aria-label={t('assistant.inputLabel')}
        />
        <button
          type="submit"
          className="send"
          disabled={busy || draft.trim() === ''}
          aria-label={t('assistant.send')}
        >
          <svg viewBox="0 0 24 24" aria-hidden="true">
            <path d="M3 11.5 21 3l-8.5 18-2.2-7.3z" />
          </svg>
        </button>
      </form>
    </Section>
  );
}
