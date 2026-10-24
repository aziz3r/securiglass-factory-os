/**
 * Graphiques SVG sans dépendance : aucun style inline, couleurs via classes CSS
 * (la CSP de production interdit `style-src 'unsafe-inline'`).
 */

import type { NetworkLink, NetworkNode } from '../api/ops';
import { translate, type Locale } from '../i18n/i18n';
import type { AnomalySeverity } from '../realtime/telemetrySocket';

export interface ChartPoint {
  value: number;
  severity: AnomalySeverity | null;
}

const CHART_W = 600;
const CHART_H = 180;

function severityClass(severity: AnomalySeverity | null): string {
  switch (severity) {
    case 'CRITICAL':
      return 'sev-critical';
    case 'WARNING':
      return 'sev-warning';
    default:
      return 'sev-normal';
  }
}

interface LiveChartProps {
  points: readonly ChartPoint[];
  min: number;
  max: number;
  unit: string;
  label: string;
  /** Repères horizontaux (ex. plage de sûreté). */
  guides?: readonly number[];
}

/** Courbe en temps réel : le tracé passe à l'ambre puis au rouge selon le diagnostic ML. */
export function LiveChart({ points, min, max, unit, label, guides = [] }: LiveChartProps) {
  const span = Math.max(max - min, 1);
  const x = (i: number): number =>
    points.length <= 1 ? CHART_W : (i / (points.length - 1)) * CHART_W;
  const y = (v: number): number =>
    CHART_H - 8 - ((Math.min(Math.max(v, min), max) - min) / span) * (CHART_H - 16);

  // Un segment par plage de gravité contiguë ; il reprend le dernier point du précédent.
  const segments: { cls: string; coords: string[] }[] = [];
  for (let i = 0; i < points.length; i += 1) {
    const p = points[i];
    if (p === undefined) {
      continue;
    }
    const cls = severityClass(p.severity);
    const coord = `${x(i).toFixed(1)},${y(p.value).toFixed(1)}`;
    const last = segments[segments.length - 1];
    if (last !== undefined && last.cls === cls) {
      last.coords.push(coord);
    } else {
      const carry = last?.coords[last.coords.length - 1];
      segments.push({ cls, coords: carry !== undefined ? [carry, coord] : [coord] });
    }
  }

  const area =
    points.length > 1
      ? `M0,${CHART_H} L${points
          .map((p, i) => `${x(i).toFixed(1)},${y(p.value).toFixed(1)}`)
          .join(' L')} L${CHART_W},${CHART_H} Z`
      : '';
  const lastPoint = points[points.length - 1];

  return (
    <figure className="live-chart">
      <figcaption className="visually-hidden">{label}</figcaption>
      <svg
        viewBox={`0 0 ${CHART_W} ${CHART_H}`}
        preserveAspectRatio="none"
        role="img"
        aria-label={`${label} : ${
          lastPoint !== undefined ? lastPoint.value.toFixed(1) : '—'
        } ${unit}`}
      >
        <defs>
          <linearGradient id="chart-fill" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" className="stop-fill-a" />
            <stop offset="1" className="stop-fill-b" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75].map((f) => (
          <line
            key={f}
            x1="0"
            x2={CHART_W}
            y1={CHART_H * f}
            y2={CHART_H * f}
            className="chart-grid"
          />
        ))}
        {guides.map((g) => (
          <line
            key={g}
            x1="0"
            x2={CHART_W}
            y1={y(g)}
            y2={y(g)}
            className="chart-guide"
          />
        ))}
        {area !== '' ? <path d={area} fill="url(#chart-fill)" /> : null}
        {segments.map((s, i) => (
          <path key={i} d={`M${s.coords.join(' L')}`} className={`chart-line ${s.cls}`} />
        ))}
      </svg>
      <div className="chart-scale" aria-hidden="true">
        <span>
          {max} {unit}
        </span>
        <span>
          {min} {unit}
        </span>
      </div>
    </figure>
  );
}

interface GaugeProps {
  value: number | null;
  min: number;
  max: number;
  unit: string;
  label: string;
  decimals?: number;
  /** Fraction (0-1) à partir de laquelle l'aiguille passe en alerte. */
  warnFrom?: number;
  locale?: Locale;
}

const GAUGE_R = 70;
const GAUGE_CX = 90;
const GAUGE_CY = 90;

function polar(angleDeg: number, radius: number): [number, number] {
  const a = (Math.PI * (180 - angleDeg)) / 180;
  return [GAUGE_CX + radius * Math.cos(a), GAUGE_CY - radius * Math.sin(a)];
}

function arc(from: number, to: number): string {
  const [x1, y1] = polar(from, GAUGE_R);
  const [x2, y2] = polar(to, GAUGE_R);
  return `M${x1.toFixed(2)},${y1.toFixed(2)} A${GAUGE_R},${GAUGE_R} 0 ${
    to - from > 180 ? 1 : 0
  } 1 ${x2.toFixed(2)},${y2.toFixed(2)}`;
}

export function Gauge({
  value,
  min,
  max,
  unit,
  label,
  decimals = 0,
  warnFrom = 0.85,
  locale = 'fr',
}: GaugeProps) {
  const frac = value === null ? 0 : Math.min(Math.max((value - min) / (max - min), 0), 1);
  const angle = frac * 180;
  const [nx, ny] = polar(angle, GAUGE_R - 14);
  const [tx, ty] = polar(warnFrom * 180, GAUGE_R);
  const state = frac >= warnFrom ? 'warn' : 'normal';
  return (
    <figure className="gauge">
      <svg
        viewBox="0 0 180 104"
        role="img"
        aria-label={`${label} : ${value === null ? translate(locale, 'furnace.gaugeUnavailable') : `${value.toFixed(decimals)} ${unit}`}`}
      >
        <path d={arc(0, 180)} className="gauge-track" />
        {frac > 0.01 ? (
          <path d={arc(0, angle)} className={`gauge-fill gauge-fill--${state}`} />
        ) : null}
        <line
          x1={tx}
          y1={ty}
          x2={polar(warnFrom * 180, GAUGE_R - 8)[0]}
          y2={polar(warnFrom * 180, GAUGE_R - 8)[1]}
          className="gauge-threshold"
        />
        <line
          x1={GAUGE_CX}
          y1={GAUGE_CY}
          x2={nx}
          y2={ny}
          className="gauge-needle"
        />
        <circle cx={GAUGE_CX} cy={GAUGE_CY} r="4.5" className="gauge-hub" />
      </svg>
      <figcaption>
        <strong>{value === null ? '—' : value.toFixed(decimals)}</strong>
        <span>{unit}</span>
        <em>{label}</em>
      </figcaption>
    </figure>
  );
}

interface RingProps {
  pct: number;
  label: string;
  tone?: 'ok' | 'warn' | 'danger' | 'info';
}

const RING_R = 34;
const RING_C = 2 * Math.PI * RING_R;

export function Ring({ pct, label, tone = 'info' }: RingProps) {
  const clamped = Math.min(Math.max(pct, 0), 100);
  return (
    <figure className="ring">
      <svg viewBox="0 0 90 90" role="img" aria-label={`${label} : ${clamped} %`}>
        <circle cx="45" cy="45" r={RING_R} className="ring-track" />
        <circle
          cx="45"
          cy="45"
          r={RING_R}
          className={`ring-value ring-value--${tone}`}
          strokeDasharray={`${((clamped / 100) * RING_C).toFixed(1)} ${RING_C.toFixed(1)}`}
          transform="rotate(-90 45 45)"
        />
        <text x="45" y="51" textAnchor="middle" className="ring-text">
          {clamped}
        </text>
      </svg>
      <figcaption>{label}</figcaption>
    </figure>
  );
}

interface TankProps {
  pct: number;
  label: string;
  low: boolean;
}

/** Colonne de stock (silo) : le niveau est une barre SVG, rouge sous le seuil de réapprovisionnement. */
export function Tank({ pct, label, low }: TankProps) {
  const level = Math.min(Math.max(pct, 0), 100);
  const h = (level / 100) * 100;
  return (
    <figure className="tank">
      <svg viewBox="0 0 48 120" role="img" aria-label={`${label} : ${level} %`}>
        <rect x="6" y="6" width="36" height="108" rx="12" className="tank-body" />
        <rect
          x="9"
          y={110 - h}
          width="30"
          height={Math.max(h, 0)}
          rx="9"
          className={low ? 'tank-fill tank-fill--low' : 'tank-fill'}
        />
      </svg>
      <figcaption>
        <strong>{level}%</strong>
        <span>{label}</span>
      </figcaption>
    </figure>
  );
}

const NODE_POS: Readonly<Record<string, readonly [number, number]>> = {
  plc: [55, 120],
  gateway: [185, 120],
  diode: [320, 120],
  backend: [455, 120],
  db: [585, 55],
  llm: [585, 120],
  soc: [585, 185],
  web: [455, 45],
};

interface NetworkMapProps {
  nodes: readonly NetworkNode[];
  links: readonly NetworkLink[];
  locale?: Locale;
}

const NODE_LABEL_KEYS: Readonly<Record<string, string>> = {
  plc: 'network.node.plc',
  gateway: 'network.node.gateway',
  diode: 'network.node.diode',
  backend: 'network.node.backend',
  db: 'network.node.db',
  llm: 'network.node.llm',
  soc: 'network.node.soc',
  web: 'network.node.web',
};

/** Cartographie OT / DMZ / IT : les flux s'animent tant que les deux extrémités sont actives.
 * Les libellés des nœuds viennent de l'API (en français) ; en anglais on les retraduit
 * localement via leur identifiant stable (`n.id`). */
export function NetworkMap({ nodes, links, locale = 'fr' }: NetworkMapProps) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const nodeLabel = (n: NetworkNode): string =>
    locale === 'en' && NODE_LABEL_KEYS[n.id] !== undefined
      ? translate(locale, NODE_LABEL_KEYS[n.id] as string)
      : n.label;
  return (
    <svg
      className="network-map"
      viewBox="0 0 640 230"
      role="img"
      aria-label={
        locale === 'fr'
          ? 'Cartographie des flux entre le réseau OT de l’usine et le portail web IT'
          : 'Map of data flows between the plant’s OT network and the IT web portal'
      }
    >
      <line x1="262" y1="8" x2="262" y2="222" className="zone-divider" />
      <line x1="378" y1="8" x2="378" y2="222" className="zone-divider" />
      <text x="14" y="20" className="zone-label">
        {translate(locale, 'network.zone.ot')}
      </text>
      <text x="320" y="20" textAnchor="middle" className="zone-label zone-label--dmz">
        {translate(locale, 'network.zone.middle')}
      </text>
      <text x="626" y="20" textAnchor="end" className="zone-label">
        {translate(locale, 'network.zone.it')}
      </text>
      {links.map((l) => {
        const a = NODE_POS[l.source];
        const b = NODE_POS[l.target];
        const na = byId.get(l.source);
        const nb = byId.get(l.target);
        if (a === undefined || b === undefined) {
          return null;
        }
        const live = na?.up === true && nb?.up === true;
        return (
          <g key={`${l.source}-${l.target}`}>
            <title>{l.label}</title>
            <line
              x1={a[0]}
              y1={a[1]}
              x2={b[0]}
              y2={b[1]}
              className={live ? 'net-link net-link--live' : 'net-link net-link--down'}
            />
          </g>
        );
      })}
      {nodes.map((n) => {
        const pos = NODE_POS[n.id];
        if (pos === undefined) {
          return null;
        }
        const state = n.up ? n.zone.toLowerCase() : 'down';
        return (
          <g key={n.id} transform={`translate(${pos[0]} ${pos[1]})`}>
            <rect x="-34" y="-14" width="68" height="28" rx="6" className={`net-node net-node--${state}`} />
            <text y="4" textAnchor="middle" className="net-node-label">
              {nodeLabel(n)}
            </text>
            <text y="34" textAnchor="middle" className="net-label">
              {translate(locale, n.up ? 'network.node.online' : 'network.node.offline')}
            </text>
          </g>
        );
      })}
    </svg>
  );
}

interface ZoneBarsProps {
  zonesC: readonly number[];
  min: number;
  max: number;
  guides: readonly [number, number];
  locale?: Locale;
}

/** Barres de température par zone de chauffe : lecture rapide, sans élément décoratif.
 * Le remplissage est un rectangle SVG (jamais un attribut `style`, interdit par la CSP). */
export function ZoneBars({ zonesC, min, max, guides, locale = 'fr' }: ZoneBarsProps) {
  const span = Math.max(max - min, 1);
  const pct = (v: number): number =>
    Math.min(Math.max(((v - min) / span) * 100, 2), 100);
  return (
    <ul
      className="zone-bars"
      aria-label={locale === 'fr' ? 'Température par zone de chauffe' : 'Temperature by heating zone'}
    >
      {zonesC.map((t, i) => {
        const out = t < guides[0] || t > guides[1];
        const zoneLabel = translate(locale, 'furnace.zone', { n: i + 1 });
        return (
          <li key={i}>
            <span className="zone-bars-label">{zoneLabel}</span>
            <svg
              className="zone-bars-track"
              viewBox="0 0 100 8"
              preserveAspectRatio="none"
              role="img"
              aria-label={`${zoneLabel} : ${t.toFixed(0)} °C`}
            >
              <rect x="0" y="0" width="100" height="8" rx="4" className="zone-bars-base" />
              <rect
                x="0"
                y="0"
                width={pct(t)}
                height="8"
                rx="4"
                className={out ? 'zone-bars-fill zone-bars-fill--out' : 'zone-bars-fill'}
              />
            </svg>
            <span className="zone-bars-value">{t.toFixed(0)} °C</span>
          </li>
        );
      })}
    </ul>
  );
}
