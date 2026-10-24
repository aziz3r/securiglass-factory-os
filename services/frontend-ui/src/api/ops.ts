/**
 * Client des endpoints « usine » : vue d'ensemble, historique, alertes SOC, commandes,
 * assistant IA. Mêmes règles que `client.ts` : URL relative, aucun cookie, jeton passé
 * à chaque appel, aucune redirection suivie. Les réponses sont validées avant usage.
 */

import { ApiError, ForbiddenError, NetworkError, ProtocolError, RateLimitError, ServerError, UnauthorizedError } from './errors';
import { parseTelemetryPayload, type TelemetrySample } from '../realtime/telemetrySocket';
import type { FetchLike } from './types';

const BASE = '/api/v1';

export interface InventoryItem {
  code: string;
  name: string;
  unit: string;
  stock: number;
  capacity: number;
  reorderLevel: number;
  levelPct: number;
  low: boolean;
}

export interface OrderSummary {
  orderRef: string;
  customer: string;
  recipe: string;
  quantity: number;
  status: string;
  createdAt: string;
}

export interface RecipeOption {
  code: string;
  name: string;
  thicknessMm: number;
}

export interface SalesOverview {
  recipes: RecipeOption[];
  ordersTotal: number;
  ordersOpen: number;
  panesOrdered: number;
  recent: OrderSummary[];
}

export interface BatchOverview {
  code: string;
  planned: number;
  produced: number;
  scrapped: number;
  status: string;
}

export interface ProductionOverview {
  lineStatus: string | null;
  batch: BatchOverview | null;
  telemetryAgeS: number | null;
  mlTrained: boolean;
  mlBackend: string;
}

export interface NetworkNode {
  id: string;
  label: string;
  zone: 'OT' | 'DMZ' | 'IT';
  purdueLevel: number;
  up: boolean;
}

export interface NetworkLink {
  source: string;
  target: string;
  label: string;
}

export interface ComplianceControl {
  name: string;
  ok: boolean;
  detail: string;
}

export interface ComplianceOverview {
  score: number;
  controls: ComplianceControl[];
  threatsBlocked24h: number;
  ciJobs: string[];
}

export interface MitreTag {
  id: string;
  name: string;
  tactic: string;
  framework: string;
}

export type AlertSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface SocAlert {
  id: string;
  time: string;
  eventType: string;
  actor: string;
  sourceIp: string;
  resource: string;
  outcome: string;
  severity: AlertSeverity;
  mitre: MitreTag;
  blocked: boolean;
}

/** Chaque bloc vaut `null` si le rôle courant n'en a pas besoin (filtré côté serveur). */
export interface Overview {
  inventory: InventoryItem[] | null;
  production: ProductionOverview | null;
  network: { nodes: NetworkNode[]; links: NetworkLink[] } | null;
  sales: SalesOverview | null;
  compliance: ComplianceOverview | null;
  alerts: SocAlert[] | null;
}

export interface OrderInput {
  customerId: string;
  recipeCode: string;
  quantity: number;
  widthMm: number;
  heightMm: number;
}

export interface OrderResult {
  orderRef: string;
  quantity: number;
  areaM2: number;
  materialsConsumed: Record<string, number>;
  inventory: InventoryItem[];
}

export type AssistantReply =
  | {
      kind: 'answer';
      answer: string;
      sources: string[];
      confidence: number;
    }
  | { kind: 'blocked'; detail: string };

export interface OpsPort {
  overview(token: string): Promise<Overview>;
  history(token: string, limit?: number): Promise<TelemetrySample[]>;
  alerts(token: string, limit?: number): Promise<SocAlert[]>;
  createOrder(token: string, input: OrderInput): Promise<OrderResult>;
  askAssistant(token: string, prompt: string): Promise<AssistantReply>;
  attemptSetpoint(token: string, furnaceTempC: number): Promise<string>;
}

type Rec = Record<string, unknown>;

function rec(value: unknown): Rec {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new ProtocolError();
  }
  return value as Rec;
}

function arr(value: unknown): unknown[] {
  if (!Array.isArray(value)) {
    throw new ProtocolError();
  }
  return value;
}

function str(value: unknown): string {
  if (typeof value !== 'string') {
    throw new ProtocolError();
  }
  return value;
}

function num(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new ProtocolError();
  }
  return value;
}

function optNum(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function optStr(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function parseInventory(raw: unknown): InventoryItem[] {
  return arr(raw).map((item) => {
    const r = rec(item);
    return {
      code: str(r['code']),
      name: str(r['name']),
      unit: str(r['unit']),
      stock: num(r['stock']),
      capacity: num(r['capacity']),
      reorderLevel: num(r['reorder_level']),
      levelPct: num(r['level_pct']),
      low: r['low'] === true,
    };
  });
}

function parseAlert(raw: unknown): SocAlert {
  const r = rec(raw);
  const m = rec(r['mitre']);
  const severity = str(r['severity']);
  return {
    id: str(r['id']),
    time: str(r['time']),
    eventType: str(r['event_type']),
    actor: str(r['actor']),
    sourceIp: str(r['source_ip']),
    resource: str(r['resource']),
    outcome: str(r['outcome']),
    severity:
      severity === 'CRITICAL' || severity === 'HIGH' || severity === 'MEDIUM'
        ? severity
        : 'LOW',
    mitre: {
      id: str(m['id']),
      name: str(m['name']),
      tactic: str(m['tactic']),
      framework: str(m['framework']),
    },
    blocked: r['blocked'] === true,
  };
}

function parseProduction(raw: unknown): ProductionOverview {
  const p = rec(raw);
  const ml = rec(p['ml']);
  const batch = p['batch'] === null ? null : rec(p['batch']);
  return {
    lineStatus: optStr(p['line_status']),
    batch:
      batch === null
        ? null
        : {
            code: str(batch['code']),
            planned: num(batch['planned']),
            produced: num(batch['produced']),
            scrapped: num(batch['scrapped']),
            status: str(batch['status']),
          },
    telemetryAgeS: optNum(p['telemetry_age_s']),
    mlTrained: ml['trained'] === true,
    mlBackend: str(ml['backend']),
  };
}

function parseNetwork(raw: unknown): { nodes: NetworkNode[]; links: NetworkLink[] } {
  const net = rec(raw);
  return {
    nodes: arr(net['nodes']).map((n) => {
      const x = rec(n);
      const zone = str(x['zone']);
      return {
        id: str(x['id']),
        label: str(x['label']),
        zone: zone === 'OT' || zone === 'DMZ' ? zone : 'IT',
        purdueLevel: num(x['purdue_level']),
        up: x['up'] === true,
      };
    }),
    links: arr(net['links']).map((l) => {
      const x = rec(l);
      return {
        source: str(x['source']),
        target: str(x['target']),
        label: str(x['label']),
      };
    }),
  };
}

function parseSales(raw: unknown): SalesOverview {
  const sales = rec(raw);
  return {
    recipes: arr(sales['recipes']).map((o) => {
      const x = rec(o);
      return {
        code: str(x['code']),
        name: str(x['name']),
        thicknessMm: num(x['thickness_mm']),
      };
    }),
    ordersTotal: num(sales['orders_total']),
    ordersOpen: num(sales['orders_open']),
    panesOrdered: num(sales['panes_ordered']),
    recent: arr(sales['recent']).map((o) => {
      const x = rec(o);
      return {
        orderRef: str(x['order_ref']),
        customer: str(x['customer']),
        recipe: str(x['recipe']),
        quantity: num(x['quantity']),
        status: str(x['status']),
        createdAt: str(x['created_at']),
      };
    }),
  };
}

function parseCompliance(raw: unknown): ComplianceOverview {
  const compliance = rec(raw);
  return {
    score: num(compliance['score']),
    controls: arr(compliance['controls']).map((c) => {
      const x = rec(c);
      return { name: str(x['name']), ok: x['ok'] === true, detail: str(x['detail']) };
    }),
    threatsBlocked24h: num(compliance['threats_blocked_24h']),
    ciJobs: arr(compliance['ci_jobs']).map(str),
  };
}

function nullable<T>(value: unknown, parse: (raw: unknown) => T): T | null {
  return value === null || value === undefined ? null : parse(value);
}

function parseOverview(raw: unknown): Overview {
  const r = rec(raw);
  return {
    inventory: nullable(r['inventory'], parseInventory),
    production: nullable(r['production'], parseProduction),
    network: nullable(r['network'], parseNetwork),
    sales: nullable(r['sales'], parseSales),
    compliance: nullable(r['compliance'], parseCompliance),
    alerts: nullable(r['alerts'], (v) => arr(v).map(parseAlert)),
  };
}

function mapError(status: number): ApiError {
  if (status === 401) {
    return new UnauthorizedError();
  }
  if (status === 403) {
    return new ForbiddenError();
  }
  if (status === 429) {
    return new RateLimitError();
  }
  if (status >= 500) {
    return new ServerError(status);
  }
  return new ApiError('Requête refusée', { status, kind: 'http' });
}

export interface OpsClientOptions {
  fetchImpl?: FetchLike;
}

export function createOpsClient(options: OpsClientOptions = {}): OpsPort {
  const fetchImpl: FetchLike =
    options.fetchImpl ?? ((input, init) => fetch(input, init));

  /** Retourne (statut, corps JSON | null) ; lève pour 401/403/429/5xx. */
  async function call(
    path: string,
    method: 'GET' | 'POST',
    token: string,
    body?: unknown,
    passthrough: readonly number[] = [],
  ): Promise<{ status: number; data: unknown }> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      Authorization: `Bearer ${token}`,
    };
    const init: RequestInit = {
      method,
      headers,
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    };
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let response: Response;
    try {
      response = await fetchImpl(`${BASE}${path}`, init);
    } catch (error) {
      throw error instanceof ApiError ? error : new NetworkError(error);
    }
    let data: unknown = null;
    try {
      const text = await response.text();
      data = text.length > 0 ? (JSON.parse(text) as unknown) : null;
    } catch {
      if (response.ok) {
        throw new ProtocolError();
      }
    }
    if (!response.ok && !passthrough.includes(response.status)) {
      throw mapError(response.status);
    }
    return { status: response.status, data };
  }

  return {
    async overview(token) {
      return parseOverview((await call('/factory/overview', 'GET', token)).data);
    },

    async history(token, limit = 120) {
      const { data } = await call(
        `/factory/telemetry/history?limit=${String(limit)}`,
        'GET',
        token,
      );
      return arr(data)
        .map(parseTelemetryPayload)
        .filter((s): s is TelemetrySample => s !== null);
    },

    async alerts(token, limit = 50) {
      const { data } = await call(`/soc/alerts?limit=${String(limit)}`, 'GET', token);
      return arr(data).map(parseAlert);
    },

    async createOrder(token, input) {
      const { status, data } = await call(
        '/orders',
        'POST',
        token,
        {
          customer_id: input.customerId,
          recipe_code: input.recipeCode,
          quantity: input.quantity,
          width_mm: input.widthMm,
          height_mm: input.heightMm,
        },
        [404, 409, 422],
      );
      if (status !== 201) {
        const detail =
          typeof data === 'object' && data !== null && 'detail' in data
            ? String((data as Rec)['detail'])
            : 'Commande refusée';
        throw new ApiError(detail, { status, kind: 'http' });
      }
      const r = rec(data);
      const consumed = rec(r['materials_consumed']);
      return {
        orderRef: str(r['order_ref']),
        quantity: num(r['quantity']),
        areaM2: num(r['area_m2']),
        materialsConsumed: Object.fromEntries(
          Object.entries(consumed).map(([k, v]) => [k, num(v)]),
        ),
        inventory: parseInventory(r['inventory']),
      };
    },

    async askAssistant(token, prompt) {
      const { status, data } = await call(
        '/rag/query',
        'POST',
        token,
        { prompt },
        [400],
      );
      if (status === 400) {
        const detail =
          typeof data === 'object' && data !== null && 'detail' in data
            ? String((data as Rec)['detail'])
            : 'Requête rejetée par LLM Guard.';
        return { kind: 'blocked', detail };
      }
      const r = rec(data);
      return {
        kind: 'answer',
        answer: str(r['answer']),
        sources: arr(r['retrieved_sources']).map(str),
        confidence: optNum(r['confidence_score']) ?? 0,
      };
    },

    async attemptSetpoint(token, furnaceTempC) {
      const { data } = await call(
        '/factory/furnace/setpoint',
        'POST',
        token,
        { furnace_temp_c: furnaceTempC },
        [403],
      );
      return typeof data === 'object' && data !== null && 'detail' in data
        ? String((data as Rec)['detail'])
        : 'Écriture OT interdite depuis le domaine IT.';
    },
  };
}
