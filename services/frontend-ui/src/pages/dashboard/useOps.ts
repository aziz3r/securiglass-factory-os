import { useCallback, useEffect, useRef, useState } from 'react';

import { UnauthorizedError } from '../../api/errors';
import { createOpsClient, type Overview, type OpsPort } from '../../api/ops';
import type { TelemetrySample } from '../../realtime/telemetrySocket';
import { useAppStore } from '../../store/StoreProvider';
import { selectToken } from '../../store/selectors';

const OVERVIEW_REFRESH_MS = 5000;
export const HISTORY_SIZE = 120;

let sharedApi: OpsPort | null = null;

export function getOpsApi(): OpsPort {
  sharedApi ??= createOpsClient();
  return sharedApi;
}

export interface OpsData {
  overview: Overview | null;
  overviewError: string | null;
  samples: TelemetrySample[];
  refresh: () => Promise<void>;
}

/** Vue d'ensemble rafraîchie périodiquement + historique alimenté par le flux WSS. */
export function useOpsData({ history = true }: { history?: boolean } = {}): OpsData {
  const token = useAppStore(selectToken);
  const expireSession = useAppStore((state) => state.expireSession);
  const liveSample = useAppStore((state) => state.telemetry.sample);
  const receivedAt = useAppStore((state) => state.telemetry.sampleReceivedAt);

  const [overview, setOverview] = useState<Overview | null>(null);
  const [overviewError, setOverviewError] = useState<string | null>(null);
  const [samples, setSamples] = useState<TelemetrySample[]>([]);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(async (): Promise<void> => {
    if (token === null) {
      return;
    }
    try {
      const next = await getOpsApi().overview(token);
      if (mounted.current) {
        setOverview(next);
        setOverviewError(null);
      }
    } catch (error) {
      if (error instanceof UnauthorizedError) {
        expireSession();
        return;
      }
      if (mounted.current) {
        setOverviewError('Vue d’ensemble indisponible.');
      }
    }
  }, [token, expireSession]);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => {
      void refresh();
    }, OVERVIEW_REFRESH_MS);
    return () => {
      window.clearInterval(timer);
    };
  }, [refresh]);

  useEffect(() => {
    if (token === null || !history) {
      return undefined;
    }
    let cancelled = false;
    getOpsApi()
      .history(token, HISTORY_SIZE)
      .then((points) => {
        if (!cancelled) {
          setSamples((current) => mergeSamples(points, current));
        }
      })
      .catch((error: unknown) => {
        if (error instanceof UnauthorizedError) {
          expireSession();
        }
      });
    return () => {
      cancelled = true;
    };
  }, [token, history, expireSession]);

  useEffect(() => {
    if (!history || liveSample === null) {
      return;
    }
    setSamples((current) => mergeSamples(current, [liveSample]));
  }, [history, liveSample, receivedAt]);

  return { overview, overviewError, samples, refresh };
}

function mergeSamples(
  base: readonly TelemetrySample[],
  extra: readonly TelemetrySample[],
): TelemetrySample[] {
  const seen = new Set<string>();
  const merged: TelemetrySample[] = [];
  for (const sample of [...base, ...extra]) {
    const key = sample.timestamp ?? '';
    if (key !== '' && seen.has(key)) {
      continue;
    }
    seen.add(key);
    merged.push(sample);
  }
  merged.sort((a, b) => (a.timestamp ?? '').localeCompare(b.timestamp ?? ''));
  return merged.slice(-HISTORY_SIZE);
}
