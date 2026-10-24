import type { ReactNode } from 'react';

import { InfoTip } from '../../components/InfoTip';

export interface KpiProps {
  label: string;
  value: string;
  hint?: string | undefined;
  info?: ReactNode;
  tone?: 'ok' | 'warn' | 'danger' | undefined;
}

export function Kpi({ label, value, hint, info, tone }: KpiProps) {
  return (
    <div className={tone !== undefined ? `kpi kpi--${tone}` : 'kpi'}>
      <span className="kpi-label">
        {label}
        {info !== undefined ? <InfoTip label={label}>{info}</InfoTip> : null}
      </span>
      <strong>{value}</strong>
      {hint !== undefined ? <small>{hint}</small> : null}
    </div>
  );
}
