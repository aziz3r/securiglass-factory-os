import type { ReactNode } from 'react';

export type BadgeTone = 'ok' | 'warn' | 'danger' | 'neutral' | 'info';

export interface StatusBadgeProps {
  tone: BadgeTone;
  children: ReactNode;
}

export function StatusBadge({ tone, children }: StatusBadgeProps) {
  return <span className={`badge badge--${tone}`}>{children}</span>;
}
