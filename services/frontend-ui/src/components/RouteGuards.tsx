import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';

import type { Role } from '../security/roles';

import { useAppStore } from '../store/StoreProvider';
import {
  selectRoles,
  selectCanReadAudit,
  selectCanReadCustomers,
  selectIsAuthenticated,
} from '../store/selectors';
import { AccessDeniedPage } from '../pages/AccessDeniedPage';

export function RequireAuth({ children }: { children: ReactNode }) {
  const authenticated = useAppStore(selectIsAuthenticated);
  if (!authenticated) {
    return <Navigate to="/login" replace />;
  }
  return <>{children}</>;
}

export function RequireCustomerAccess({ children }: { children: ReactNode }) {
  const allowed = useAppStore(selectCanReadCustomers);
  if (!allowed) {
    return <AccessDeniedPage />;
  }
  return <>{children}</>;
}

export function RequireAuditAccess({ children }: { children: ReactNode }) {
  const allowed = useAppStore(selectCanReadAudit);
  if (!allowed) {
    return <AccessDeniedPage />;
  }
  return <>{children}</>;
}

/** Garde générique : n'affiche la page que si l'un des rôles courants satisfait la règle. */
export function RequireCapability({
  allow,
  children,
}: {
  allow: (roles: readonly Role[]) => boolean;
  children: ReactNode;
}) {
  const roles = useAppStore(selectRoles);
  if (!allow(roles)) {
    return <AccessDeniedPage />;
  }
  return <>{children}</>;
}
