import { useEffect } from 'react';
import { Navigate, Route, Routes } from 'react-router-dom';

import { AppShell } from './components/AppShell';
import {
  RequireCapability,
  RequireAuditAccess,
  RequireAuth,
  RequireCustomerAccess,
} from './components/RouteGuards';
import { AccessDeniedPage } from './pages/AccessDeniedPage';
import { AuditPage } from './pages/AuditPage';
import { CustomersPage } from './pages/CustomersPage';
import { AssistantPage } from './pages/AssistantPage';
import { HomePage } from './pages/HomePage';
import { ProductionPage } from './pages/ProductionPage';
import { SalesPage } from './pages/SalesPage';
import { SecurityPage } from './pages/SecurityPage';
import { StockPage } from './pages/StockPage';
import { LoginPage } from './pages/LoginPage';
import { NotFoundPage } from './pages/NotFoundPage';
import { useAppStore } from './store/StoreProvider';
import {
  canUseAssistant,
  canViewProduction,
  canViewSales,
  canViewSecurity,
  canViewStock,
} from './security/roles';
import { selectIsAuthenticated, selectRoles } from './store/selectors';

export function App() {
  const authenticated = useAppStore(selectIsAuthenticated);
  const roles = useAppStore(selectRoles);
  const wantsTelemetry = canViewProduction(roles);
  const connectTelemetry = useAppStore((state) => state.connectTelemetry);
  const disconnectTelemetry = useAppStore((state) => state.disconnectTelemetry);

  useEffect(() => {
    if (!authenticated || !wantsTelemetry) {
      return undefined;
    }
    connectTelemetry();
    return () => {
      disconnectTelemetry();
    };
  }, [authenticated, wantsTelemetry, connectTelemetry, disconnectTelemetry]);

  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/dashboard" replace />} />
        <Route path="dashboard" element={<HomePage />} />
        <Route
          path="production"
          element={
            <RequireCapability allow={canViewProduction}>
              <ProductionPage />
            </RequireCapability>
          }
        />
        <Route
          path="stock"
          element={
            <RequireCapability allow={canViewStock}>
              <StockPage />
            </RequireCapability>
          }
        />
        <Route
          path="sales"
          element={
            <RequireCapability allow={canViewSales}>
              <SalesPage />
            </RequireCapability>
          }
        />
        <Route
          path="assistant"
          element={
            <RequireCapability allow={canUseAssistant}>
              <AssistantPage />
            </RequireCapability>
          }
        />
        <Route
          path="security"
          element={
            <RequireCapability allow={canViewSecurity}>
              <SecurityPage />
            </RequireCapability>
          }
        />
        <Route
          path="customers"
          element={
            <RequireCustomerAccess>
              <CustomersPage />
            </RequireCustomerAccess>
          }
        />
        <Route
          path="audit"
          element={
            <RequireAuditAccess>
              <AuditPage />
            </RequireAuditAccess>
          }
        />
        <Route path="access-denied" element={<AccessDeniedPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
