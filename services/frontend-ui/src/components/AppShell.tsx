import { NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom';

import { useLocale } from '../i18n/i18n';
import type { SocketStatus } from '../realtime/telemetrySocket';
import {
  canUseAssistant,
  canViewProduction,
  canViewSales,
  canViewSecurity,
  canViewStock,
  getRoleLabel,
} from '../security/roles';
import { useAppStore } from '../store/StoreProvider';
import {
  selectCanReadAudit,
  selectCanReadCustomers,
  selectRoles,
  selectUser,
} from '../store/selectors';

const SOCKET_STATUS_KEYS: Readonly<Record<SocketStatus, string>> = {
  idle: 'topbar.status.idle',
  connecting: 'topbar.status.connecting',
  authenticating: 'topbar.status.authenticating',
  live: 'topbar.status.live',
  reconnecting: 'topbar.status.reconnecting',
  closed: 'topbar.status.closed',
  error: 'topbar.status.error',
};

const PAGE_TITLE_KEYS: Readonly<Record<string, string>> = {
  '/dashboard': 'nav.home',
  '/production': 'nav.production',
  '/stock': 'nav.stock',
  '/sales': 'nav.sales',
  '/customers': 'nav.customers',
  '/assistant': 'nav.assistant',
  '/security': 'nav.security',
  '/audit': 'nav.audit',
};

interface NavItem {
  to: string;
  labelKey: string;
  allowed: boolean;
}

function navClass({ isActive }: { isActive: boolean }): string {
  return isActive ? 'nav-link nav-link--active' : 'nav-link';
}

function initials(name: string): string {
  return name
    .replace(/^demo_/, '')
    .split(/[_\s.-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part.charAt(0).toUpperCase())
    .join('');
}

function ThemeToggle() {
  const { theme, setTheme, t } = useLocale();
  const dark = theme === 'dark';
  return (
    <button
      type="button"
      className="icon-toggle"
      onClick={() => setTheme(dark ? 'light' : 'dark')}
      aria-label={dark ? t('topbar.themeToLight') : t('topbar.themeToDark')}
      title={dark ? t('topbar.themeToLight') : t('topbar.themeToDark')}
    >
      {dark ? (
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <circle cx="12" cy="12" r="4.5" />
          <path d="M12 2.5v2.4M12 19.1v2.4M4.5 12H2M22 12h-2.5M5.3 5.3l1.7 1.7M17 17l1.7 1.7M18.7 5.3 17 7M7 17l-1.7 1.7" />
        </svg>
      ) : (
        <svg viewBox="0 0 24 24" aria-hidden="true">
          <path d="M21 14.5A8.5 8.5 0 1 1 9.5 3a7 7 0 0 0 11.5 11.5z" />
        </svg>
      )}
    </button>
  );
}

function LanguageToggle() {
  const { locale, setLocale, t } = useLocale();
  const next = locale === 'fr' ? 'en' : 'fr';
  return (
    <button
      type="button"
      className="icon-toggle icon-toggle--text"
      onClick={() => setLocale(next)}
      aria-label={t('topbar.language')}
      title={t('topbar.language')}
    >
      {locale.toUpperCase()}
    </button>
  );
}

export function AppShell() {
  const { t, locale } = useLocale();
  const user = useAppStore(selectUser);
  const roles = useAppStore(selectRoles);
  const canReadCustomers = useAppStore(selectCanReadCustomers);
  const canReadAudit = useAppStore(selectCanReadAudit);
  const socketStatus = useAppStore((state) => state.telemetry.status);
  const logout = useAppStore((state) => state.logout);
  const navigate = useNavigate();
  const location = useLocation();

  function handleLogout(): void {
    void logout();
    navigate('/login', { replace: true });
  }

  const items: NavItem[] = [
    { to: '/production', labelKey: 'nav.production', allowed: canViewProduction(roles) },
    { to: '/stock', labelKey: 'nav.stock', allowed: canViewStock(roles) },
    { to: '/sales', labelKey: 'nav.sales', allowed: canViewSales(roles) },
    { to: '/customers', labelKey: 'nav.customers', allowed: canReadCustomers },
    { to: '/assistant', labelKey: 'nav.assistant', allowed: canUseAssistant(roles) },
    { to: '/security', labelKey: 'nav.security', allowed: canViewSecurity(roles) },
    { to: '/audit', labelKey: 'nav.audit', allowed: canReadAudit },
  ];
  const visible = (to: string[]): NavItem[] =>
    items.filter((i) => to.includes(i.to) && i.allowed);
  const groups = [
    {
      titleKey: 'nav.group.operations',
      items: visible(['/production', '/stock', '/sales', '/customers', '/assistant']),
    },
    { titleKey: 'nav.group.security', items: visible(['/security', '/audit']) },
  ].filter((g) => g.items.length > 0);
  const showStatus = canViewProduction(roles);
  const live = socketStatus === 'live';
  const tone = live
    ? 'ok'
    : socketStatus === 'error' || socketStatus === 'closed'
      ? 'danger'
      : 'warn';

  return (
    <div className="shell">
      <a className="skip-link" href="#main-content">
        {locale === 'fr' ? 'Aller au contenu principal' : 'Skip to main content'}
      </a>

      <aside className="sidebar" aria-label={locale === 'fr' ? 'Navigation de la console' : 'Console navigation'}>
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            SG
          </span>
          <span className="brand-text">
            <strong>{t('brand.name')}</strong>
            <small>{t('brand.tagline')}</small>
          </span>
        </div>
        <nav className="nav" aria-label={locale === 'fr' ? 'Navigation principale' : 'Main navigation'}>
          <NavLink to="/dashboard" className={navClass}>
            {t('nav.home')}
          </NavLink>
          {groups.map((group) => (
            <div key={group.titleKey} className="nav-group">
              <p className="nav-section">{t(group.titleKey)}</p>
              {group.items.map((item) => (
                <NavLink key={item.to} to={item.to} className={navClass}>
                  {t(item.labelKey)}
                </NavLink>
              ))}
            </div>
          ))}
        </nav>
        <p className="sidebar-note">{t('sidebar.note')}</p>
      </aside>

      <div className="shell-main">
        <header className="topbar">
          <div className="topbar-title">
            <h1>{t(PAGE_TITLE_KEYS[location.pathname] ?? 'brand.name')}</h1>
            <span>{t('brand.subtitle')}</span>
          </div>

          {showStatus ? (
            <span className={`pill pill--${tone}`} role="status" title={t('topbar.live')}>
              <span className="pill-dot" aria-hidden="true" />
              {t('topbar.live')} : {t(SOCKET_STATUS_KEYS[socketStatus])}
            </span>
          ) : null}

          <div className="topbar-controls">
            <ThemeToggle />
            <LanguageToggle />
          </div>

          <div className="topbar-user">
            <span className="avatar" aria-hidden="true">
              {initials(user?.username ?? 'SG')}
            </span>
            <div className="user-identity">
              <strong>{user?.username ?? 'Session'}</strong>
              <span title={roles.map((role) => getRoleLabel(locale, role)).join(', ')}>
                {roles.map((role) => getRoleLabel(locale, role)).join(' · ')}
                {user !== null ? ` · ${t('topbar.clearance')} ${user.clearance_level}/5` : ''}
              </span>
            </div>
            <button type="button" className="ghost-button" onClick={handleLogout}>
              {t('topbar.logout')}
            </button>
          </div>
        </header>

        <main id="main-content" className="content" tabIndex={-1}>
          <Outlet />
        </main>
      </div>
    </div>
  );
}
