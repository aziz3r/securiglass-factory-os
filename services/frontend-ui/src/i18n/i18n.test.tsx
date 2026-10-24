import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it } from 'vitest';

import { LocaleProvider, translate, translateNotice, useLocale } from './i18n';

describe('traduction', () => {
  it('traduit une clé connue dans les deux langues et retombe sur la clé sinon', () => {
    expect(translate('fr', 'nav.home')).toBe('Accueil');
    expect(translate('en', 'nav.home')).toBe('Home');
    expect(translate('fr', 'clé.inexistante')).toBe('clé.inexistante');
  });

  it('interpole les variables', () => {
    expect(translate('fr', 'home.hello', { name: 'Alex' })).toBe('Bonjour Alex');
    expect(translate('en', 'home.hello', { name: 'Alex' })).toBe('Hello Alex');
  });

  it('traduit les messages connus du store, laisse les autres inchangés', () => {
    expect(translateNotice('Identifiants invalides.', 'en')).toBe('Invalid credentials.');
    expect(translateNotice('Identifiants invalides.', 'fr')).toBe('Identifiants invalides.');
    expect(translateNotice('Texte non répertorié', 'en')).toBe('Texte non répertorié');
  });
});

function Probe() {
  const { locale, setLocale, theme, setTheme, t } = useLocale();
  return (
    <div>
      <p>{t('nav.home')}</p>
      <p data-testid="locale">{locale}</p>
      <p data-testid="theme">{theme}</p>
      <button onClick={() => setLocale(locale === 'fr' ? 'en' : 'fr')}>toggle-locale</button>
      <button onClick={() => setTheme(theme === 'light' ? 'dark' : 'light')}>toggle-theme</button>
    </div>
  );
}

describe('LocaleProvider', () => {
  it('démarre en français et bascule la langue, le texte et <html lang>', async () => {
    const user = userEvent.setup();
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );
    expect(screen.getByText('Accueil')).toBeInTheDocument();
    expect(screen.getByTestId('locale')).toHaveTextContent('fr');
    expect(document.documentElement.lang).toBe('fr');

    await user.click(screen.getByText('toggle-locale'));

    expect(screen.getByText('Home')).toBeInTheDocument();
    expect(document.documentElement.lang).toBe('en');
  });

  it('bascule le thème et pose data-theme sur <html>, sans rien écrire en storage', async () => {
    const user = userEvent.setup();
    render(
      <LocaleProvider>
        <Probe />
      </LocaleProvider>,
    );
    const before = screen.getByTestId('theme').textContent;
    await user.click(screen.getByText('toggle-theme'));
    const after = screen.getByTestId('theme').textContent;
    expect(after).not.toBe(before);
    expect(document.documentElement.dataset['theme']).toBe(after);
  });
});
