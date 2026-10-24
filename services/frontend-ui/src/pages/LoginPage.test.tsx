import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { LoginPage } from './LoginPage';
import { LocaleProvider } from '../i18n/i18n';
import { StoreProvider } from '../store/StoreProvider';
import { createAppStore } from '../store/createAppStore';
import { createFakeApi, createFakeSocket } from '../test/fixtures';

function renderLogin() {
  const api = createFakeApi();
  const socket = createFakeSocket();
  const store = createAppStore({ api: api.api, socketFactory: socket.factory });
  render(
    <LocaleProvider>
      <StoreProvider store={store}>
        <MemoryRouter initialEntries={['/login']}>
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/dashboard" element={<h1>Tableau de bord</h1>} />
          </Routes>
        </MemoryRouter>
      </StoreProvider>
    </LocaleProvider>,
  );
  return { api, store };
}

describe('LoginPage', () => {
  it('valide les champs avant tout appel réseau', async () => {
    const user = userEvent.setup();
    const { api } = renderLogin();

    await user.click(screen.getByRole('button', { name: 'Se connecter' }));

    expect(screen.getByText('Identifiant : 3 à 64 caractères.')).toBeInTheDocument();
    expect(screen.getByText('Mot de passe requis (256 caractères maximum).')).toBeInTheDocument();
    expect(api.login).not.toHaveBeenCalled();
  });

  it('connecte puis redirige vers le tableau de bord', async () => {
    const user = userEvent.setup();
    const { api } = renderLogin();

    await user.type(screen.getByLabelText('Identifiant'), 'manager');
    await user.type(screen.getByLabelText('Mot de passe'), 'correct-horse');
    await user.click(screen.getByRole('button', { name: 'Se connecter' }));

    expect(await screen.findByText('Tableau de bord')).toBeInTheDocument();
    expect(api.login).toHaveBeenCalledWith({
      username: 'manager',
      password: 'correct-horse',
    });
  });
});
