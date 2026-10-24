import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { CustomersPage } from './CustomersPage';
import { LocaleProvider } from '../i18n/i18n';
import { StoreProvider } from '../store/StoreProvider';
import { createAppStore } from '../store/createAppStore';
import { CUSTOMER, createFakeApi, createFakeSocket, PLANT_MANAGER } from '../test/fixtures';

describe('CustomersPage — échappement', () => {
  it('affiche une raison sociale hostile comme texte, jamais comme HTML', async () => {
    const malicious = '<img src=x onerror="alert(1)">';
    const api = createFakeApi(PLANT_MANAGER);
    api.listCustomers.mockResolvedValueOnce([{ ...CUSTOMER, company_name: malicious }]);
    const socket = createFakeSocket();
    const store = createAppStore({ api: api.api, socketFactory: socket.factory });
    await store.getState().login({ username: 'manager', password: 'secret' });

    render(
      <LocaleProvider>
        <StoreProvider store={store}>
          <MemoryRouter>
            <CustomersPage />
          </MemoryRouter>
        </StoreProvider>
      </LocaleProvider>,
    );

    expect(await screen.findByText(malicious)).toBeInTheDocument();
    expect(document.querySelector('img')).toBeNull();
    expect(document.querySelector('[onerror]')).toBeNull();
  });
});
