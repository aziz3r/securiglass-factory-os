import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter } from 'react-router-dom';

import { App } from './App';
import { LocaleProvider } from './i18n/i18n';
import { StoreProvider } from './store/StoreProvider';
import { createRuntimeStore } from './store/runtime';
import './styles.css';
import './ui.css';

const container = document.getElementById('root');
if (!(container instanceof HTMLElement)) {
  throw new Error('Conteneur #root introuvable');
}

const store = createRuntimeStore();

createRoot(container).render(
  <StrictMode>
    <LocaleProvider>
      <StoreProvider store={store}>
        <BrowserRouter>
          <App />
        </BrowserRouter>
      </StoreProvider>
    </LocaleProvider>
  </StrictMode>,
);
