import {
  createContext,
  useContext,
  type ReactNode,
} from 'react';
import { useStore } from 'zustand';

import type { AppStore, AppStoreApi } from './createAppStore';

const StoreContext = createContext<AppStoreApi | null>(null);

export interface StoreProviderProps {
  store: AppStoreApi;
  children: ReactNode;
}

export function StoreProvider({ store, children }: StoreProviderProps) {
  return <StoreContext.Provider value={store}>{children}</StoreContext.Provider>;
}

/**
 * Abonnement Zustand typé. Les sélecteurs doivent retourner des valeurs
 * stables (primitives, références de slice) pour éviter les re-rendus en boucle.
 */
export function useAppStore<T>(selector: (state: AppStore) => T): T {
  const store = useContext(StoreContext);
  if (store === null) {
    throw new Error('useAppStore doit être utilisé dans <StoreProvider>.');
  }
  return useStore(store, selector);
}
