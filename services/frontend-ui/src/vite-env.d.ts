/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** URL WSS explicite (doit commencer par wss:). Sinon même origine /ws/telemetry. */
  readonly VITE_WSS_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
