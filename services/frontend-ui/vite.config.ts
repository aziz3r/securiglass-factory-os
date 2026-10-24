import { defineConfig } from 'vitest/config';
import type { Plugin } from 'vite';
import path from 'node:path';

/**
 * En développement uniquement, Vite injecte les styles via des balises <style>
 * et ouvre un WebSocket HMR. La CSP de production reste inchangée : ce plugin
 * n'a d'effet qu'en mode `serve`. `npm run verify:build` vérifie le build.
 */
function devOnlyCspRelaxation(): Plugin {
  return {
    name: 'securiglass-dev-csp-relaxation',
    apply: 'serve',
    transformIndexHtml(html) {
      return html
        .replace("style-src 'self';", "style-src 'self' 'unsafe-inline';")
        .replace(
          "connect-src 'self';",
          "connect-src 'self' ws://localhost:5173 ws://127.0.0.1:5173;",
        );
    },
  };
}

export default defineConfig({
  base: '/',
  resolve: {
    alias: {
      jsdom: path.resolve(__dirname, 'node_modules/jsdom'),
    },
  },
  plugins: [devOnlyCspRelaxation()],
  // Pas de @vitejs/plugin-react : Vite 8 transforme le JSX via Oxc en se basant
  // sur tsconfig (`jsx: react-jsx`), ce qui évite le préambule inline de Fast
  // Refresh en développement (CSP).
  build: {
    target: 'es2022',
    sourcemap: false,
    assetsInlineLimit: 0,
    cssCodeSplit: true,
    reportCompressedSize: true,
  },
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: false,
      },
      '/health': {
        target: 'http://127.0.0.1:8000',
        changeOrigin: false,
      },
      '/ws': {
        target: 'ws://127.0.0.1:8000',
        ws: true,
      },
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/test/setup.ts'],
    css: false,
    restoreMocks: true,
    clearMocks: true,
    unstubGlobals: true,
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      reportsDirectory: './coverage',
      include: [
        'src/api/**/*.ts',
        'src/realtime/**/*.ts',
        'src/security/**/*.ts',
        'src/store/**/*.ts',
        'src/utils/**/*.ts',
        'src/validation/**/*.ts',
      ],
      exclude: ['src/**/*.test.ts', 'src/**/*.test.tsx', 'src/test/**'],
      thresholds: {
        lines: 80,
        functions: 80,
        branches: 80,
        statements: 80,
      },
    },
  },
});
