// @vitest-environment node
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const SRC_DIR = fileURLToPath(new URL('..', import.meta.url));
const PROJECT_DIR = fileURLToPath(new URL('../..', import.meta.url));

function listSourceFiles(directory: string): string[] {
  const files: string[] = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      if (entry === 'test') {
        continue;
      }
      files.push(...listSourceFiles(path));
      continue;
    }
    if (!/\.(ts|tsx)$/.test(entry) || /\.test\.(ts|tsx)$/.test(entry)) {
      continue;
    }
    files.push(path);
  }
  return files;
}

const SOURCE_FILES = listSourceFiles(SRC_DIR);
const SOURCE_TEXT = SOURCE_FILES.map((file) => ({
  file,
  content: readFileSync(file, 'utf8'),
}));

const FORBIDDEN_PATTERNS: ReadonlyArray<{ label: string; pattern: RegExp }> = [
  { label: 'dangerouslySetInnerHTML', pattern: /dangerouslySetInnerHTML/ },
  { label: 'innerHTML', pattern: /\.innerHTML\b/ },
  { label: 'outerHTML', pattern: /\.outerHTML\b/ },
  { label: 'insertAdjacentHTML', pattern: /insertAdjacentHTML\s*\(/ },
  { label: 'eval()', pattern: /\beval\s*\(/ },
  { label: 'new Function()', pattern: /\bnew\s+Function\s*\(/ },
  { label: 'localStorage', pattern: /\b(?:window\.)?localStorage\s*\./ },
  { label: 'sessionStorage', pattern: /\b(?:window\.)?sessionStorage\s*\./ },
  { label: 'document.cookie', pattern: /document\s*\.\s*cookie/ },
  { label: 'setTimeout(string)', pattern: /setTimeout\s*\(\s*['"`]/ },
];

describe('invariants de sécurité du code source', () => {
  it('aucune API de stockage navigateur, aucun cookie', () => {
    for (const { file, content } of SOURCE_TEXT) {
      expect(content, file).not.toMatch(/\b(?:window\.)?localStorage\s*\./);
      expect(content, file).not.toMatch(/\b(?:window\.)?sessionStorage\s*\./);
      expect(content, file).not.toMatch(/document\s*\.\s*cookie/);
      expect(content, file).not.toMatch(/indexedDB/);
    }
  });

  it('aucune injection HTML ni exécution dynamique', () => {
    for (const { file, content } of SOURCE_TEXT) {
      expect(content, file).not.toMatch(/dangerouslySetInnerHTML/);
      expect(content, file).not.toMatch(/\.innerHTML\b/);
      expect(content, file).not.toMatch(/\.outerHTML\b/);
      expect(content, file).not.toMatch(/insertAdjacentHTML\s*\(/);
      expect(content, file).not.toMatch(/\beval\s*\(/);
      expect(content, file).not.toMatch(/\bnew\s+Function\s*\(/);
    }
  });

  it('aucun stockage ni attribut inline dans index.html', () => {
    const html = readFileSync(join(PROJECT_DIR, 'index.html'), 'utf8');
    expect(html).not.toMatch(/\son[a-z]+\s*=/i);
    expect(html).not.toMatch(/\sstyle\s*=/i);
    expect(html).toContain('Content-Security-Policy');
  });

  it('dépendances de production sans Redux ni bibliothèque de rendu HTML', () => {
    const manifest = JSON.parse(
      readFileSync(join(PROJECT_DIR, 'package.json'), 'utf8'),
    ) as { dependencies?: Record<string, string> };
    const dependencies = Object.keys(manifest.dependencies ?? {});
    expect(dependencies).toEqual(
      expect.arrayContaining(['react', 'react-dom', 'react-router-dom', 'zustand']),
    );
    expect(dependencies.some((name) => name.includes('redux'))).toBe(false);
    expect(dependencies).not.toContain('dompurify');
  });

  it('aucune correspondance interdite détectée dans les sources', () => {
    for (const rule of FORBIDDEN_PATTERNS) {
      for (const { file, content } of SOURCE_TEXT) {
        expect(content, `${rule.label} dans ${file}`).not.toMatch(rule.pattern);
      }
    }
  });
});
