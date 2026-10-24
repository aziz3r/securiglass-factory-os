import { readFileSync } from 'node:fs';
import { join } from 'node:path';

import { describe, expect, it } from 'vitest';

import {
  CSP_DIRECTIVES,
  CSP_POLICY,
  META_IGNORED_DIRECTIVES,
} from './csp';

const HTML = readFileSync(join(process.cwd(), 'index.html'), 'utf8');

function metaPolicy(): string {
  const match = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(HTML);
  if (match?.[1] === undefined) {
    throw new Error('balise CSP absente de index.html');
  }
  return match[1].replace(/\s+/g, ' ').trim();
}

describe('CSP de index.html', () => {
  it('déclare exactement la politique de production', () => {
    expect(metaPolicy()).toBe(CSP_POLICY);
  });

  it('applique les directives minimales exigées', () => {
    expect(CSP_DIRECTIVES['default-src']).toEqual(["'none'"]);
    expect(CSP_DIRECTIVES['script-src']).toEqual(["'self'"]);
    expect(CSP_DIRECTIVES['style-src']).toEqual(["'self'"]);
    expect(CSP_DIRECTIVES['connect-src']).toEqual(["'self'"]);
    expect(CSP_DIRECTIVES['base-uri']).toEqual(["'none'"]);
    expect(CSP_DIRECTIVES['form-action']).toEqual(["'self'"]);
    expect(CSP_DIRECTIVES['frame-ancestors']).toEqual(["'none'"]);
    expect(CSP_DIRECTIVES['object-src']).toEqual(["'none'"]);
  });

  it('n’autorise ni inline, ni eval, ni source externe', () => {
    const policy = metaPolicy();
    expect(policy).not.toMatch(/unsafe-inline|unsafe-eval|unsafe-hashes/);
    expect(policy).not.toMatch(/https?:|\*/);
    expect(CSP_DIRECTIVES['script-src']).not.toContain("'unsafe-inline'");
    expect(CSP_DIRECTIVES['style-src']).not.toContain("'unsafe-inline'");
  });

  it('documente les directives ignorées dans une balise meta', () => {
    expect(META_IGNORED_DIRECTIVES).toContain('frame-ancestors');
  });

  it('ne contient aucun script inline ni gestionnaire inline', () => {
    const scriptTags = [...HTML.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
    expect(scriptTags.length).toBeGreaterThan(0);
    for (const tag of scriptTags) {
      expect(tag[1]).toMatch(/\bsrc=/);
      expect(tag[2]?.trim() ?? '').toBe('');
    }
    expect(HTML).not.toMatch(/\son[a-z]+\s*=/i);
    expect(HTML).not.toContain('<style');
    expect(HTML).not.toMatch(/\sstyle\s*=/i);
  });
});
