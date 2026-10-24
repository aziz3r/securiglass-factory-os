/**
 * Vérification du build de production :
 * - CSP stricte présente et conforme ;
 * - aucun script inline, aucun handler/style inline ;
 * - aucun source map ;
 * - mesure réelle des tailles (brut + gzip).
 *
 * Échoue avec un code non nul à la moindre violation.
 */
import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { gzipSync } from 'node:zlib';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const DIST = join(ROOT, 'dist');

const REQUIRED_DIRECTIVES = new Map([
  ['default-src', ["'none'"]],
  ['script-src', ["'self'"]],
  ['style-src', ["'self'"]],
  ['img-src', ["'self'", 'data:']],
  ['font-src', ["'self'"]],
  ['connect-src', ["'self'"]],
  ['base-uri', ["'none'"]],
  ['form-action', ["'self'"]],
  ['frame-ancestors', ["'none'"]],
]);

function fail(message) {
  console.error(`✗ ${message}`);
  process.exitCode = 1;
}

function readCsp(html) {
  const match = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(html);
  if (match?.[1] === undefined) {
    fail('CSP <meta http-equiv="Content-Security-Policy"> absente du build');
    return null;
  }
  return match[1].replace(/\s+/g, ' ').trim();
}

function checkCsp(policy) {
  if (policy === null) {
    return;
  }
  if (/unsafe-inline|unsafe-eval|unsafe-hashes/.test(policy)) {
    fail('la CSP contient un assouplissement unsafe-*');
  }
  if (/https?:|\*/.test(policy)) {
    fail('la CSP autorise une source externe ou un joker');
  }
  const directives = new Map();
  for (const part of policy.split(';')) {
    const tokens = part.trim().split(/\s+/).filter(Boolean);
    const [name, ...sources] = tokens;
    if (name !== undefined) {
      directives.set(name, sources);
    }
  }
  for (const [name, sources] of REQUIRED_DIRECTIVES) {
    const actual = directives.get(name);
    if (actual === undefined) {
      fail(`directive CSP manquante : ${name}`);
      continue;
    }
    for (const source of sources) {
      if (!actual.includes(source)) {
        fail(`directive ${name} : source ${source} manquante`);
      }
    }
  }
}

function checkNoInline(html) {
  const scriptTags = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)];
  if (scriptTags.length === 0) {
    fail('aucune balise <script> trouvée : le bundle JS est absent');
  }
  for (const tag of scriptTags) {
    const attributes = tag[1] ?? '';
    const body = tag[2] ?? '';
    if (!/\bsrc=/.test(attributes)) {
      fail('script inline détecté dans dist/index.html');
    }
    if (body.trim().length > 0) {
      fail('contenu inline détecté dans une balise <script>');
    }
  }
  if (/<style\b/i.test(html)) {
    fail('balise <style> inline détectée');
  }
  if (/\son[a-z]+\s*=/i.test(html)) {
    fail('gestionnaire d’événement inline détecté');
  }
  if (/\sstyle\s*=/i.test(html)) {
    fail('attribut style inline détecté');
  }
  if (html.includes('/@vite/client')) {
    fail('le client de développement Vite est présent dans le build');
  }
}

function walk(directory) {
  const files = [];
  for (const entry of readdirSync(directory)) {
    const path = join(directory, entry);
    if (statSync(path).isDirectory()) {
      files.push(...walk(path));
    } else {
      files.push(path);
    }
  }
  return files;
}

if (statSync(DIST, { throwIfNoEntry: false }) === undefined) {
  console.error('✗ dist/ introuvable : exécuter `npm run build` d’abord.');
  process.exit(1);
}

const html = readFileSync(join(DIST, 'index.html'), 'utf8');
checkCsp(readCsp(html));
checkNoInline(html);

const files = walk(DIST).sort();
const rows = [];
let totalRaw = 0;
let totalGzip = 0;
for (const file of files) {
  if (file.endsWith('.map')) {
    fail(`source map exposée dans le build : ${relative(DIST, file)}`);
  }
  const content = readFileSync(file);
  const gzip = gzipSync(content);
  totalRaw += content.byteLength;
  totalGzip += gzip.byteLength;
  rows.push({
    file: relative(DIST, file),
    raw: content.byteLength,
    gzip: gzip.byteLength,
  });
}

const kb = (bytes) => `${(bytes / 1024).toFixed(2)} KiB`;

console.log('Build de production — mesures réelles');
for (const row of rows) {
  console.log(`  ${row.file.padEnd(42)} ${kb(row.raw).padStart(11)}  gzip ${kb(row.gzip).padStart(10)}`);
}
console.log(`  ${'TOTAL'.padEnd(42)} ${kb(totalRaw).padStart(11)}  gzip ${kb(totalGzip).padStart(10)}`);
console.log(`  scripts inline : 0 | sources externes : 0 | source maps : 0`);

if (process.exitCode !== 1) {
  console.log('✓ Vérification du build réussie (CSP stricte, aucun inline).');
}
