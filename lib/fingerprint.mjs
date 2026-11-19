// Stable finding IDs. A finding must keep its ID when unrelated lines are added above it, otherwise the run
// comparison reports the same problem as "new" plus "resolved".
//
// - code findings: check + rule + file + the normalised text of the flagged line + which occurrence of that
//   text in the file it is (two identical lines stay two findings);
// - URL findings: check + rule + URL without cache-busting parameters;
// - everything else: check + rule + file/component.
// The line number is kept on the finding for display only.
import fs from 'node:fs';
import { hash } from './util.mjs';

/** Query parameters that only bust caches; they must not change a finding's identity. */
const CACHE_PARAMS = new Set(['ver', 'v', '_', 'ts', 'cb', 'nocache', 'rand', 'time', 'timestamp']);

export const normalizeLine = (s) => String(s ?? '').trim().replace(/\s+/g, ' ');

/** Lines of a file (cached per run). null when the file cannot be read. */
function fileLines(absFile, cache) {
  if (cache?.has(absFile)) return cache.get(absFile);
  let lines = null;
  try {
    const st = fs.statSync(absFile);
    if (st.isFile() && st.size <= 5 * 1024 * 1024) lines = fs.readFileSync(absFile, 'utf8').split(/\r?\n/).map(normalizeLine);
  } catch { /* unreadable → line-number fallback */ }
  cache?.set(absFile, lines);
  return lines;
}

/**
 * Anchor for a code location: "<normalised line text>#<occurrence>", or null when the line cannot be read
 * (missing file, line out of range, blank line).
 */
export function codeAnchor(absFile, line, cache = new Map()) {
  const n = Number(line);
  if (!absFile || !Number.isInteger(n) || n < 1) return null;
  const lines = fileLines(absFile, cache);
  if (!lines || n > lines.length) return null;
  const text = lines[n - 1];
  if (!text) return null;
  let occurrence = 0;
  for (let i = 0; i < n - 1; i++) if (lines[i] === text) occurrence++;
  return `${text}#${occurrence}`;
}

/** URL without fragment, default port and cache-busting parameters; remaining parameters sorted. */
export function normalizeUrl(u) {
  let url;
  try { url = new URL(u); } catch { return String(u ?? ''); }
  url.hash = '';
  const params = [...url.searchParams.entries()].filter(([k]) => !CACHE_PARAMS.has(k.toLowerCase())).sort(([a, x], [b, y]) => a.localeCompare(b) || x.localeCompare(y));
  url.search = '';
  for (const [k, v] of params) url.searchParams.append(k, v);
  return `${url.protocol}//${url.host.toLowerCase()}${url.pathname || '/'}${url.search}`;
}

/**
 * @param {object} f  { check, rule, title, file (display path), absFile, line, url, component, fingerprintExtra }
 * @param {Map} [cache]  per-run file cache
 */
export function findingId(f, cache) {
  const kind = f.rule || f.title;
  if (f.fingerprintExtra !== undefined && f.fingerprintExtra !== null) return hash(f.check, kind, f.file || f.url || '', f.fingerprintExtra);
  if (f.file) {
    const anchor = f.line ? codeAnchor(f.absFile, f.line, cache) : null;
    return hash(f.check, kind, f.file.split('\\').join('/'), anchor ?? (f.line ? `L${f.line}` : ''));
  }
  if (f.url) return hash(f.check, kind, normalizeUrl(f.url), '');
  const comp = f.component && typeof f.component === 'object' ? `${f.component.type || ''}:${f.component.slug || f.component.name || ''}` : f.component || '';
  return hash(f.check, kind, comp, '');
}
