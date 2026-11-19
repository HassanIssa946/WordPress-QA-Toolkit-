// 24-hour cache for public lookups (endoflife.date, api.wordpress.org, nodejs.org, WPVulnerability …).
// Every result carries its source URL and the date it was fetched, so the report can cite it.
import fs from 'node:fs';
import path from 'node:path';
import { hash } from './util.mjs';

/**
 * Fetch JSON through the run's HTTP client with a file cache in <outRoot>/cache.
 * Returns { ok, data, source: { url, fetchedAt, fromCache }, error }.
 * offline: only the cache is used (a miss is a failed lookup, never a guess).
 */
export async function cachedJson(run, url, { ttlHours = 24, offline = false, timeoutMs = 20000 } = {}) {
  const dir = path.join(run.cfg._outRoot, 'cache');
  const file = path.join(dir, `${hash(url)}.json`);
  let cached = null;
  try { cached = JSON.parse(fs.readFileSync(file, 'utf8')); } catch { /* no cache */ }
  const fresh = cached && cached.url === url && Date.now() - Date.parse(cached.fetchedAt) < ttlHours * 3600e3;
  if (fresh || (offline && cached?.url === url)) return { ok: true, data: cached.data, source: { url, fetchedAt: cached.fetchedAt, fromCache: true } };
  if (offline) return { ok: false, error: 'offline and not cached', source: { url, fetchedAt: null, fromCache: false } };
  const r = await run.http(url, { timeoutMs, redirect: 'follow', maxBody: 20 * 1024 * 1024 });
  if (!r.ok || r.status !== 200) {
    // A stale cache entry is better than nothing, but say how old it is.
    if (cached?.url === url) return { ok: true, data: cached.data, stale: true, source: { url, fetchedAt: cached.fetchedAt, fromCache: true } };
    return { ok: false, error: r.ok ? `HTTP ${r.status}` : r.error, source: { url, fetchedAt: null, fromCache: false } };
  }
  let data;
  try { data = JSON.parse(r.text); } catch { return { ok: false, error: 'response is not JSON', source: { url, fetchedAt: null, fromCache: false } }; }
  const fetchedAt = new Date().toISOString();
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(file, JSON.stringify({ url, fetchedAt, data }));
  } catch { /* cache is optional */ }
  return { ok: true, data, source: { url, fetchedAt, fromCache: false } };
}
