// Performance: Lighthouse (lab, mobile + desktop), caching and compression headers, and nonces cached longer than
// their lifetime. Read-only GET requests; Lighthouse loads pages in headless Chromium.
import fs from 'node:fs';
import path from 'node:path';
import { createRequire } from 'node:module';
import { run as runCmd, truncate } from '../lib/util.mjs';
import { reachableTargets, getPage, pageUrl } from '../lib/targets.mjs';
import { nonceMarkers, assetUrls, cacheEvidence } from '../lib/html.mjs';

const CAT = 'performance';
const require = createRequire(import.meta.url);

/** Lighthouse JSON → scores, key metrics and the top opportunities. */
export function summarizeLighthouse(lhr) {
  const a = lhr?.audits || {};
  const num = (id) => (typeof a[id]?.numericValue === 'number' ? a[id].numericValue : null);
  const scores = Object.fromEntries(Object.entries(lhr?.categories || {}).map(([k, v]) => [k, v.score == null ? null : Math.round(v.score * 100)]));
  const opportunities = Object.values(a)
    .filter((x) => x.details?.type === 'opportunity' && (x.details.overallSavingsMs > 0 || x.details.overallSavingsBytes > 0) && x.score !== null && x.score < 0.9)
    .sort((x, y) => (y.details.overallSavingsMs || 0) - (x.details.overallSavingsMs || 0) || (y.details.overallSavingsBytes || 0) - (x.details.overallSavingsBytes || 0))
    .slice(0, 5)
    .map((x) => ({ id: x.id, title: x.title, savingsMs: Math.round(x.details.overallSavingsMs || 0), savingsKb: Math.round((x.details.overallSavingsBytes || 0) / 1024) }));
  return {
    scores,
    lcpMs: num('largest-contentful-paint'),
    cls: num('cumulative-layout-shift'),
    tbtMs: num('total-blocking-time'),
    fcpMs: num('first-contentful-paint'),
    opportunities,
    runtimeError: lhr?.runtimeError?.code || null,
    version: lhr?.lighthouseVersion || null,
  };
}

/**
 * Nonce cached longer than it is guaranteed valid. WordPress nonces live 12–24 h (two "ticks" of nonce_life/2),
 * so a cached copy older than half the lifetime may hand visitors an expired nonce.
 * Returns null (no problem / no evidence) or { confidence, age, why }.
 */
export function cachedNonceRisk(ev, lifetimeSec = 86400) {
  const safe = lifetimeSec / 2;
  if (!ev.anyHit && !(ev.maxAge > safe && !ev.noStore)) return null;
  if (ev.ageSec != null && ev.ageSec > safe) return { confidence: 'confirmed', why: `served from cache (${ev.layers.filter((l) => l.hit).map((l) => l.layer).join(', ') || 'shared cache'}) and the cached copy is ${(ev.ageSec / 3600).toFixed(1)} h old (${ev.ageFrom}) — older than the ${safe / 3600} h a nonce is guaranteed valid` };
  if (ev.maxAge != null && ev.maxAge > safe && !ev.noStore) return { confidence: 'likely', why: `cache lifetime ${Math.round(ev.maxAge / 3600)} h (Cache-Control) is longer than the ${safe / 3600} h a nonce is guaranteed valid` };
  if (ev.anyHit) return { confidence: 'likely', why: `served from cache (${ev.layers.filter((l) => l.hit).map((l) => l.layer).join(', ')}); the cache lifetime is not visible in the headers (LiteSpeed's default public TTL is 7 days)` };
  return null;
}

export default async function performance(run) {
  const { cfg } = run;
  const pc = cfg.performance;
  const local = cfg.site.environment === 'local';

  /* ---------------- Lighthouse ---------------- */
  await run.check({ id: 'performance.lighthouse', title: `Lighthouse lab test, mobile + desktop (first ${pc.pages} pages)`, category: CAT, tool: 'Lighthouse', requires: { url: true } }, async (c) => {
    let cli;
    try { cli = require.resolve('lighthouse/cli/index.js'); } catch { return c.skip('Lighthouse not installed', 'npm install lighthouse (in the toolkit folder)'); }
    let chromePath = process.env.CHROME_PATH || null;
    if (!chromePath) { try { chromePath = (await import('playwright')).chromium.executablePath(); } catch { /* let Lighthouse find Chrome */ } }
    const dir = run.artifactDir('lighthouse');
    const pages = (cfg.site.pages || ['/']).slice(0, pc.pages);
    const label = local ? 'lab, local — not production' : 'lab';
    const sev = local ? 'low' : 'medium';
    const rows = [];
    let failures = 0;
    const exec = run.lighthouse || (async (url, preset, out) => {
      const args = [cli, url, '--output=json', `--output-path=${out}`, '--quiet', '--only-categories=performance,accessibility,best-practices,seo', '--chrome-flags=--headless=new --no-first-run --disable-gpu', '--max-wait-for-load=60000'];
      if (preset === 'desktop') args.push('--preset=desktop');
      const r = await runCmd(process.execPath, args, { timeoutMs: 180000, env: chromePath ? { CHROME_PATH: chromePath } : {} });
      // On Windows Lighthouse often exits 1 with EPERM while deleting its temp profile, after writing the report.
      let lhr = null;
      try { lhr = JSON.parse(fs.readFileSync(out, 'utf8')); } catch { /* no report */ }
      return { lhr, r };
    });
    for (const p of pages) {
      const url = new URL(p, cfg.site.url + '/').href;
      c.scope([url]);
      for (const preset of ['mobile', 'desktop']) {
        const out = path.join(dir, `${p.replace(/[^a-z0-9]+/gi, '_') || 'home'}-${preset}.json`);
        const { lhr, r } = await exec(url, preset, out);
        if (!lhr) { failures++; c.note(`${preset} ${url}: no report (${truncate((r?.stderr || r?.stdout || 'unknown error').split('\n').filter(Boolean).pop() || '', 200)})`); continue; }
        const s = summarizeLighthouse(lhr);
        if (s.runtimeError) { failures++; c.note(`${preset} ${url}: Lighthouse runtime error ${s.runtimeError}`); continue; }
        c.artifact?.(out);
        rows.push({ url, preset, ...s });
        const over = [];
        if (s.lcpMs != null && s.lcpMs > pc.lcpMs) over.push(`LCP ${(s.lcpMs / 1000).toFixed(1)} s > ${(pc.lcpMs / 1000).toFixed(1)} s`);
        if (s.cls != null && s.cls > pc.cls) over.push(`CLS ${s.cls.toFixed(3)} > ${pc.cls}`);
        if (s.tbtMs != null && s.tbtMs > pc.tbtMs) over.push(`TBT ${Math.round(s.tbtMs)} ms > ${pc.tbtMs} ms`);
        if (over.length) c.finding({ severity: sev, rule: 'lighthouse.metrics', title: `${preset}: ${over.join(', ')} (${label})`, url, fingerprintExtra: `${preset}`, message: s.opportunities.length ? `Top opportunities: ${s.opportunities.map((o) => `${o.title}${o.savingsMs ? ` (~${o.savingsMs} ms)` : o.savingsKb ? ` (~${o.savingsKb} KB)` : ''}`).join(' · ')}` : null, recommendation: 'Start with the listed opportunities. Lab numbers on a local machine differ from real visitors; confirm on production (PageSpeed Insights / CrUX).' });
      }
    }
    c.stats = { runs: rows.length, failures };
    if (!rows.length) return c.skip(`Lighthouse produced no report (${failures} run(s) failed)`, 'Check that Chromium is installed (npx playwright install chromium) and the site loads in a browser.');
    if (failures) c.note(`${failures} Lighthouse run(s) failed — those pages/presets are not tested`);
    const L = [`Scores are Lighthouse's own output (${label}; Lighthouse ${rows[0].version}). Thresholds: LCP ${pc.lcpMs} ms, CLS ${pc.cls}, TBT ${pc.tbtMs} ms.`, '', '| Page | Device | Perf | A11y | Best pr. | SEO | LCP | CLS | TBT |', '|---|---|---:|---:|---:|---:|---:|---:|---:|'];
    for (const r of rows) L.push(`| ${new URL(r.url).pathname} | ${r.preset} | ${r.scores.performance ?? '—'} | ${r.scores.accessibility ?? '—'} | ${r.scores['best-practices'] ?? '—'} | ${r.scores.seo ?? '—'} | ${r.lcpMs != null ? (r.lcpMs / 1000).toFixed(1) + ' s' : '—'} | ${r.cls != null ? r.cls.toFixed(3) : '—'} | ${r.tbtMs != null ? Math.round(r.tbtMs) + ' ms' : '—'} |`);
    const opp = new Map();
    for (const r of rows) for (const o of r.opportunities) { const x = opp.get(o.id) || { ...o, pages: 0 }; x.pages++; x.savingsMs = Math.max(x.savingsMs, o.savingsMs); opp.set(o.id, x); }
    if (opp.size) { L.push('', 'Top opportunities (all runs):'); for (const o of [...opp.values()].sort((a, b) => b.savingsMs - a.savingsMs).slice(0, 5)) L.push(`- ${o.title} — up to ~${o.savingsMs} ms${o.savingsKb ? `, ${o.savingsKb} KB` : ''} (${o.pages} run(s))`); }
    run.sections.push({ id: 'lighthouse', title: 'Lighthouse (lab)', lines: L, data: rows });
  });

  /* ---------------- caching + compression ---------------- */
  await run.check({ id: 'performance.caching', title: 'Page cache, browser caching and compression headers', category: CAT, tool: 'HTTP headers' }, async (c) => {
    const { targets, finish } = await reachableTargets(run);
    let pagesChecked = 0;
    for (const t of targets) {
      const sev = t.production ? 'medium' : 'low';
      const summary = [];
      let homeHtml = null;
      for (const p of t.pages.slice(0, 5)) {
        const url = pageUrl(t, p);
        const r = await getPage(run, url);
        if (!r.ok || r.status >= 400) { c.note(`${t.label}: ${url} → ${r.ok ? `HTTP ${r.status}` : r.error}`); continue; }
        pagesChecked++;
        c.scope([url]);
        if (!homeHtml) homeHtml = { html: r.text, url: r.url || url };
        const ev = cacheEvidence(r.headers);
        summary.push(`${new URL(url).pathname}: ${ev.layers.length ? ev.layers.map((l) => `${l.layer} ${l.status}`).join(', ') : 'no cache headers'}${ev.ageSec != null ? `, copy ${(ev.ageSec / 3600).toFixed(1)} h old` : ''}`);
        if (!r.headers['content-encoding'] && (r.text || '').length > 2048) c.finding({ severity: sev, rule: 'cache.compression', title: `${t.label}: HTML sent uncompressed`, url, fingerprintExtra: `html-compression:${t.base}`, aggregate: true, recommendation: 'Enable gzip or Brotli on the web server / CDN.' });
      }
      if (!summary.length) continue;
      const anyCache = summary.some((s) => !/no cache headers/.test(s));
      c.note(`${t.label} — page cache: ${summary.join(' · ')}`);
      if (!anyCache) c.note(`${t.label}: no page-cache headers seen — insufficient evidence, not proof that caching is off (many caches don't announce themselves)`);
      // Static assets: browser caching and compression.
      for (const a of homeHtml ? assetUrls(homeHtml.html, homeHtml.url) : []) {
        const r = await run.http(a.url, { timeoutMs: 20000, redirect: 'follow', readBody: a.type !== 'image', headers: { 'accept-encoding': 'gzip, deflate, br' } });
        if (!r.ok || r.status >= 400) continue;
        c.scope([a.url]);
        const ev = cacheEvidence(r.headers);
        const ttl = ev.maxAge ?? (ev.expires ? Math.round((Date.parse(ev.expires) - Date.now()) / 1000) : null);
        if (ttl == null || ttl < 7 * 86400) c.finding({ severity: 'low', rule: 'cache.static-ttl', title: `${t.label}: ${a.type.toUpperCase()} cached ${ttl == null ? 'without a browser cache lifetime' : `only ${Math.max(0, Math.round(ttl / 3600))} h`}`, url: a.url, fingerprintExtra: `static-ttl:${t.base}:${a.type}`, aggregate: true, message: ev.cacheControl ? `Cache-Control: ${ev.cacheControl}` : 'no Cache-Control / Expires', recommendation: 'Versioned static files (?ver=) can be cached for a year: Cache-Control: public, max-age=31536000, immutable.' });
        if (a.type !== 'image' && !r.headers['content-encoding'] && (r.text || '').length > 2048) c.finding({ severity: sev, rule: 'cache.compression', title: `${t.label}: ${a.type.toUpperCase()} sent uncompressed`, url: a.url, fingerprintExtra: `asset-compression:${t.base}:${a.type}`, aggregate: true, recommendation: 'Enable gzip or Brotli for text assets.' });
      }
    }
    if (!pagesChecked) return targets.length ? c.skip('no page could be fetched') : finish(c);
    c.stats = { pages: pagesChecked };
    finish(c);
  });

  /* ---------------- nonce in cached HTML ---------------- */
  await run.check({ id: 'performance.cached-nonce', title: 'Nonces in public HTML cached longer than the nonce lifetime', category: CAT, tool: 'HTTP headers' }, async (c) => {
    const { targets, finish } = await reachableTargets(run);
    const life = pc.nonceLifetimeSec;
    let pagesChecked = 0, withNonce = 0;
    for (const t of targets) {
      for (const p of t.pages) {
        const url = pageUrl(t, p);
        const r = await getPage(run, url);
        if (!r.ok || r.status >= 400) continue;
        pagesChecked++;
        c.scope([url]);
        const markers = nonceMarkers(r.text);
        if (!markers.length) continue;
        withNonce++;
        const ev = cacheEvidence(r.headers);
        const risk = cachedNonceRisk(ev, life);
        if (!risk) { c.note(`${url}: nonce in HTML (${markers.join(', ')}), no shared-cache evidence`); continue; }
        c.finding({
          severity: 'medium', confidence: risk.confidence, rule: 'cache.nonce', url,
          title: `${t.label}: page with a nonce (${markers.join(', ')}) is ${risk.confidence === 'confirmed' ? 'served from a cache older than' : 'cached and may outlive'} the nonce lifetime`,
          fingerprintExtra: `${new URL(url).pathname}:${markers.join('|')}`,
          message: `${risk.why}. Headers: ${[ev.layers.map((l) => `${l.layer}: ${l.status}`).join(', '), ev.cacheControl && `Cache-Control: ${ev.cacheControl}`].filter(Boolean).join('; ')}. The nonce value is not shown.`,
          recommendation: 'Visitors can get an expired nonce, so the form/action fails ("link expired", 403) until the cache refreshes. Fetch the nonce at runtime instead (a small uncached REST/AJAX request, or LiteSpeed ESI for that block), exclude the page from the page cache, or set the page cache TTL below 12 h. For logged-out visitors, consider whether a nonce is needed at all (it does not identify them; use a honeypot/rate limit instead).',
        });
      }
    }
    c.stats = { pages: pagesChecked, pagesWithNonce: withNonce };
    if (!pagesChecked) return targets.length ? c.skip('no page could be fetched') : finish(c);
    if (!withNonce) c.note(`no nonce found in the HTML of ${pagesChecked} page(s)`);
    finish(c);
  });
}
