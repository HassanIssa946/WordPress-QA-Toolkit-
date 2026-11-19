// Performance + SEO (M3): Lighthouse summary (recorded results), caching/compression headers, cached nonces,
// robots/sitemaps/page SEO. HTTP is served from fixtures; no browser or network.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import performance, { summarizeLighthouse, cachedNonceRisk } from '../modules/performance.mjs';
import seo, { parseRobots } from '../modules/seo.mjs';
import { pageFacts, nonceMarkers, cacheEvidence } from '../lib/html.mjs';
import { verdict } from '../lib/report.mjs';
import { MODES } from '../lib/modes.mjs';
import { makeRun, TESTS_DIR } from './helpers.mjs';

const fx = (n) => fs.readFileSync(path.join(TESTS_DIR, 'fixtures', 'http', n), 'utf8');
const BAD = fx('bad-page.html'), GOOD = fx('good-page.html');
const LH_SLOW = JSON.parse(fx('lighthouse-slow.json')), LH_FAST = JSON.parse(fx('lighthouse-fast.json'));
const NONCE_VALUES = ['0123456789', 'abcdef0123', 'fedcba9876'];
const html = (text, headers = {}) => ({ ok: true, status: 200, headers: { 'content-type': 'text/html; charset=UTF-8', ...headers }, text, url: null });

function fakeRun({ config, routes, lighthouse, reachable = true, mode = 'performance' }) {
  const run = makeRun({ config, mode });
  run.siteReachable = async () => (reachable ? { ok: true, status: 200 } : { ok: false, error: 'HTTP 502 from http://fixture.local (site or database down?)' });
  run.http = async (url) => {
    const r = routes[url] ?? routes[url.replace(/\/$/, '')];
    if (typeof r === 'function') return r(url);
    return r ? { ...r, url } : { ok: true, status: 404, headers: {}, text: 'not found', url };
  };
  run.lighthouse = async (url, preset) => ({ lhr: typeof lighthouse === 'function' ? lighthouse(url, preset) : lighthouse, r: null });
  return run;
}

/* ---------------- helpers ---------------- */

describe('html helpers', () => {
  test('page facts from the bad fixture', () => {
    const f = pageFacts(BAD);
    assert.equal(f.title, null);
    assert.equal(f.h1, 2);
    assert.equal(f.lang, null);
    assert.ok(f.noindex);
    assert.equal(f.jsonLd[0].ok, false);
    assert.equal(f.hreflang[0].lang, 'english');
  });
  test('X-Robots-Tag header counts as noindex', () => assert.ok(pageFacts(GOOD, { 'x-robots-tag': 'noindex' }).noindex));
  test('nonce markers name the field, never the value', () => {
    const m = nonceMarkers(BAD);
    assert.equal(m.length, 3);
    for (const v of NONCE_VALUES) assert.ok(!m.join(' ').includes(v));
    assert.deepEqual(nonceMarkers(GOOD), []);
  });
  test('cache evidence: LiteSpeed ETag timestamp and Age give the copy\'s age', () => {
    const now = Date.parse('2026-11-19T12:00:00Z');
    const ev = cacheEvidence({ 'x-litespeed-cache': 'hit', etag: `"251-${Math.round(now / 1000) - 60000};br"`, age: '100', 'x-hcdn-cache-status': 'HIT' }, now);
    assert.equal(ev.ageSec, 60000);
    assert.equal(ev.ageFrom, 'LiteSpeed ETag timestamp');
    assert.equal(ev.layers.length, 2);
  });
  test('cached nonce risk: confirmed / likely / none', () => {
    assert.equal(cachedNonceRisk({ anyHit: true, ageSec: 50000, layers: [{ layer: 'LiteSpeed', hit: true }] }).confidence, 'confirmed');
    assert.equal(cachedNonceRisk({ anyHit: true, ageSec: 600, layers: [{ layer: 'LiteSpeed', hit: true }] }).confidence, 'likely');
    assert.equal(cachedNonceRisk({ anyHit: false, maxAge: 86400 * 7, layers: [] }).confidence, 'likely');
    assert.equal(cachedNonceRisk({ anyHit: false, maxAge: 600, layers: [] }), null);
    assert.equal(cachedNonceRisk({ anyHit: false, maxAge: 86400 * 7, noStore: true, layers: [] }), null);
  });
  test('robots.txt parsing', () => {
    assert.deepEqual(parseRobots('User-agent: *\nDisallow: /\nSitemap: https://x/s.xml'), { blocksAll: true, sitemaps: ['https://x/s.xml'] });
    assert.equal(parseRobots('User-agent: Googlebot\nDisallow: /\n\nUser-agent: *\nDisallow: /wp-admin/').blocksAll, false);
  });
  test('Lighthouse summary: scores as reported, metrics and top opportunities', () => {
    const s = summarizeLighthouse(LH_SLOW);
    assert.equal(s.scores.performance, 42);
    assert.equal(s.lcpMs, 6200);
    assert.deepEqual(s.opportunities.map((o) => o.id), ['render-blocking-resources', 'unused-javascript']);
  });
});

/* ---------------- must detect ---------------- */

describe('M3 — fixture that must be flagged (local + production)', async () => {
  const now = Math.round(Date.now() / 1000);
  const run = fakeRun({
    config: { site: { url: 'http://fixture.local', environment: 'local', pages: ['/'] }, publicSite: { url: 'https://shop.example' } },
    lighthouse: LH_SLOW,
    routes: {
      'http://fixture.local/': html(BAD),
      'https://shop.example/': html(BAD, { 'x-litespeed-cache': 'hit', etag: `"251-${now - 50000};br"`, 'x-hcdn-cache-status': 'HIT', age: '49000', 'content-encoding': 'br' }),
      'http://fixture.local/robots.txt': { ok: true, status: 200, headers: {}, text: 'User-agent: *\nDisallow: /\n' },
      'https://shop.example/robots.txt': { ok: true, status: 200, headers: {}, text: 'User-agent: *\nDisallow: /\n' },
    },
  });
  await performance(run);
  await seo(run);
  run.finalizeFindings();
  const f = (rule, label) => run.findings.filter((x) => x.rule === rule && (!label || x.title.startsWith(label)));

  test('Lighthouse: metrics over thresholds, labelled lab/local, low on a local site', () => {
    const l = f('lighthouse.metrics');
    assert.equal(l.length, 2, 'mobile + desktop');
    assert.ok(l.every((x) => x.severity === 'low' && /lab, local — not production/.test(x.title) && /LCP 6\.2 s/.test(x.title)));
    assert.match(l[0].message, /Eliminate render-blocking resources/);
    assert.ok(run.sections.find((s) => s.id === 'lighthouse'));
  });
  test('cached nonce on production: confirmed, medium, no nonce values anywhere', () => {
    const n = f('cache.nonce');
    assert.equal(n.length, 1);
    assert.equal(n[0].confidence, 'confirmed');
    assert.equal(n[0].severity, 'medium');
    assert.match(n[0].title, /^production/);
    const everything = JSON.stringify({ findings: run.findings, checks: run.checks });
    for (const v of NONCE_VALUES) assert.ok(!everything.includes(v), `nonce value ${v} leaked`);
  });
  test('noindex: high on production, info on the local copy', () => {
    assert.equal(f('seo.noindex', 'production')[0].severity, 'high');
    assert.equal(f('seo.noindex', 'local')[0].severity, 'info');
  });
  test('robots.txt blocking everything: critical on production only', () => {
    assert.equal(f('seo.robots-blocks-all', 'production')[0].severity, 'critical');
    assert.equal(f('seo.robots-blocks-all', 'local')[0].severity, 'info');
  });
  test('page SEO rules', () => {
    for (const rule of ['seo.title-missing', 'seo.description-missing', 'seo.canonical-host', 'seo.h1', 'seo.lang', 'seo.hreflang-invalid', 'seo.jsonld-invalid', 'seo.sitemap-missing']) assert.ok(f(rule).length, rule);
    assert.equal(f('seo.canonical-host', 'production')[0].severity, 'high');
  });
  test('every check ran', () => {
    for (const c of run.checks) assert.ok(['passed', 'failed'].includes(c.status), `${c.id}: ${c.status} ${c.reason || ''}`);
  });
});

/* ---------------- clean ---------------- */

describe('M3 — clean fixture has zero findings', async () => {
  const run = fakeRun({
    config: { site: { url: 'http://fixture.local', environment: 'local', pages: ['/'] } },
    lighthouse: LH_FAST,
    routes: {
      'http://fixture.local/': html(GOOD, { 'content-encoding': 'gzip' }),
      'http://fixture.local/robots.txt': { ok: true, status: 200, headers: {}, text: 'User-agent: *\nDisallow: /wp-admin/\nSitemap: http://fixture.local/wp-sitemap.xml\n' },
      'http://fixture.local/wp-sitemap.xml': { ok: true, status: 200, headers: {}, text: '<?xml version="1.0"?><urlset><url><loc>http://fixture.local/</loc></url></urlset>' },
      'http://fixture.local/wp-content/themes/t/style.css?ver=1.0': { ok: true, status: 200, headers: { 'cache-control': 'public, max-age=31536000, immutable', 'content-encoding': 'gzip' }, text: 'body{}' },
    },
  });
  await performance(run);
  await seo(run);
  run.finalizeFindings();
  test('no findings (info included)', () => assert.deepEqual(run.findings.map((x) => `${x.rule}: ${x.title}`), []));
  test('all checks passed', () => {
    for (const c of run.checks) assert.equal(c.status, 'passed', `${c.id}: ${c.reason || ''}`);
  });
  test('no cache headers on the local site is a note ("insufficient evidence"), not a finding', () => {
    assert.match(run.checks.find((c) => c.id === 'performance.caching').notes.join(' '), /insufficient evidence/);
  });
});

/* ---------------- site down ---------------- */

describe('unavailable site → INCOMPLETE, never PASS', async () => {
  const run = fakeRun({ config: { site: { url: 'http://fixture.local', environment: 'local' } }, routes: {}, lighthouse: LH_FAST, reachable: false, mode: 'performance' });
  await performance(run);
  await seo(run);
  test('every check is skipped with the reason', () => {
    for (const c of run.checks) { assert.equal(c.status, 'skipped', c.id); assert.match(c.reason, /HTTP 502/); }
  });
  test('verdict is INCOMPLETE for performance and seo modes', () => {
    for (const mode of ['performance', 'seo']) {
      const v = verdict([], 'high', { checks: run.checks, core: MODES[mode].core, minCoverage: 80 });
      assert.equal(v.status, 'INCOMPLETE', mode);
    }
  });
  test('Lighthouse with no report is skipped, not passed', async () => {
    const r2 = fakeRun({ config: {}, routes: {}, lighthouse: null });
    await performance(r2);
    assert.equal(r2.checks.find((c) => c.id === 'performance.lighthouse').status, 'skipped');
  });
});

describe('local site down, public production site up', async () => {
  const now = Math.round(Date.now() / 1000);
  const run = fakeRun({
    config: { site: { url: 'http://fixture.local', environment: 'local', pages: ['/'] }, publicSite: { url: 'https://shop.example' } },
    reachable: false,
    lighthouse: LH_FAST,
    routes: { 'https://shop.example/': html(BAD, { 'x-litespeed-cache': 'hit', etag: `"251-${now - 50000};br"`, 'content-encoding': 'br' }) },
  });
  await performance(run);
  test('production cached nonce is still reported', () => assert.ok(run.findings.some((f) => f.rule === 'cache.nonce' && f.confidence === 'confirmed')));
  test('but the check is skipped, so the verdict cannot be PASS', () => {
    const c = run.checks.find((x) => x.id === 'performance.cached-nonce');
    assert.equal(c.status, 'skipped');
    assert.match(c.reason, /only the public production site was checked/);
  });
});
