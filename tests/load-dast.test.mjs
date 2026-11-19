// M5: k6 load tests and OWASP ZAP. Both must refuse without --approve, on a host that is not allowlisted, on
// production (host, www/apex, shared IP, environment), and on bad config. ZAP without Docker is "not run".
// One real k6 smoke run (2 VUs, 3 s) against a throwaway server on 127.0.0.1 — skipped if k6 is not installed.
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import path from 'node:path';
import scalability, { durationSec, buildProfile, k6Script, readSummary } from '../modules/scalability.mjs';
import dast, { pinnedImage, parseZapReport } from '../modules/dast.mjs';
import { makeRun, tempDir, TESTS_DIR } from './helpers.mjs';
import { IS_WIN, exists } from '../lib/util.mjs';

const BIN = path.join(TESTS_DIR, "..", "bin", "wpqa.mjs");
const LIMITS = { maxVus: 50, maxDurationSec: 600 };

function gatedRun({ mode = 'scalability', site = { url: 'http://sandbox.local', environment: 'local' }, publicSite = { url: 'https://shop.example' }, allowed = ['sandbox.local'], flags = {}, config = {}, ips = { 'sandbox.local': ['127.0.0.1'], 'shop.example': ['203.0.113.10'], 'www.shop.example': ['203.0.113.10'] } }) {
  const run = makeRun({ config: { site, publicSite, safety: { allowedHosts: allowed }, ...config }, mode, flags });
  run.siteReachable = async () => ({ ok: true, status: 200 });
  run.resolve = async (h) => ips[h] || [];
  run.wpEnvironmentType = async () => null;
  run.k6 = async () => { throw new Error('k6 must not run in a refusal test'); };
  run.exec = async () => { throw new Error('docker must not run in a refusal test'); };
  run.tool = async (n) => ({ ok: n !== 'docker', name: n, version: 'x' });
  return run;
}
const reasonOf = (run, id) => run.checks.find((c) => c.id === id);

/* ---------------- helpers ---------------- */

describe('k6 + ZAP helpers', () => {
  test('durations', () => { assert.equal(durationSec('2m'), 120); assert.equal(durationSec('30s'), 30); assert.equal(durationSec(45), 45); assert.equal(durationSec('soon'), null); });
  test('profiles never exceed the limits; stress is marked', () => {
    const load = { vus: 80, duration: '20m', rampUp: '30s', smokeVus: 2, smokeDuration: '30s', stressStep: '1m' };
    assert.equal(buildProfile('load', load, LIMITS).vus, 50);
    assert.equal(buildProfile('smoke', load, LIMITS).vus, 2);
    assert.equal(buildProfile('stress', load, LIMITS).stress, true);
    assert.equal(buildProfile('stress', load, LIMITS).durationSec, 270);
    assert.equal(buildProfile('chaos', load, LIMITS), null);
  });
  test('k6 script is GET only with p95 and error-rate thresholds', () => {
    const s = k6Script({ urls: ['http://x/'], stages: [{ duration: '5s', target: 1 }], p95Ms: 1500, errorRate: 0.01, summaryPath: 'C:/tmp/s.json', insecure: true });
    assert.match(s, /http\.get\(/);
    assert.doesNotMatch(s, /http\.(post|put|patch|del|request)\(/);
    assert.match(s, /p\(95\)<1500/);
    assert.match(s, /rate<0\.01/);
  });
  test('k6 summary reading', () => {
    const r = readSummary({ metrics: { http_req_duration: { values: { 'p(95)': 900, avg: 300 }, thresholds: { 'p(95)<800': { ok: false } } }, http_req_failed: { values: { rate: 0 }, thresholds: { 'rate<0.01': { ok: true } } }, http_reqs: { values: { count: 100, rate: 10 } } } });
    assert.equal(r.p95Ok, false);
    assert.equal(r.errorsOk, true);
  });
  test('ZAP image must be pinned', () => {
    assert.ok(pinnedImage('ghcr.io/zaproxy/zaproxy:2.16.1'));
    assert.ok(pinnedImage('ghcr.io/zaproxy/zaproxy@sha256:' + 'a'.repeat(64)));
    for (const t of ['ghcr.io/zaproxy/zaproxy:stable', 'ghcr.io/zaproxy/zaproxy:latest', 'ghcr.io/zaproxy/zaproxy:weekly', 'ghcr.io/zaproxy/zaproxy']) assert.ok(!pinnedImage(t), t);
  });
  test('ZAP report parsing', () => {
    const { alerts } = parseZapReport({ site: [{ alerts: [{ pluginid: '10038', alertRef: '10038', name: 'CSP header not set', riskcode: '2', count: '3', instances: [{ uri: 'http://x/' }], cweid: '693' }] }] });
    assert.deepEqual([alerts[0].risk, alerts[0].count, alerts[0].pluginId, alerts[0].key], ['medium', 3, '10038', '10038']);
  });
});

/* ---------------- ZAP results (the run on test.local exposed these) ---------------- */

// Shape of a real ZAP 2.16.1 baseline report: one plugin (10055) raises four distinct CSP alerts, 10049 three
// cache alerts; 10116 is ZAP talking about itself.
const alert = (pluginid, alertRef, name, riskcode, uris) => ({ pluginid, alertRef, name, alert: name, riskcode: String(riskcode), count: String(uris.length), instances: uris.map((uri) => ({ uri })), solution: '<p>fix</p>', cweid: '693' });
const ZAP_JSON = {
  '@version': '2.16.1',
  site: [{ '@name': 'http://sandbox.local', alerts: [
    alert('10055', '10055-13', 'CSP: Failure to Define Directive with No Fallback', 2, ['http://sandbox.local/']),
    alert('10055', '10055-4', 'CSP: Wildcard Directive', 2, ['http://sandbox.local/']),
    alert('10055', '10055-5', 'CSP: script-src unsafe-inline', 2, ['http://sandbox.local/']),
    alert('10055', '10055-6', 'CSP: style-src unsafe-inline', 2, ['http://sandbox.local/']),
    alert('10049', '10049-1', 'Non-Storable Content', 0, ['http://sandbox.local/wp-login.php']),
    alert('10049', '10049-2', 'Storable but Non-Cacheable Content', 0, ['http://sandbox.local/']),
    alert('10049', '10049-3', 'Storable and Cacheable Content', 0, ['http://sandbox.local/sample-page/', 'http://sandbox.local/feed/']),
    alert('10116', '10116', 'ZAP is Out of Date', 1, ['http://sandbox.local']),
  ] }],
};

describe('ZAP baseline results are reported completely', () => {
  const zapRun = async (json) => {
    const run = gatedRun({ mode: 'dast', flags: { approve: true } });
    run.tool = async (n) => ({ ok: true, name: n, version: 'x' });
    run.exec = async (cmd, args) => {
      const mount = args[args.indexOf('-v') + 1];
      const dir = mount.slice(0, mount.lastIndexOf(':/zap/wrk'));
      if (json) fs.writeFileSync(path.join(dir, 'zap.json'), JSON.stringify(json));
      return { code: json ? 2 : 1, stdout: '', stderr: json ? '' : 'container failed' };
    };
    await dast(run);
    run.finalizeFindings();
    return run;
  };
  test('every distinct alert is a finding — several alerts from one plugin are not merged', async () => {
    const run = await zapRun(ZAP_JSON);
    const titles = run.findings.map((f) => f.title.replace(/ \(\d+ instances?\)$/, ''));
    assert.equal(run.findings.length, 7);
    for (const n of ['CSP: Wildcard Directive', 'CSP: script-src unsafe-inline', 'CSP: style-src unsafe-inline', 'CSP: Failure to Define Directive with No Fallback']) assert.ok(titles.includes(n), n);
    const c = reasonOf(run, 'dast.zap-baseline');
    assert.equal(c.findingCount ?? run.findings.length, run.findings.length, 'check count and report totals agree');
  });
  test('"ZAP is Out of Date" is a note about the scanner, not a site finding', async () => {
    const run = await zapRun(ZAP_JSON);
    assert.ok(!run.findings.some((f) => f.rule === 'zap.10116'));
    assert.match(reasonOf(run, 'dast.zap-baseline').notes.join(' '), /ZAP about itself.*ZAP is Out of Date/);
  });
  test('URLs inspected = the URLs ZAP reported on', async () => {
    const run = await zapRun(ZAP_JSON);
    const c = reasonOf(run, 'dast.zap-baseline');
    assert.equal(c.stats.urls, 4);
    for (const u of ['http://sandbox.local/wp-login.php', 'http://sandbox.local/sample-page/', 'http://sandbox.local/feed/']) assert.ok(c.scope.includes(u), u);
  });
  test('no ZAP JSON produced → error (not run), never passed', async () => {
    const run = await zapRun(null);
    assert.equal(reasonOf(run, 'dast.zap-baseline').status, 'error');
  });
});

/* ---------------- refusals (both k6 and ZAP) ---------------- */

const CASES = [
  ['no --approve', {}, /needs explicit approval/],
  ['host not allowlisted', { flags: { approve: true }, allowed: [] }, /not in safety\.allowedHosts/],
  ['environment is production', { flags: { approve: true }, site: { url: 'http://sandbox.local', environment: 'production' } }, /production/],
  ['target is the public production host', { flags: { approve: true }, site: { url: 'https://shop.example', environment: 'staging' }, allowed: ['shop.example'] }, /production/],
  ['target is the www variant of production', { flags: { approve: true }, site: { url: 'https://www.shop.example', environment: 'staging' }, allowed: ['www.shop.example'] }, /production/],
  ['target resolves to the production IP', { flags: { approve: true }, ips: { 'sandbox.local': ['203.0.113.10'], 'shop.example': ['203.0.113.10'] } }, /same address as production|resolves to production|production IP|shares/i],
];

describe('k6 refuses', () => {
  for (const [name, o, re] of CASES) {
    test(name, async () => {
      const run = gatedRun({ ...o });
      await scalability(run);
      const c = reasonOf(run, 'scalability.k6');
      assert.equal(c.status, 'skipped');
      assert.match(c.reason, re);
    });
  }
  test('stress without safety.allowStress', async () => {
    const run = gatedRun({ flags: { approve: true, profile: 'stress' } });
    await scalability(run);
    assert.match(reasonOf(run, 'scalability.k6').reason, /allowStress/);
  });
  test('bad config: unknown profile, invalid duration', async () => {
    const r1 = gatedRun({ flags: { approve: true, profile: 'chaos' } });
    await scalability(r1);
    assert.match(reasonOf(r1, 'scalability.k6').reason, /unknown --profile/);
    const r2 = gatedRun({ flags: { approve: true }, config: { load: { duration: 'forever' } } });
    await scalability(r2);
    assert.equal(reasonOf(r2, 'scalability.k6').status, 'skipped');
    assert.match(reasonOf(r2, 'scalability.k6').reason, /invalid load duration/);
  });
});

describe('ZAP refuses or reports "not run"', () => {
  for (const [name, o, re] of CASES) {
    test(name, async () => {
      const run = gatedRun({ mode: 'dast', ...o });
      await dast(run);
      const c = reasonOf(run, 'dast.zap-baseline');
      assert.equal(c.status, 'skipped');
      assert.match(c.reason, re);
    });
  }
  test('approved and allowed, but Docker missing → skipped "ZAP did not run", never passed', async () => {
    const run = gatedRun({ mode: 'dast', flags: { approve: true } });
    await dast(run);
    const c = reasonOf(run, 'dast.zap-baseline');
    assert.equal(c.status, 'skipped');
    assert.match(c.reason, /Docker not available — ZAP did not run/);
  });
  test('unpinned image refused', async () => {
    const run = gatedRun({ mode: 'dast', flags: { approve: true }, config: { dast: { zapImage: 'ghcr.io/zaproxy/zaproxy:stable' } } });
    await dast(run);
    assert.match(reasonOf(run, 'dast.zap-baseline').reason, /not pinned/);
  });
  test('full (active) scan: N/A unless dast.active; refused without approval when enabled', async () => {
    const r1 = gatedRun({ mode: 'dast', flags: { approve: true } });
    await dast(r1);
    assert.equal(reasonOf(r1, 'dast.zap-full').status, 'not_applicable');
    const r2 = gatedRun({ mode: 'dast', config: { dast: { active: true } } });
    await dast(r2);
    assert.match(reasonOf(r2, 'dast.zap-full').reason, /needs explicit approval/);
  });
});

describe('CLI refusals', () => {
  test('--approve=yes is rejected (exit 2)', () => {
    const r = spawnSync(process.execPath, [BIN, 'scalability', '--approve=yes'], { cwd: tempDir(), encoding: 'utf8' });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /approve.*takes no value/);
  });
  test('missing config → exit 2', () => {
    const r = spawnSync(process.execPath, [BIN, 'scalability', '--approve'], { cwd: tempDir(), encoding: 'utf8' });
    assert.equal(r.status, 2);
    assert.match(r.stderr, /No wpqa\.config\.json/);
  });
});

/* ---------------- real k6 smoke run against a throwaway local server ---------------- */

describe('k6 smoke run (real k6, 127.0.0.1 throwaway server)', () => {
  let server, port, hits = 0, methods = new Set();
  const k6Path = (() => { const r = spawnSync('k6', ['version'], { encoding: 'utf8', shell: IS_WIN }); if (r.status === 0) return 'k6'; return IS_WIN && exists('C:\\Program Files\\k6\\k6.exe') ? 'C:\\Program Files\\k6\\k6.exe' : null; })();
  before(async () => {
    server = http.createServer((req, res) => { hits++; methods.add(req.method); res.writeHead(200, { 'content-type': 'text/html' }); res.end('<h1>ok</h1>'); });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    port = server.address().port;
  });
  after(() => server?.close());
  test('runs, stays GET-only, and reports p95 / error rate', async (t) => {
    if (!k6Path) return t.skip('k6 not installed');
    const run = makeRun({ config: { site: { url: `http://127.0.0.1:${port}`, environment: 'local', pages: ['/'] }, safety: { allowedHosts: ['127.0.0.1'] }, load: { smokeVus: 2, smokeDuration: '3s' }, tools: { k6: k6Path } }, mode: 'scalability', flags: { approve: true, profile: 'smoke' } });
    run.siteReachable = async () => ({ ok: true, status: 200 });
    run.wpEnvironmentType = async () => null;
    await scalability(run);
    const c = reasonOf(run, 'scalability.k6');
    assert.equal(c.status, 'passed', `${c.status}: ${c.reason || ''} ${c.notes.join(' ')}`);
    assert.ok(hits > 0);
    assert.deepEqual([...methods], ['GET']);
    assert.ok(c.stats.p95Ms != null && c.stats.errorRate === 0);
    assert.match(c.notes.join(' '), /not production capacity/);
    assert.equal(run.approvals[0].allowed, true);
  });
});
