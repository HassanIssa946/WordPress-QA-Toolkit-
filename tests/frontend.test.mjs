// Frontend (M1): real Chromium (Playwright) + axe against a local fixture server. Also: link safety, visual
// regression with baselines, e2e specs, and the approval gate / cleanup of the block-editor test.
// If Chromium cannot start, the browser tests are reported as skipped (never as passed).
import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import frontend, { sampleAttributes, lostAttributes, UNSAFE_LINK, editorBlocks, slugOf } from '../modules/frontend.mjs';
import { makeRun, TESTS_DIR, tempDir } from './helpers.mjs';

const FX = path.join(TESTS_DIR, 'fixtures', 'frontend');
let server, base, chromiumOk = true, chromiumWhy = '';
const requested = [];
let homeVariant = 'good';

before(async () => {
  try { const { chromium } = await import('playwright'); const b = await chromium.launch(); await b.close(); } catch (e) { chromiumOk = false; chromiumWhy = e.message.split('\n')[0]; }
  server = http.createServer((req, res) => {
    requested.push(req.url);
    const send = (code, body, type = 'text/html') => { res.writeHead(code, { 'content-type': type }); res.end(body); };
    if (req.url === '/') return send(200, fs.readFileSync(path.join(FX, `${homeVariant}.html`)));
    if (req.url === '/bad/') return send(200, fs.readFileSync(path.join(FX, 'bad.html')));
    if (req.url === '/about/') return send(200, fs.readFileSync(path.join(FX, 'good.html')));
    if (req.url === '/pixel.png') return send(200, fs.readFileSync(path.join(FX, 'pixel.png')), 'image/png');
    return send(404, 'not found', 'text/plain');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server?.close());

function feRun({ pages = ['/'], config = {}, flags = {}, root } = {}) {
  const run = makeRun({ config: { site: { url: base, environment: 'local', pages }, scan: { plugins: [] }, frontend: { viewports: ['desktop', 'mobile'] }, ...config }, mode: 'frontend', flags });
  if (root) run.cfg._root = root;
  run.wpEnvironmentType = async () => null;
  return run;
}
const browserTest = (name, fn) => test(name, async (t) => { if (!chromiumOk) return t.skip(`Chromium not available: ${chromiumWhy}`); await fn(t); });

/* ---------------- pure helpers ---------------- */

describe('frontend helpers', () => {
  test('unsafe links are never requested', () => {
    for (const u of ['/wp-login.php?action=logout&_wpnonce=1', '/wp-admin/', '/?add-to-cart=5', '/cart/', '/checkout/', '/x?_wpnonce=1', '/?action=delete', '/my-account/customer-logout/']) assert.ok(UNSAFE_LINK.test(u), u);
    for (const u of ['/about/', '/blog/cartography/', '/shop/']) assert.ok(!UNSAFE_LINK.test(u), u);
  });
  test('sample attributes from block.json schema; lost attributes detected', () => {
    const a = sampleAttributes({ title: { type: 'string' }, count: { type: 'number' }, wide: { type: 'boolean', default: false }, size: { type: 'string', enum: ['s', 'm', 'l'] }, content: { type: 'string', source: 'html', selector: 'p' } });
    assert.deepEqual(a, { title: 'wpqa-test', count: 7, wide: true, size: 'l' });
    assert.deepEqual(lostAttributes(a, { title: 'wpqa-test', count: 7, wide: false, size: 'l' }), ['wide']);
  });
  test('custom blocks for the editor test come from block.json', () => {
    const run = makeRun({ config: { scan: { plugins: ['safe-plugin'] } } });
    assert.ok(editorBlocks(run.customDirs).some((b) => b.name === 'safe-fixture/card'));
  });
});

/* ---------------- must detect ---------------- */

describe('M1 — fixture page that must be flagged', () => {
  let run;
  before(async () => { if (!chromiumOk) return; requested.length = 0; run = feRun({ pages: ['/bad/'] }); await frontend(run); run.finalizeFindings(); });
  const has = (rule) => run.findings.filter((f) => f.rule === rule);
  browserTest('page health rules', () => {
    for (const r of ['page.js-error', 'page.failed-request', 'page.overflow', 'page.img-alt', 'page.img-dimensions', 'page.form-label', 'page.form-nonce']) assert.ok(has(r).length, r);
    assert.equal(has('page.overflow').find((f) => /^mobile/.test(f.title)).severity, 'medium');
  });
  browserTest('axe: critical → high, serious → medium', () => {
    const axe = run.findings.filter((f) => f.rule.startsWith('axe.'));
    assert.ok(axe.some((f) => f.rule === 'axe.image-alt' && f.severity === 'high'), axe.map((f) => `${f.rule}:${f.severity}`).join(', '));
    assert.ok(axe.some((f) => f.severity === 'medium'));
  });
  browserTest('broken internal link found; logout/login/cart links never requested', () => {
    assert.ok(has('link.broken').some((f) => f.url.endsWith('/missing-page/')));
    assert.ok(!requested.some((u) => /wp-login|logout|_wpnonce|\/cart\//.test(u)), requested.join(' '));
    assert.match(run.checks.find((c) => c.id === 'frontend.links').notes.join(' '), /not requested on purpose/);
  });
});

/* ---------------- clean ---------------- */

describe('M1 — clean fixture has zero findings', () => {
  let run;
  before(async () => { if (!chromiumOk) return; homeVariant = 'good'; run = feRun({ pages: ['/'] }); await frontend(run); run.finalizeFindings(); });
  browserTest('no findings', () => assert.deepEqual(run.findings.map((f) => `${f.rule}: ${f.title}`), []));
  browserTest('pages and links passed; visual skipped (no baseline yet), editor N/A (no custom blocks), e2e N/A', () => {
    const st = Object.fromEntries(run.checks.map((c) => [c.id, c.status]));
    assert.equal(st['frontend.pages'], 'passed');
    assert.equal(st['frontend.links'], 'passed');
    assert.equal(st['frontend.visual'], 'skipped');
    assert.equal(st['frontend.block-editor'], 'not_applicable');
    assert.equal(st['frontend.e2e'], 'not_applicable');
  });
});

/* ---------------- visual regression + e2e ---------------- */

describe('visual regression and e2e specs', () => {
  browserTest('approved baseline → identical page passes, changed page is flagged; baselines never auto-updated', async () => {
    const root = tempDir();
    homeVariant = 'good';
    const r1 = feRun({ pages: ['/'], root, config: { frontend: { viewports: ['desktop'] } } });
    await frontend(r1);
    const shot = r1.checks.find((c) => c.id === 'frontend.visual').artifacts.find((a) => /desktop/.test(a.label));
    assert.ok(shot, 'screenshot taken');
    assert.ok(!fs.existsSync(path.join(root, 'wpqa-tests', 'baselines')), 'no baseline written automatically');
    // Approve (what `wpqa baselines update --confirm` does).
    const src = path.join(r1.outDir, 'artifacts', 'visual', 'desktop', `${slugOf('/')}.png`);
    fs.mkdirSync(path.join(root, 'wpqa-tests', 'baselines', 'desktop'), { recursive: true });
    fs.copyFileSync(src, path.join(root, 'wpqa-tests', 'baselines', 'desktop', 'home.png'));
    const r2 = feRun({ pages: ['/'], root, config: { frontend: { viewports: ['desktop'] } } });
    await frontend(r2);
    assert.equal(r2.checks.find((c) => c.id === 'frontend.visual').status, 'passed');
    homeVariant = 'bad';
    const r3 = feRun({ pages: ['/'], root, config: { frontend: { viewports: ['desktop'] } } });
    await frontend(r3);
    homeVariant = 'good';
    assert.ok(r3.findings.some((f) => f.rule === 'visual.diff' || f.rule === 'visual.size'));
  });
  browserTest('e2e specs: passing and failing tests reported', async () => {
    const root = tempDir();
    fs.mkdirSync(path.join(root, 'wpqa-tests', 'e2e'), { recursive: true });
    fs.writeFileSync(path.join(root, 'wpqa-tests', 'e2e', 'home.spec.mjs'), `export default [
  { name: 'has h1', run: async ({ page, baseURL, assert }) => { await page.goto(baseURL + '/'); assert.equal(await page.locator('h1').count(), 1); } },
  { name: 'has pricing table', run: async ({ page, baseURL }) => { await page.goto(baseURL + '/'); await page.locator('#pricing').waitFor({ timeout: 1000 }); } },
];\n`);
    const run = feRun({ pages: ['/'], root, config: { frontend: { viewports: ['desktop'], visualRegression: false } } });
    await frontend(run);
    const c = run.checks.find((x) => x.id === 'frontend.e2e');
    assert.equal(c.status, 'failed');
    assert.deepEqual([c.stats.passed, c.stats.failed], [1, 1]);
    assert.match(run.findings.find((f) => f.rule === 'e2e.failed').title, /has pricing table/);
  });
});

/* ---------------- block editor gate + cleanup ---------------- */

describe('block editor test: approval gate, credentials, cleanup', () => {
  const editorRun = (flags, allowed = ['127.0.0.1']) => {
    const run = feRun({ pages: ['/'], flags, config: { scan: { plugins: ['safe-plugin'] }, safety: { allowedHosts: allowed }, frontend: { viewports: ['desktop'], visualRegression: false } } });
    run.siteReachable = async () => ({ ok: true, status: 200 });
    run.browserFactory = async () => ({ newContext: async () => ({ newPage: async () => ({}), close: async () => {} }), newPage: async () => ({ close: async () => {} }), close: async () => {} });
    return run;
  };
  const only = { only: ['frontend.block-editor'] };
  test('no --approve → skipped and listed as waiting for approval', async () => {
    const run = editorRun({ ...only });
    await frontend(run);
    const c = run.checks.find((x) => x.id === 'frontend.block-editor');
    assert.equal(c.status, 'skipped');
    assert.match(c.reason, /needs explicit approval/);
    assert.equal(run.needsApproval[0].kind, 'editor-drafts');
  });
  test('host not allowlisted → refused even with --approve', async () => {
    const run = editorRun({ ...only, approve: true }, []);
    await frontend(run);
    assert.match(run.checks.find((x) => x.id === 'frontend.block-editor').reason, /blocked: .*not in safety\.allowedHosts/);
  });
  test('approved but no credentials → skipped, nothing attempted', async () => {
    const saved = [process.env.WPQA_WP_USER, process.env.WPQA_WP_PASS];
    delete process.env.WPQA_WP_USER; delete process.env.WPQA_WP_PASS;
    try {
      const run = editorRun({ ...only, approve: true });
      let called = false;
      run.editorRoundTrip = async () => { called = true; return {}; };
      await frontend(run);
      assert.match(run.checks.find((x) => x.id === 'frontend.block-editor').reason, /credentials not set/);
      assert.equal(called, false);
    } finally { if (saved[0] !== undefined) process.env.WPQA_WP_USER = saved[0]; if (saved[1] !== undefined) process.env.WPQA_WP_PASS = saved[1]; }
  });
  test('round-trip problems and a leftover draft are high findings; credentials never in the report', async () => {
    process.env.WPQA_WP_USER = 'fixture-user'; process.env.WPQA_WP_PASS = 'fixture-secret-pass';
    try {
      const run = editorRun({ ...only, approve: true });
      run.editorRoundTrip = async ({ blocks }) => ({ postId: 42, leftover: 42, error: null, steps: ['login', 'editor', 'insert', 'save', 'reload', 'preview'], cleanup: { deleted: false, log: ['DELETE: HTTP 403 rest_cannot_delete'] }, blocks: blocks.map((b) => ({ ...b, registered: true, invalid: true, lost: ['title'], renderError: null })) });
      await frontend(run);
      const rules = run.findings.map((f) => `${f.rule}:${f.severity}`);
      for (const r of ['editor.invalid:high', 'editor.attributes-lost:high', 'editor.leftover-draft:high']) assert.ok(rules.includes(r), r);
      assert.match(run.findings.find((f) => f.rule === 'editor.leftover-draft').message, /Cleanup attempts: DELETE: HTTP 403 rest_cannot_delete/);
      const notes = run.checks.find((x) => x.id === 'frontend.block-editor').notes.join(' | ');
      assert.match(notes, /steps completed: login → editor → insert → save → reload → preview/);
      assert.ok(!JSON.stringify({ f: run.findings, c: run.checks }).includes('fixture-secret-pass'));
    } finally { delete process.env.WPQA_WP_USER; delete process.env.WPQA_WP_PASS; }
  });
});
