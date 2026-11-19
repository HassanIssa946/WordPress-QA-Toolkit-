// Frontend (Playwright + axe): page health per page × viewport, broken internal links, visual regression against
// approved baselines, site-specific e2e specs, and the approval-gated Gutenberg draft test (sandbox only).
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { readJson, exists, truncate } from '../lib/util.mjs';
import { discoverBlocks } from '../lib/discover.mjs';
import { pageTargets } from '../lib/targets.mjs';

const CAT = 'frontend';
export const VIEWPORTS = {
  desktop: { viewport: { width: 1366, height: 900 } },
  mobile: { viewport: { width: 390, height: 844 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 },
};
const AXE_SEV = { critical: 'high', serious: 'medium', moderate: 'low', minor: 'info' };

/** Links the crawler must never request (they log out, change state or need a session). */
export const UNSAFE_LINK = /(logout|log-out|wp-login\.php|\/wp-admin\b|[?&]action=|_wpnonce|add-to-cart|remove_item|\/cart\/?(\?|$)|\/checkout\/?|\/my-account\/customer-logout|[?&]empty-cart|[?&]undo_item|xmlrpc\.php|wp-cron\.php)/i;

export const slugOf = (p) => (p.replace(/^\/|\/$/g, '').replace(/[^a-z0-9]+/gi, '-').toLowerCase() || 'home');
export const baselineDir = (cfg) => path.join(cfg._root, 'wpqa-tests', 'baselines');

/** Example attribute values for a block from its block.json schema (to prove they survive save + reload). */
export function sampleAttributes(attrs = {}) {
  const out = {};
  for (const [k, d] of Object.entries(attrs || {})) {
    if (d?.source || k === 'lock' || k === 'metadata') continue; // sourced from markup / editor internals
    if (Array.isArray(d?.enum) && d.enum.length) out[k] = d.enum[d.enum.length - 1];
    else if (d?.type === 'string') out[k] = 'wpqa-test';
    else if (d?.type === 'number' || d?.type === 'integer') out[k] = 7;
    else if (d?.type === 'boolean') out[k] = !(d.default ?? false);
  }
  return out;
}

/** Custom blocks to test in the editor: one per name (build copy preferred), skipping child-only blocks. */
export function editorBlocks(customDirs) {
  const all = discoverBlocks(customDirs.map((d) => d.dir));
  const byName = new Map();
  for (const b of all.sort((a, c) => Number(c.inBuild) - Number(a.inBuild))) {
    const j = readJson(b.path);
    if (!j?.name || byName.has(j.name) || j.parent || j.ancestor || j.supports?.inserter === false) continue;
    byName.set(j.name, { name: j.name, file: b.path, attrs: sampleAttributes(j.attributes) });
  }
  return [...byName.values()];
}

/** Attributes that did not survive save + reload. */
export function lostAttributes(expected, actual = {}) {
  return Object.entries(expected).filter(([k, v]) => JSON.stringify(actual[k]) !== JSON.stringify(v)).map(([k]) => k);
}

/* ------------------------------ in-page probes ------------------------------ */

// Runs inside the page. Returns DOM facts for the checks (no values of form fields are read).
const PAGE_PROBE = () => {
  const desc = (e) => e.tagName.toLowerCase() + (e.id ? '#' + e.id : '') + (typeof e.className === 'string' && e.className.trim() ? '.' + e.className.trim().split(/\s+/).slice(0, 2).join('.') : '');
  const vw = document.documentElement.clientWidth;
  const sw = Math.max(document.documentElement.scrollWidth, document.body ? document.body.scrollWidth : 0);
  const offenders = sw > vw + 1 ? [...document.querySelectorAll('body *')].filter((e) => { const r = e.getBoundingClientRect(); return r.width > 0 && r.right > vw + 1 && getComputedStyle(e).position !== 'fixed'; }).slice(0, 5).map(desc) : [];
  const imgs = [...document.images].filter((i) => i.getBoundingClientRect().width > 1);
  const noAlt = imgs.filter((i) => !i.hasAttribute('alt')).slice(0, 10).map((i) => (i.currentSrc || i.src).split('?')[0].slice(-80));
  const noDims = imgs.filter((i) => !(i.getAttribute('width') && i.getAttribute('height')) && !getComputedStyle(i).aspectRatio.match(/\d/)).slice(0, 10).map((i) => (i.currentSrc || i.src).split('?')[0].slice(-80));
  const fields = [...document.querySelectorAll('input, select, textarea')].filter((f) => !['hidden', 'submit', 'button', 'reset', 'image'].includes((f.type || '').toLowerCase()) && f.getBoundingClientRect().width > 0);
  const unlabeled = fields.filter((f) => !(f.labels && f.labels.length) && !f.getAttribute('aria-label') && !f.getAttribute('aria-labelledby') && !f.getAttribute('title')).slice(0, 10).map(desc);
  const hasNonce = (el) => [...el.querySelectorAll('input[type=hidden]')].some((i) => /nonce/i.test(i.name)) || [el, ...el.querySelectorAll('*')].some((n) => [...n.attributes].some((a) => /nonce/i.test(a.name)));
  const postForms = [...document.forms].filter((f) => (f.getAttribute('method') || '').toLowerCase() === 'post');
  const noNonce = postForms.filter((f) => !hasNonce(f) && !/wp-comments-post\.php|wp-login\.php/.test(f.getAttribute('action') || '')).slice(0, 5).map((f) => desc(f) + (f.getAttribute('action') ? ` action=${f.getAttribute('action').slice(0, 60)}` : ''));
  const links = [...document.querySelectorAll('a[href]')].map((a) => a.href).filter((h) => /^https?:/.test(h));
  return { overflowPx: sw - vw, offenders, noAlt, noDims, unlabeled, noNonce, links };
};

// Runs in a blank page: compares two PNG data URLs pixel by pixel (no extra npm package needed).
const DIFF_PROBE = async ({ a, b, tolerance }) => {
  const load = (src) => new Promise((res, rej) => { const i = new Image(); i.onload = () => res(i); i.onerror = () => rej(new Error('image decode failed')); i.src = src; });
  const [ia, ib] = await Promise.all([load(a), load(b)]);
  if (ia.width !== ib.width || ia.height !== ib.height) return { sizeChanged: true, a: [ia.width, ia.height], b: [ib.width, ib.height] };
  const cv = (img) => { const c = document.createElement('canvas'); c.width = img.width; c.height = img.height; const x = c.getContext('2d'); x.drawImage(img, 0, 0); return x.getImageData(0, 0, img.width, img.height); };
  const da = cv(ia), db = cv(ib);
  const out = document.createElement('canvas'); out.width = ia.width; out.height = ia.height;
  const ox = out.getContext('2d'); const od = ox.createImageData(ia.width, ia.height);
  let diff = 0;
  for (let i = 0; i < da.data.length; i += 4) {
    const d = Math.abs(da.data[i] - db.data[i]) + Math.abs(da.data[i + 1] - db.data[i + 1]) + Math.abs(da.data[i + 2] - db.data[i + 2]);
    if (d > tolerance) { diff++; od.data[i] = 255; od.data[i + 3] = 255; } else { od.data[i] = od.data[i + 1] = od.data[i + 2] = da.data[i] * 0.3; od.data[i + 3] = 255; }
  }
  ox.putImageData(od, 0, 0);
  return { ratio: diff / (da.data.length / 4), diffPixels: diff, png: diff ? out.toDataURL('image/png') : null };
};

/* ------------------------------ module ------------------------------ */

async function launch(run) {
  if (run.browserFactory) return run.browserFactory();
  const { chromium } = await import('playwright');
  return chromium.launch({ headless: true });
}

export default async function frontend(run) {
  const { cfg } = run;
  const fc = cfg.frontend;
  const viewports = (fc.viewports || ['desktop', 'mobile']).filter((v) => VIEWPORTS[v]);
  let browser = null, browserError = null;
  const getBrowser = async () => {
    if (browser || browserError) return browser;
    try { browser = await launch(run); } catch (e) { browserError = truncate(e.message, 300); }
    return browser;
  };
  const noBrowser = (c) => c.skip(`browser not available: ${browserError}`, 'Install Playwright + Chromium in the toolkit folder: npm install playwright @axe-core/playwright, then npx playwright install chromium.');
  const shots = []; // { page, viewport, file } for visual regression
  const base = cfg.site.url.replace(/\/$/, '');
  const pages = (cfg.site.pages || ['/']).slice(0, fc.maxPages || 12);
  const linkSet = new Set();

  try {
    /* ---------------- page health + axe ---------------- */
    await run.check({ id: 'frontend.pages', title: 'Page health per viewport: status, JS errors, failed requests, overflow, images, labels, forms, accessibility (axe)', category: CAT, tool: 'Playwright + axe-core', requires: { url: true } }, async (c) => {
      if (!(await getBrowser())) return noBrowser(c);
      let AxeBuilder = null;
      try { AxeBuilder = (await import('@axe-core/playwright')).default; } catch { c.note('@axe-core/playwright not installed — accessibility part not tested'); }
      const host = new URL(base).host;
      const shotDir = run.artifactDir('visual');
      let loaded = 0;
      for (const vp of viewports) {
        const ctx = await browser.newContext({ ...VIEWPORTS[vp], ignoreHTTPSErrors: cfg.site.environment !== 'production' });
        try {
          for (const p of pages) {
            const url = new URL(p, base + '/').href;
            const page = await ctx.newPage();
            const consoleErrors = [], pageErrors = [], failed = [];
            page.on('console', (m) => { if (m.type() === 'error') consoleErrors.push(m.text().slice(0, 200)); });
            page.on('pageerror', (e) => pageErrors.push(String(e.message || e).slice(0, 200)));
            page.on('requestfailed', (r) => { try { if (new URL(r.url()).host === host) failed.push(`${r.failure()?.errorText || 'failed'} ${r.url().slice(0, 120)}`); } catch { /* ignore */ } });
            page.on('response', (r) => { try { if (r.status() >= 400 && new URL(r.url()).host === host && r.url() !== url) failed.push(`HTTP ${r.status()} ${r.url().slice(0, 120)}`); } catch { /* ignore */ } });
            let resp = null;
            try { resp = await page.goto(url, { waitUntil: 'load', timeout: 60000 }); await page.waitForTimeout(800); } catch (e) { c.finding({ severity: 'high', rule: 'page.load', title: `${vp}: page did not load (${truncate(e.message.split('\n')[0], 120)})`, url, fingerprintExtra: vp }); await page.close(); continue; }
            loaded++;
            c.scope([url]);
            const status = resp?.status() ?? 0;
            if (status >= 400) c.finding({ severity: status >= 500 ? 'high' : 'medium', rule: 'page.status', title: `HTTP ${status}`, url, fingerprintExtra: `status:${status}` });
            if (pageErrors.length) c.finding({ severity: 'medium', rule: 'page.js-error', title: `${vp}: ${pageErrors.length} uncaught JavaScript error(s)`, url, fingerprintExtra: `pageerror:${vp}`, message: [...new Set(pageErrors)].slice(0, 5).join(' · ') });
            if (consoleErrors.length) c.finding({ severity: 'low', rule: 'page.console-error', title: `${vp}: ${consoleErrors.length} console error(s)`, url, fingerprintExtra: `console:${vp}`, message: [...new Set(consoleErrors)].slice(0, 5).join(' · ') });
            if (failed.length) c.finding({ severity: 'medium', rule: 'page.failed-request', title: `${vp}: ${failed.length} failed same-origin request(s)`, url, fingerprintExtra: `failed:${vp}`, message: [...new Set(failed)].slice(0, 8).join(' · ') });
            const d = await page.evaluate(PAGE_PROBE);
            d.links.forEach((l) => linkSet.add(l));
            if (d.overflowPx > 1) c.finding({ severity: vp === 'mobile' ? 'medium' : 'low', rule: 'page.overflow', title: `${vp}: page scrolls sideways (${d.overflowPx}px wider than the screen)`, url, fingerprintExtra: `overflow:${vp}`, message: d.offenders.length ? `Wider elements: ${d.offenders.join(', ')}` : null, recommendation: 'Find the element wider than the viewport (fixed widths, 100vw + padding, long words/URLs) and constrain it.' });
            if (vp === viewports[0]) {
              if (d.noAlt.length) c.finding({ severity: 'medium', rule: 'page.img-alt', title: `${d.noAlt.length} image(s) without an alt attribute`, url, message: d.noAlt.join(', '), recommendation: 'Add alt text (or alt="" for decorative images).' });
              if (d.noDims.length) c.finding({ severity: 'low', rule: 'page.img-dimensions', title: `${d.noDims.length} image(s) without width/height`, url, message: d.noDims.join(', '), recommendation: 'Set width and height (or aspect-ratio) so the layout does not jump while images load (CLS).' });
              if (d.unlabeled.length) c.finding({ severity: 'medium', rule: 'page.form-label', title: `${d.unlabeled.length} form field(s) without a label`, url, message: d.unlabeled.join(', '), recommendation: 'Associate a <label for>, or aria-label/aria-labelledby.' });
              if (d.noNonce.length) c.finding({ severity: 'low', confidence: 'heuristic', rule: 'page.form-nonce', title: `${d.noNonce.length} POST form(s) without a nonce field`, url, message: d.noNonce.join(', '), recommendation: 'If the form changes data for logged-in users, add wp_nonce_field() and verify it. Public forms (search, newsletter) may not need one — confirm.' });
            }
            if (AxeBuilder) {
              try {
                const res = await new AxeBuilder({ page }).analyze();
                for (const v of res.violations) {
                  c.finding({ severity: AXE_SEV[v.impact] || 'low', rule: `axe.${v.id}`, title: `${vp}: ${v.help} (${v.nodes.length} element${v.nodes.length > 1 ? 's' : ''})`, url, fingerprintExtra: `axe:${v.id}`, message: v.nodes.slice(0, 3).map((n) => n.target.join(' ')).join(' · '), references: [v.helpUrl], tool: 'axe-core', recommendation: v.description });
                }
              } catch (e) { c.note(`axe failed on ${vp} ${url}: ${truncate(e.message, 120)}`); }
            }
            if (fc.visualRegression) {
              const file = path.join(shotDir, vp, `${slugOf(p)}.png`);
              fs.mkdirSync(path.dirname(file), { recursive: true });
              try {
                const mask = (fc.visualMask || []).map((s) => page.locator(s));
                await page.screenshot({ path: file, fullPage: true, animations: 'disabled', mask, caret: 'hide' });
                shots.push({ page: p, viewport: vp, file, url });
              } catch (e) { c.note(`screenshot failed (${vp} ${url}): ${truncate(e.message, 120)}`); }
            }
            await page.close();
          }
        } finally { await ctx.close(); }
      }
      c.stats = { pages: pages.length, viewports, loaded };
      if (!loaded) return c.skip('no page could be loaded in the browser');
    });

    /* ---------------- broken internal links ---------------- */
    await run.check({ id: 'frontend.links', title: 'Broken internal links (logout, login, admin, nonce and cart links are never requested)', category: CAT, requires: { url: true } }, async (c) => {
      const host = new URL(base).host;
      if (!linkSet.size) {
        // Without the browser pass, collect links from the HTML of the configured pages.
        for (const t of (await pageTargets(run)).slice(0, 1)) for (const p of t.pages) {
          const r = await run.http(new URL(p, base + '/').href, { timeoutMs: 20000, redirect: 'follow' });
          for (const m of String(r.text || '').matchAll(/<a\b[^>]*href=["']([^"'#]+)/gi)) { try { linkSet.add(new URL(m[1].replace(/&amp;/g, '&'), base + '/').href); } catch { /* skip */ } }
        }
      }
      const internal = [...linkSet].map((l) => l.split('#')[0]).filter((l, i, a) => l && a.indexOf(l) === i).filter((l) => { try { return new URL(l).host === host; } catch { return false; } });
      const skipped = internal.filter((l) => UNSAFE_LINK.test(l));
      const toCheck = internal.filter((l) => !UNSAFE_LINK.test(l)).slice(0, fc.maxLinksToCheck);
      if (!toCheck.length) return c.notApplicable('no internal links found on the configured pages');
      let broken = 0;
      for (const l of toCheck) {
        const r = await run.http(l, { timeoutMs: 20000, redirect: 'follow', readBody: false });
        c.scope([l]);
        if (!r.ok || r.status >= 400) { broken++; c.finding({ severity: r.status >= 500 || !r.ok ? 'high' : 'medium', rule: 'link.broken', title: `Broken internal link: ${r.ok ? `HTTP ${r.status}` : r.error}`, url: l, recommendation: 'Fix or remove the link (menus, content, widgets), or add a redirect.' }); }
      }
      c.stats = { checked: toCheck.length, broken, neverRequested: skipped.length, found: internal.length };
      if (skipped.length) c.note(`${skipped.length} link(s) not requested on purpose (logout/login/admin/nonce/cart)`);
      if (internal.length > toCheck.length + skipped.length) c.note(`${internal.length - toCheck.length - skipped.length} more link(s) not checked (frontend.maxLinksToCheck = ${fc.maxLinksToCheck})`);
    });

    /* ---------------- visual regression ---------------- */
    await run.check({ id: 'frontend.visual', title: 'Visual regression against approved baselines (wpqa-tests/baselines)', category: CAT, tool: 'Playwright screenshots', requires: { url: true } }, async (c) => {
      if (!fc.visualRegression) return c.notApplicable('frontend.visualRegression is false');
      if (!shots.length) return c.skip('no screenshots were taken (frontend.pages did not load pages)');
      const dir = baselineDir(cfg);
      const missing = shots.filter((s) => !exists(path.join(dir, s.viewport, `${slugOf(s.page)}.png`)));
      const compare = shots.filter((s) => !missing.includes(s));
      for (const s of shots) c.artifact(s.file, `${s.viewport} ${s.page}`);
      if (!compare.length) return c.skip(`no approved baselines yet (${missing.length} screenshot(s) taken)`, 'Review the screenshots in this report\'s artifacts/visual folder, then approve them with: node <toolkit>/bin/wpqa.mjs baselines update --confirm');
      if (!(await getBrowser())) return noBrowser(c);
      const page = await browser.newPage();
      try {
        for (const s of compare) {
          const basePng = path.join(dir, s.viewport, `${slugOf(s.page)}.png`);
          c.scope([s.url]);
          const toUrl = (f) => 'data:image/png;base64,' + fs.readFileSync(f).toString('base64');
          const r = await page.evaluate(DIFF_PROBE, { a: toUrl(basePng), b: toUrl(s.file), tolerance: 30 });
          if (r.sizeChanged) { c.finding({ severity: 'medium', rule: 'visual.size', title: `${s.viewport} ${s.page}: page size changed (${r.a.join('×')} → ${r.b.join('×')})`, url: s.url, fingerprintExtra: `${s.viewport}:${s.page}`, recommendation: 'Compare the screenshots. If the change is intended, approve it: wpqa baselines update --confirm' }); continue; }
          if (r.ratio > fc.visualThreshold) {
            const diffFile = s.file.replace(/\.png$/, '.diff.png');
            fs.writeFileSync(diffFile, Buffer.from(r.png.split(',')[1], 'base64'));
            c.artifact(diffFile, `diff ${s.viewport} ${s.page}`);
            c.finding({ severity: 'medium', rule: 'visual.diff', title: `${s.viewport} ${s.page}: ${(r.ratio * 100).toFixed(2)}% of pixels changed`, url: s.url, fingerprintExtra: `${s.viewport}:${s.page}`, recommendation: 'Look at the diff image (red = changed). If intended, approve the new screenshots: wpqa baselines update --confirm. Baselines are never updated automatically.' });
          }
        }
      } finally { await page.close(); }
      c.stats = { compared: compare.length, withoutBaseline: missing.length };
      if (missing.length) c.note(`${missing.length} screenshot(s) have no baseline yet — not compared`);
    });

    /* ---------------- site-specific e2e specs ---------------- */
    await run.check({ id: 'frontend.e2e', title: 'Site-specific end-to-end specs (wpqa-tests/e2e/*.spec.mjs)', category: CAT, tool: 'Playwright', requires: { url: true } }, async (c) => {
      const dir = path.join(cfg._root, 'wpqa-tests', 'e2e');
      const specs = exists(dir) ? fs.readdirSync(dir).filter((f) => f.endsWith('.spec.mjs')).sort() : [];
      if (!specs.length) return c.notApplicable('no specs in wpqa-tests/e2e (add *.spec.mjs files to test site-specific flows)');
      if (!(await getBrowser())) return noBrowser(c);
      const assert = (await import('node:assert/strict')).default;
      let passed = 0, failed = 0;
      for (const f of specs) {
        const file = path.join(dir, f);
        c.scope([file]);
        let mod;
        try { mod = await import(pathToFileURL(file).href + `?t=${Date.now()}`); } catch (e) { failed++; c.finding({ severity: 'medium', rule: 'e2e.load', title: `${f}: cannot load spec (${truncate(e.message, 120)})`, file }); continue; }
        const tests = Array.isArray(mod.default) ? mod.default : typeof mod.default === 'function' ? [{ name: f, run: mod.default }] : [];
        for (const t of tests) {
          const ctx = await browser.newContext(VIEWPORTS[t.viewport || 'desktop']);
          const page = await ctx.newPage();
          try {
            await t.run({ page, baseURL: base, assert, readOnly: true });
            passed++;
          } catch (e) {
            failed++;
            const shot = path.join(run.artifactDir('e2e'), `${slugOf(f + '-' + t.name)}.png`);
            try { await page.screenshot({ path: shot, fullPage: true }); c.artifact(shot, `failure ${t.name}`); } catch { /* ignore */ }
            c.finding({ severity: t.severity || 'medium', rule: 'e2e.failed', title: `${f} › ${t.name}: ${truncate(e.message.split('\n')[0], 140)}`, file, fingerprintExtra: t.name });
          } finally { await ctx.close(); }
        }
      }
      c.stats = { specs: specs.length, passed, failed };
    });

    /* ---------------- Gutenberg editor round trip (sandbox only) ---------------- */
    await run.check({ id: 'frontend.block-editor', title: 'Block editor: insert each custom block, save, reload, attributes kept, block valid, front-end render (temporary draft, always deleted)', category: CAT, tool: 'Playwright', requires: { url: true } }, async (c) => {
      if (fc.blockEditorTest === false) return c.notApplicable('frontend.blockEditorTest is false');
      const blocks = editorBlocks(run.customDirs);
      if (!blocks.length) return c.notApplicable('no custom blocks (block.json) in your themes/plugins');
      if (!(await c.requireApproval('editor-drafts', base))) return;
      const user = process.env.WPQA_WP_USER, pass = process.env.WPQA_WP_PASS;
      if (!user || !pass) return c.skip('credentials not set', 'Set WPQA_WP_USER and WPQA_WP_PASS (an Editor or Administrator on the sandbox) in the environment. They are never written to files or reports.');
      if (!(await getBrowser())) return noBrowser(c);
      const result = await (run.editorRoundTrip || editorRoundTrip)({ browser, base, blocks, user, pass, artifactDir: run.artifactDir('block-editor') });
      for (const b of result.blocks) {
        c.scope([`${base}/wp-admin/post.php?post=${result.postId}`]);
        if (!b.registered) c.finding({ severity: 'high', rule: 'editor.not-registered', title: `Block ${b.name} is not registered in the editor`, file: b.file, recommendation: 'Its editorScript is missing or failed to load (build the block, check the browser console in the editor).' });
        else {
          if (b.invalid) c.finding({ severity: 'high', rule: 'editor.invalid', title: `Block ${b.name} is invalid after reload ("This block contains unexpected or invalid content")`, file: b.file, recommendation: 'save() output changed or does not match the stored markup — add a deprecation or fix save().' });
          if (b.lost?.length) c.finding({ severity: 'high', rule: 'editor.attributes-lost', title: `Block ${b.name}: attribute(s) not kept after save + reload: ${b.lost.join(', ')}`, file: b.file, recommendation: 'Check the attribute definitions in block.json (type, source/selector) and that edit() calls setAttributes for them.' });
          if (b.renderError) c.finding({ severity: 'high', rule: 'editor.render', title: `Block ${b.name}: front-end render problem (${b.renderError})`, file: b.file });
        }
      }
      if (result.error) c.finding({ severity: 'high', rule: 'editor.flow', title: `Editor test did not complete: ${truncate(result.error, 160)}`, url: `${base}/wp-admin/post-new.php` });
      const cleanupLog = (result.cleanup?.log || []).join('; ');
      if (result.leftover) c.finding({ severity: 'high', rule: 'editor.leftover-draft', title: `Temporary draft ${result.leftover} could not be deleted — remove it by hand`, url: `${base}/wp-admin/post.php?post=${result.leftover}&action=edit`, message: cleanupLog ? `Cleanup attempts: ${cleanupLog}` : null, recommendation: 'Delete the draft "WPQA temporary draft" in Posts → Drafts (and empty the trash).' });
      c.stats = { blocks: blocks.length, postId: result.postId, deleted: !result.leftover, steps: result.steps || [] };
      c.note(`steps completed: ${(result.steps || []).join(' → ') || '(none)'}${result.error ? ` — stopped: ${truncate(result.error, 120)}` : ''}`);
      c.note(`temporary draft ${result.postId ?? '(none)'} ${result.leftover ? 'NOT deleted' : 'deleted'}${cleanupLog ? ` (${cleanupLog})` : ''}`);
    });
  } finally {
    if (browser) await browser.close().catch(() => {});
  }
}

const NONCE_RE = /^[a-f0-9]{10}$/i;
const firstLine = (e) => String(e?.message || e).split('\n')[0];

/** Log in through the request API (no page needed). Sets the session cookies on the context. Never logs creds. */
async function requestLogin(request, base, user, pass) {
  await request.get(`${base}/wp-login.php`); // sets wordpress_test_cookie
  const r = await request.post(`${base}/wp-login.php`, { form: { log: user, pwd: pass, rememberme: 'forever', 'wp-submit': 'Log In', testcookie: '1', redirect_to: `${base}/wp-admin/` } });
  return r.status();
}

/**
 * Permanently delete the temporary draft and prove it is gone (REST GET → 404). Uses the browser context's
 * request API, so it works whatever state the page is in (error page, crashed or closed page).
 * Order: REST nonce (re-login if the session is gone) → DELETE → POST + X-HTTP-Method-Override (what WordPress's
 * own apiFetch uses when servers block DELETE) → again if the post only went to the trash.
 * Returns { deleted, log } — the log has HTTP statuses and WordPress error codes only, never the nonce or cookies.
 */
export async function deleteDraft({ request, base, postId, user, pass }) {
  const log = [];
  const rest = (q) => `${base}/?rest_route=/wp/v2/posts/${postId}${q}`;
  const code = async (r) => { try { return (await r.json())?.code || ''; } catch { return ''; } };
  const getNonce = async () => {
    const r = await request.get(`${base}/wp-admin/admin-ajax.php?action=rest-nonce`);
    const t = (await r.text()).trim();
    if (NONCE_RE.test(t)) return t;
    log.push(`rest-nonce: HTTP ${r.status()}, ${/^-?[01]$/.test(t) ? `answer "${t}" (session not accepted)` : 'no nonce in the answer'}`);
    return null;
  };
  let relogged = false;
  const relogin = async () => {
    relogged = true;
    log.push(`re-login: HTTP ${await requestLogin(request, base, user, pass)}`);
    return getNonce();
  };
  try {
    let nonce = await getNonce();
    if (!nonce && user && pass) nonce = await relogin();
    if (!nonce) return { deleted: false, log };
    const headers = { 'X-WP-Nonce': nonce };
    for (const how of ['DELETE', 'POST+override', 'POST+override']) {
      const r = how === 'DELETE'
        ? await request.delete(rest('&force=true'), { headers })
        : await request.post(rest('&force=true'), { headers: { ...headers, 'X-HTTP-Method-Override': 'DELETE' } });
      const c = await code(r);
      log.push(`${how}: HTTP ${r.status()}${c ? ` ${c}` : ''}`);
      // Session or nonce no longer accepted by REST → one fresh login, then carry on with the new nonce.
      if ((r.status() === 401 || c === 'rest_cookie_invalid_nonce') && !relogged && user && pass) {
        const fresh = await relogin();
        if (!fresh) return { deleted: false, log };
        headers['X-WP-Nonce'] = fresh;
      }
      const check = await request.get(rest('&context=edit'), { headers });
      if (check.status() === 404) { log.push('verified: post no longer exists (HTTP 404)'); return { deleted: true, log }; }
      let st = '';
      try { st = (await check.json())?.status || ''; } catch { /* not JSON */ }
      log.push(`check: HTTP ${check.status()}${st ? `, post status "${st}"` : ''}${await code(check) ? ` ${await code(check)}` : ''}`);
    }
    return { deleted: false, log };
  } catch (e) {
    log.push(`cleanup error: ${firstLine(e)}`);
    return { deleted: false, log };
  }
}

/**
 * The editor flow. Logs in, creates a draft with every block, saves, reloads, checks, previews, and ALWAYS deletes
 * the draft. Never logs or returns the credentials. `steps` lists the stages that completed.
 */
export async function editorRoundTrip({ browser, base, blocks, user, pass, timeoutMs = 60000 }) {
  const ctx = await browser.newContext({ viewport: { width: 1366, height: 900 } });
  const out = { postId: null, blocks: blocks.map((b) => ({ ...b })), error: null, leftover: null, steps: [], cleanup: null };
  const T = { timeout: timeoutMs };
  let page = null;
  try {
    page = await ctx.newPage();
    await page.goto(`${base}/wp-login.php`, { waitUntil: 'domcontentloaded', ...T });
    await page.fill('#user_login', user);
    await page.fill('#user_pass', pass);
    await Promise.all([page.waitForURL((u) => !/wp-login\.php/.test(u.pathname), T).catch(() => {}), page.click('#wp-submit')]);
    if (/wp-login\.php/.test(page.url())) throw new Error('login failed — check WPQA_WP_USER / WPQA_WP_PASS');
    out.steps.push('login');
    await page.goto(`${base}/wp-admin/post-new.php`, { waitUntil: 'domcontentloaded', ...T });
    await page.waitForFunction(() => window.wp?.data?.select('core/editor')?.getCurrentPostId?.(), null, T);
    out.postId = await page.evaluate(() => wp.data.select('core/editor').getCurrentPostId());
    out.steps.push('editor');
    await page.evaluate(() => { try { wp.data.dispatch('core/preferences').set('core/edit-post', 'welcomeGuide', false); } catch { /* older WP */ } });
    const reg = await page.evaluate((list) => list.map((b) => !!wp.blocks.getBlockType(b.name)), blocks);
    out.blocks.forEach((b, i) => { b.registered = reg[i]; });
    await page.evaluate((list) => {
      const made = list.filter((b) => wp.blocks.getBlockType(b.name)).map((b) => wp.blocks.createBlock(b.name, b.attrs));
      wp.data.dispatch('core/block-editor').insertBlocks(made);
      wp.data.dispatch('core/editor').editPost({ title: 'WPQA temporary draft — safe to delete', status: 'draft' });
    }, blocks);
    out.steps.push('insert');
    await page.evaluate(() => wp.data.dispatch('core/editor').savePost());
    // Done when the save finished: clean, or failed (a failed save stays dirty, so "not dirty" alone would hang).
    await page.waitForFunction(() => {
      const ed = wp.data.select('core/editor');
      if (ed.isSavingPost()) return false;
      const failed = ed.didPostSaveRequestFail?.() || wp.data.select('core/notices').getNotices().some((n) => n.status === 'error');
      return failed || !ed.isEditedPostDirty();
    }, null, T);
    const saveError = await page.evaluate(() => {
      const n = wp.data.select('core/notices').getNotices().find((x) => x.status === 'error');
      if (n) return String(n.content);
      return wp.data.select('core/editor').didPostSaveRequestFail?.() ? 'save request failed' : null;
    });
    if (saveError) throw new Error(`save failed: ${saveError}`);
    out.steps.push('save');
    await page.goto(`${base}/wp-admin/post.php?post=${out.postId}&action=edit`, { waitUntil: 'domcontentloaded', ...T });
    await page.waitForFunction(() => window.wp?.data?.select('core/block-editor')?.getBlocks?.().length > 0, null, T);
    const after = await page.evaluate(() => wp.data.select('core/block-editor').getBlocks().map((b) => ({ name: b.name, isValid: b.isValid, attributes: b.attributes })));
    for (const b of out.blocks.filter((x) => x.registered)) {
      const a = after.find((x) => x.name === b.name);
      if (!a) { b.lost = ['(block missing after reload)']; continue; }
      b.invalid = a.isValid === false;
      b.lost = lostAttributes(b.attrs, a.attributes);
    }
    out.steps.push('reload');
    const resp = await page.goto(`${base}/?p=${out.postId}&preview=true`, { waitUntil: 'load', ...T });
    const html = await page.content();
    const fatal = /There has been a critical error|Fatal error:|Parse error:/i.test(html) || (resp && resp.status() >= 500);
    for (const b of out.blocks.filter((x) => x.registered)) {
      const cls = `wp-block-${b.name.replace('/', '-')}`;
      if (fatal) b.renderError = `preview returned ${resp?.status()} with a PHP error`;
      else if (!html.includes(cls) && !html.includes(`data-wpqa-block="${b.name}"`)) b.renderError = `no element with class ${cls} in the preview (did render.php / save() output anything?)`;
    }
    out.steps.push('preview');
  } catch (e) {
    out.error = firstLine(e);
  } finally {
    if (out.postId) {
      out.cleanup = await deleteDraft({ request: ctx.request, base, postId: out.postId, user, pass });
      if (!out.cleanup.deleted) out.leftover = out.postId;
    }
    await ctx.close().catch(() => {});
  }
  return out;
}
