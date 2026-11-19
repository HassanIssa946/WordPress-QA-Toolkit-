// Block-editor round trip against a fake WordPress (login, editor stub, admin-ajax rest-nonce, REST posts with
// cookie + nonce auth, preview) in real Chromium. Proves the temporary draft is deleted on success, on a failed
// test step, on a browser error, and through each cleanup fallback — and that leftovers are reported with the
// reason, never with the nonce or the credentials.
import { test, describe, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import path from 'node:path';
import crypto from 'node:crypto';
import { editorRoundTrip, deleteDraft, editorBlocks } from '../modules/frontend.mjs';
import { TESTS_DIR } from './helpers.mjs';

const USER = 'fixture-user', PASS = 'fixture-secret-pass';
const FIXTURE_PLUGIN = path.join(TESTS_DIR, '..', 'sandbox', 'wpqa-fixture-blocks');
const BLOCKS = editorBlocks([{ dir: FIXTURE_PLUGIN }]);

let server, base, browser, chromiumWhy = '';
let posts, sessions, nextId, scenario, issuedNonces;

const nonceFor = (s) => crypto.createHash('md5').update(`nonce:${s}`).digest('hex').slice(0, 10);
const cookieSession = (req) => { const m = /wordpress_logged_in_fx=([a-z0-9]+)/.exec(req.headers.cookie || ''); return m && sessions.has(m[1]) ? m[1] : null; };

const EDITOR_JS = (id, blocks, failSave) => `
window.wp = (() => {
  const s = { id: ${id}, blocks: ${JSON.stringify(blocks)}.map((b) => ({ ...b, isValid: true })), saving: false, dirty: false, failed: false, notices: [] };
  const types = { 'wpqa-fixture/notice': {} };
  const stores = {
    'core/editor': { getCurrentPostId: () => s.id, isSavingPost: () => s.saving, isEditedPostDirty: () => s.dirty, didPostSaveRequestFail: () => s.failed },
    'core/notices': { getNotices: () => s.notices },
    'core/block-editor': { getBlocks: () => s.blocks },
  };
  const actions = {
    'core/preferences': { set() {} },
    'core/block-editor': { insertBlocks(bs) { s.blocks.push(...bs.map((b) => ({ ...b, isValid: true }))); s.dirty = true; } },
    'core/editor': {
      editPost() { s.dirty = true; },
      savePost() {
        s.saving = true;
        fetch('/wpqa-save?id=' + s.id, { method: 'POST', body: JSON.stringify(s.blocks.map(({ name, attributes }) => ({ name, attributes }))) })
          .then((r) => r.json()).then((j) => {
            if (j.ok) s.dirty = false; else { s.failed = true; s.notices.push({ status: 'error', content: j.error }); }
            s.saving = false;
          });
      },
    },
  };
  return {
    blocks: { getBlockType: (n) => types[n], createBlock: (name, attributes) => ({ name, attributes: { ...attributes } }) },
    data: { select: (n) => stores[n], dispatch: (n) => actions[n] },
  };
})();`;

function handler(req, res) {
  const u = new URL(req.url, 'http://x');
  let body = '';
  req.on('data', (d) => { body += d; });
  req.on('end', () => {
    const send = (code, data, headers = {}) => {
      const json = typeof data !== 'string';
      res.writeHead(code, { 'content-type': json ? 'application/json' : 'text/html', ...headers });
      res.end(json ? JSON.stringify(data) : data);
    };
    if (u.pathname === '/wp-admin/admin-ajax.php' && scenario.expireSessionAtCleanup && !scenario.expired) { scenario.expired = true; sessions.clear(); }
    const sess = cookieSession(req);
    if (u.pathname === '/wp-login.php') {
      if (req.method === 'POST') {
        const f = new URLSearchParams(body);
        if (f.get('log') === USER && f.get('pwd') === PASS) {
          const s = crypto.randomBytes(8).toString('hex');
          sessions.add(s);
          return send(302, '', { location: '/wp-admin/', 'set-cookie': `wordpress_logged_in_fx=${s}; Path=/; HttpOnly` });
        }
      }
      return send(200, '<form method="post" action="/wp-login.php"><input id="user_login" name="log"><input id="user_pass" name="pwd" type="password"><button id="wp-submit" type="submit">Log In</button></form>', { 'set-cookie': 'wordpress_test_cookie=WP; Path=/' });
    }
    if (u.pathname === '/wp-admin/admin-ajax.php' && u.searchParams.get('action') === 'rest-nonce') {
      if (!sess) return send(200, '0');
      const n = nonceFor(sess);
      issuedNonces.add(n);
      return send(200, n);
    }
    if (u.pathname.startsWith('/wp-admin/')) {
      if (!sess) return send(302, '', { location: '/wp-login.php' });
      if (u.pathname === '/wp-admin/post-new.php') {
        const id = nextId++;
        posts.set(id, { status: 'auto-draft', blocks: [] });
        return send(200, `<html><body><div id="editor"></div><script>${EDITOR_JS(id, [], false)}</script></body></html>`);
      }
      if (u.pathname === '/wp-admin/post.php') {
        const id = Number(u.searchParams.get('post'));
        const p = posts.get(id);
        return p ? send(200, `<html><body><script>${EDITOR_JS(id, p.blocks)}</script></body></html>`) : send(404, 'gone');
      }
      return send(200, '<html><body>Dashboard</body></html>');
    }
    if (u.pathname === '/wpqa-save') {
      const p = posts.get(Number(u.searchParams.get('id')));
      if (scenario.saveFails || !p) return send(200, { ok: false, error: 'Updating failed. Could not update post in the database.' });
      Object.assign(p, { status: 'draft', blocks: JSON.parse(body) });
      return send(200, { ok: true });
    }
    const route = u.searchParams.get('rest_route');
    if (route) {
      const id = Number(/\/wp\/v2\/posts\/(\d+)/.exec(route)?.[1]);
      if (scenario.blockDeleteMethod && req.method === 'DELETE') return send(405, '<h1>405 Not Allowed</h1>');
      const method = req.method === 'POST' && req.headers['x-http-method-override'] ? req.headers['x-http-method-override'].toUpperCase() : req.method;
      if (scenario.rejectFirstNonce && !scenario.rejected) { scenario.rejected = true; sessions.clear(); }
      if (!cookieSession(req) || req.headers['x-wp-nonce'] !== nonceFor(sess)) return send(403, { code: 'rest_cookie_invalid_nonce', message: 'Cookie check failed' });
      const p = posts.get(id);
      if (!p) return send(404, { code: 'rest_post_invalid_id' });
      if (method === 'GET') return send(200, { id, status: p.status });
      if (method === 'DELETE') {
        if (scenario.neverDelete) return send(403, { code: 'rest_cannot_delete', message: 'Sorry, you are not allowed to delete this post.' });
        if (scenario.trashFirst && p.status !== 'trash') { p.status = 'trash'; return send(200, { id, status: 'trash' }); }
        posts.delete(id);
        return send(200, { deleted: true });
      }
      return send(400, { code: 'rest_no_route' });
    }
    if (u.searchParams.get('preview') === 'true') {
      const p = posts.get(Number(u.searchParams.get('p')));
      const html = (p?.blocks || []).map((b) => `<div class="wp-block-${b.name.replace('/', '-')} wpqa-notice">${b.attributes.message || ''}</div>`).join('');
      return send(200, `<html><body>${html}</body></html>`);
    }
    return send(404, 'not found');
  });
}

before(async () => {
  try { const { chromium } = await import('playwright'); browser = await chromium.launch(); } catch (e) { chromiumWhy = e.message.split('\n')[0]; }
  server = http.createServer(handler);
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(async () => { await browser?.close(); server?.close(); });
beforeEach(() => { posts = new Map(); sessions = new Set(); nextId = 100; scenario = {}; issuedNonces = new Set(); });

const browserTest = (name, fn) => test(name, async (t) => { if (!browser) return t.skip(`Chromium not available: ${chromiumWhy}`); await fn(t); });
const roundTrip = (b = browser) => editorRoundTrip({ browser: b, base, blocks: BLOCKS, user: USER, pass: PASS, timeoutMs: 10000 });
const assertNoSecrets = (out) => {
  const s = JSON.stringify(out);
  for (const secret of [PASS, ...issuedNonces]) assert.ok(!s.includes(secret), 'a secret leaked into the result');
};

/** A browser whose page is closed during the 3rd navigation (simulates a crashed / closed editor tab). */
function crashingBrowser(real) {
  const bind = (o, k) => (typeof o[k] === 'function' ? o[k].bind(o) : o[k]);
  return {
    newContext: async (opts) => {
      const ctx = await real.newContext(opts);
      return new Proxy(ctx, {
        get(t, k) {
          if (k !== 'newPage') return bind(t, k);
          return async () => {
            const p = await t.newPage();
            let n = 0;
            return new Proxy(p, { get(pt, pk) { return pk === 'goto' ? async (...a) => { if (++n === 3) await pt.close(); return pt.goto(...a); } : bind(pt, pk); } });
          };
        },
      });
    },
  };
}

describe('editor round trip — the fixture plugin block', () => {
  test('sandbox/wpqa-fixture-blocks is discovered with typed sample attributes', () => {
    assert.deepEqual(BLOCKS.map((b) => b.name), ['wpqa-fixture/notice']);
    assert.deepEqual(BLOCKS[0].attrs, { message: 'wpqa-test', level: 'error', count: 7, dismissible: true });
  });
});

describe('editor round trip — cleanup always runs', () => {
  browserTest('success: every step completes, attributes kept, block rendered, draft deleted and verified', async () => {
    const out = await roundTrip();
    assert.equal(out.error, null);
    assert.deepEqual(out.steps, ['login', 'editor', 'insert', 'save', 'reload', 'preview']);
    const b = out.blocks[0];
    assert.equal(b.registered, true);
    assert.equal(b.invalid, false);
    assert.deepEqual(b.lost, []);
    assert.equal(b.renderError, undefined);
    assert.equal(out.leftover, null);
    assert.equal(out.cleanup.deleted, true);
    assert.ok(out.cleanup.log.includes('DELETE: HTTP 200'));
    assert.equal(posts.size, 0, 'no post left on the server');
    assertNoSecrets(out);
  });

  browserTest('a failed step (save error) stops the flow quickly and still deletes the draft', async () => {
    scenario.saveFails = true;
    const t0 = Date.now();
    const out = await roundTrip();
    assert.match(out.error, /save failed: Updating failed/);
    assert.deepEqual(out.steps, ['login', 'editor', 'insert']);
    assert.ok(Date.now() - t0 < 9000, 'a failed save must not wait for the timeout');
    assert.equal(out.cleanup.deleted, true);
    assert.equal(posts.size, 0);
    assertNoSecrets(out);
  });

  browserTest('a browser error (editor tab closed mid-flow) still deletes the draft through the context', async () => {
    const out = await roundTrip(crashingBrowser(browser));
    assert.match(out.error, /closed/i);
    assert.deepEqual(out.steps, ['login', 'editor', 'insert', 'save']);
    assert.equal(out.cleanup.deleted, true);
    assert.equal(posts.size, 0);
  });

  browserTest('login failure: no draft created, nothing to clean up', async () => {
    const out = await editorRoundTrip({ browser, base, blocks: BLOCKS, user: USER, pass: 'wrong', timeoutMs: 5000 });
    assert.match(out.error, /login failed/);
    assert.equal(out.postId, null);
    assert.equal(out.leftover, null);
    assert.equal(posts.size, 0);
  });
});

describe('cleanup fallbacks (deleteDraft)', () => {
  browserTest('server blocks the DELETE method → POST + X-HTTP-Method-Override deletes it', async () => {
    scenario.blockDeleteMethod = true;
    const out = await roundTrip();
    assert.equal(out.cleanup.deleted, true, out.cleanup.log.join('; '));
    assert.ok(out.cleanup.log.includes('DELETE: HTTP 405'));
    assert.ok(out.cleanup.log.includes('POST+override: HTTP 200'));
  });

  browserTest('session gone before cleanup → logs in again through the request API, then deletes', async () => {
    scenario.expireSessionAtCleanup = true;
    const out = await roundTrip();
    assert.equal(out.cleanup.deleted, true, out.cleanup.log.join('; '));
    assert.match(out.cleanup.log.join('; '), /rest-nonce: HTTP 200, answer "0".*re-login/);
    assertNoSecrets(out);
  });

  browserTest('REST rejects the nonce (rest_cookie_invalid_nonce) → one fresh login, new nonce, deleted', async () => {
    scenario.rejectFirstNonce = true;
    const out = await roundTrip();
    assert.equal(out.cleanup.deleted, true, out.cleanup.log.join('; '));
    assert.match(out.cleanup.log.join('; '), /DELETE: HTTP 403 rest_cookie_invalid_nonce; re-login: HTTP 200/);
    assertNoSecrets(out);
  });

  browserTest('post only went to the trash → deleted on the next attempt', async () => {
    scenario.trashFirst = true;
    const out = await roundTrip();
    assert.equal(out.cleanup.deleted, true);
    assert.ok(out.cleanup.log.some((l) => /post status "trash"/.test(l)));
  });

  browserTest('deletion refused → leftover reported with HTTP status and WordPress code, no nonce', async () => {
    scenario.neverDelete = true;
    const out = await roundTrip();
    assert.equal(out.leftover, out.postId);
    assert.equal(out.cleanup.deleted, false);
    assert.ok(out.cleanup.log.includes('DELETE: HTTP 403 rest_cannot_delete'));
    assert.equal(posts.size, 1);
    assertNoSecrets(out);
  });

  browserTest('closed context → leftover with the error, never a throw', async () => {
    const ctx = await browser.newContext();
    await ctx.close();
    const r = await deleteDraft({ request: ctx.request, base, postId: 5, user: USER, pass: PASS });
    assert.equal(r.deleted, false);
    assert.match(r.log.join(' '), /cleanup error/);
  });
});
