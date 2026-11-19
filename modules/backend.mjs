// Backend: REST API (discovery, unauthenticated GET, latency), approval-gated write probes, read-only database
// health and WP-Cron via WP-CLI, PHP error log analysis, PHPUnit (only when it cannot touch the real database).
import fs from 'node:fs';
import path from 'node:path';
import { walkFiles, readText, percentile, median, truncate, parseJsonLoose } from '../lib/util.mjs';
import { redact } from '../lib/redact.mjs';

const CAT = 'backend';
const CORE_NAMESPACES = new Set(['wp/v2', 'oembed/1.0', 'wp-site-health/v1', 'wp-block-editor/v1', 'wp-abilities/v1']);

/* ------------------------------------------------------------------ */
/* Read-only SQL guard                                                 */
/* ------------------------------------------------------------------ */

const FORBIDDEN_SQL = /\b(insert|update|delete|drop|alter|create|replace|truncate|grant|revoke|rename|load|handler|call|do|set|lock|unlock|outfile|dumpfile|sleep|benchmark|into|merge|commit|rollback|savepoint|prepare|execute|deallocate|flush|kill|reset|purge|install|uninstall|shutdown|optimize|repair|analyze|begin|start|release|use)\b/i;

/**
 * Only a single SELECT / SHOW / DESCRIBE / EXPLAIN statement, without comments or data-changing keywords
 * (string literals are ignored for the keyword check). Returns the statement; throws otherwise.
 */
export function readOnlySql(sql) {
  const s = String(sql ?? '').trim().replace(/;\s*$/, '');
  const bare = s.replace(/'(?:[^'\\]|\\.)*'/g, "''").replace(/"(?:[^"\\]|\\.)*"/g, '""').replace(/`[^`]*`/g, '``');
  if (!s) throw new Error('empty SQL');
  if (/--|\/\*|\*\/|#/.test(bare)) throw new Error('SQL comments are not allowed');
  if (bare.includes(';')) throw new Error('only one SQL statement is allowed');
  if (!/^(select|show|describe|desc|explain)\b/i.test(bare)) throw new Error('only SELECT/SHOW/DESCRIBE/EXPLAIN statements are allowed');
  const bad = bare.match(FORBIDDEN_SQL);
  if (bad) throw new Error(`keyword "${bad[1].toUpperCase()}" is not allowed in read-only SQL`);
  return s;
}

const SQL_PHP = "global $wpdb; $q = str_replace('{prefix}', $wpdb->prefix, (string) getenv('WPQA_SQL')); $r = $wpdb->get_results($q, ARRAY_A); if ($wpdb->last_error) { fwrite(STDERR, 'SQL error: ' . $wpdb->last_error); exit(1); } echo wp_json_encode($r);";

/** Run one read-only query through WP-CLI ($wpdb, no plugins/themes loaded). `{prefix}` = table prefix. */
async function sqlRows(run, c, sql) {
  const q = readOnlySql(sql);
  const r = await run.wp(['eval', SQL_PHP], { env: { WPQA_SQL: q }, bare: true, timeoutMs: 120000 });
  const rows = r.code === 0 ? parseJsonLoose(r.stdout) : null;
  if (!Array.isArray(rows)) c.toolError('wp eval (read-only SQL)', r, `query failed or returned no JSON: ${q.slice(0, 120)}`);
  return rows;
}

/* ------------------------------------------------------------------ */
/* REST                                                                */
/* ------------------------------------------------------------------ */

/** Namespaces registered by the project's own code: register_rest_route( 'ns', … ) or a $namespace property. */
export function customNamespaces(files) {
  const ns = new Set();
  for (const f of files) {
    const t = readText(f) || '';
    for (const m of t.matchAll(/register_rest_route\s*\(\s*(['"])([a-z0-9][\w.-]*\/[\w.-]+)\1/gi)) ns.add(m[2]);
    for (const m of t.matchAll(/\$(?:this->)?namespace\s*=\s*(['"])([a-z0-9][\w.-]*\/v\d+[\w.-]*)\1/gi)) ns.add(m[2]);
  }
  return [...ns];
}

/** Classify an unauthenticated GET response. */
export function classifyRestResponse(r) {
  if (!r.ok) return { kind: 'unreachable', detail: r.error };
  if (r.status >= 500) return { kind: 'server-error' };
  if (r.status === 401 || r.status === 403) return { kind: 'auth-required' };
  if (r.status === 400) return { kind: 'rejected' };
  if (r.status === 404) return { kind: 'not-found' };
  if (r.status >= 200 && r.status < 300) {
    const ct = r.headers['content-type'] || '';
    try { JSON.parse(r.text); return { kind: 'public', json: true, contentType: ct }; } catch { return { kind: 'public', json: false, contentType: ct }; }
  }
  return { kind: 'other' };
}

async function restIndex(run) {
  const base = run.cfg.site.url.replace(/\/$/, '');
  let last = null;
  for (const [indexUrl, routeUrl] of [[`${base}/wp-json/`, (r) => `${base}/wp-json${r}`], [`${base}/?rest_route=/`, (r) => `${base}/?rest_route=${encodeURIComponent(r)}`]]) {
    const r = await run.http(indexUrl, { redirect: 'follow', timeoutMs: 30000, maxBody: 30 * 1024 * 1024 });
    last = r;
    if (r.ok && r.status === 200) {
      try {
        const j = JSON.parse(r.text);
        if (j && typeof j.routes === 'object') return { indexUrl, routeUrl, index: j };
      } catch { /* try the next form */ }
    }
  }
  return { error: last?.error || `HTTP ${last?.status}`, raw: last };
}

function withQuery(url, query) {
  if (!query || !Object.keys(query).length) return url;
  const u = new URL(url);
  for (const [k, v] of Object.entries(query)) u.searchParams.set(k, String(v));
  return u.toString();
}

/* ------------------------------------------------------------------ */
/* PHP error log                                                       */
/* ------------------------------------------------------------------ */

const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };

function logClass(msg) {
  if (/PHP (?:Fatal error|Parse error|Recoverable fatal error)|Uncaught /i.test(msg)) return 'fatal';
  if (/PHP Warning/i.test(msg)) return 'warning';
  if (/PHP Deprecated/i.test(msg)) return 'deprecated';
  if (/PHP Notice/i.test(msg)) return 'notice';
  return 'other';
}

/**
 * Parse debug.log text into grouped entries.
 * @returns {{groups: object[], total: number, inWindow: number, byClass: object}}
 */
export function parseDebugLog(text, { since = 0 } = {}) {
  const entries = [];
  let cur = null;
  for (const line of String(text).split(/\r?\n/)) {
    const m = line.match(/^\[(\d{2})-([A-Za-z]{3})-(\d{4}) (\d{2}):(\d{2}):(\d{2})(?: ([^\]]+))?\] (.*)$/);
    if (m) {
      if (cur) entries.push(cur);
      const t = Date.UTC(+m[3], MONTHS[m[2].toLowerCase()] ?? 0, +m[1], +m[4], +m[5], +m[6]);
      cur = { t, msg: m[8] };
    } else if (cur && line.trim()) cur.more = (cur.more || 0) + 1;
  }
  if (cur) entries.push(cur);
  const groups = new Map();
  const byClass = { fatal: 0, warning: 0, deprecated: 0, notice: 0, other: 0 };
  let inWindow = 0;
  for (const e of entries) {
    if (e.t < since) continue;
    inWindow++;
    const cls = logClass(e.msg);
    byClass[cls]++;
    const loc = e.msg.match(/ in (.+?)(?: on line |:)(\d+)\b/);
    const file = loc ? loc[1].trim() : null;
    const line = loc ? +loc[2] : null;
    const norm = e.msg
      .replace(/^PHP [A-Za-z ]+?:\s+/, '')
      .replace(/ in .+?(?: on line |:)\d+\b.*$/, '')
      .replace(/0x[0-9a-f]+/gi, 'H')
      .replace(/\d+/g, 'N')
      .replace(/\s+/g, ' ')
      .trim();
    const key = `${cls}|${norm}|${file}|${line}`;
    const g = groups.get(key) || { cls, message: norm, sample: e.msg, file, line, count: 0, first: e.t, last: e.t };
    g.count++;
    g.first = Math.min(g.first, e.t);
    g.last = Math.max(g.last, e.t);
    groups.set(key, g);
  }
  return { groups: [...groups.values()].sort((a, b) => b.count - a.count), total: entries.length, inWindow, byClass };
}

/** Who owns a file: custom code, a third-party plugin/theme, or WordPress core. */
function origin(file, cfg) {
  if (!file) return { kind: 'unknown', label: 'unknown location' };
  const f = file.split('\\').join('/');
  const p = f.match(/wp-content\/plugins\/([^/]+)/);
  const t = f.match(/wp-content\/themes\/([^/]+)/);
  if (p) return cfg.scan.plugins.includes(p[1]) ? { kind: 'custom', label: `plugin ${p[1]} (yours)` } : { kind: 'third-party', label: `plugin ${p[1]}` };
  if (t) return cfg.scan.themes.includes(t[1]) ? { kind: 'custom', label: `theme ${t[1]} (yours)` } : { kind: 'third-party', label: `theme ${t[1]}` };
  if (/wp-content\/mu-plugins\//.test(f)) return { kind: 'custom', label: 'mu-plugin' };
  if (/\/(wp-includes|wp-admin)\//.test(f)) return { kind: 'core', label: 'WordPress core' };
  return { kind: 'unknown', label: 'other code' };
}

/** Severity: fatal → high; warning → medium; notice/deprecated → low. Third-party and core noise is one step lower. */
export function logSeverity(cls, kind) {
  const base = { fatal: 'high', warning: 'medium', deprecated: 'low', notice: 'low', other: 'info' }[cls];
  if (cls === 'fatal' || kind === 'custom' || kind === 'unknown') return base;
  return { medium: 'low', low: 'info', info: 'info' }[base] || base;
}

/** Map a log path (as PHP wrote it, maybe from another machine) to a file in this WordPress tree. */
function localPath(file, wpRoot) {
  if (!file) return null;
  const f = file.split('\\').join('/');
  const i = f.search(/\/(wp-content|wp-includes|wp-admin)\//);
  if (i >= 0) return path.join(wpRoot, f.slice(i + 1));
  return fs.existsSync(file) ? file : null;
}

/* ------------------------------------------------------------------ */
/* PHPUnit                                                             */
/* ------------------------------------------------------------------ */

/** DB_NAME the WordPress PHPUnit suite will use, from wp-tests-config.php or phpunit.xml <env/const>. */
export function testDbName(dir) {
  for (const f of ['wp-tests-config.php', 'tests/wp-tests-config.php', 'tests/phpunit/wp-tests-config.php']) {
    const t = readText(path.join(dir, f));
    const m = t && t.match(/define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]+)['"]/);
    if (m) return { name: m[1], source: f };
  }
  for (const f of ['phpunit.xml', 'phpunit.xml.dist']) {
    const t = readText(path.join(dir, f));
    const m = t && t.match(/<(?:env|const)\s+name=["'](?:WP_TESTS_DB_NAME|DB_NAME)["']\s+value=["']([^"']+)["']/);
    if (m) return { name: m[1], source: f };
  }
  return null;
}

/** JUnit XML → { tests, failures, errors, skipped, failed: [{name, message}] }. */
export function parseJunit(xml) {
  const out = { tests: 0, failures: 0, errors: 0, skipped: 0, failed: [] };
  const top = String(xml).match(/<testsuite\b[^>]*>/);
  const attr = (tag, a) => Number((tag.match(new RegExp(`\\b${a}="(\\d+)"`)) || [])[1] || 0);
  if (top) for (const a of ['tests', 'failures', 'errors', 'skipped']) out[a] = attr(top[0], a);
  for (const m of String(xml).matchAll(/<testcase\b([^>]*?)(?:\/>|>([\s\S]*?)<\/testcase>)/g)) {
    const body = m[2] || '';
    const f = body.match(/<(failure|error)\b([^>]*)>([\s\S]*?)<\/\1>|<(failure|error)\b([^>]*)\/>/);
    if (f) {
      const name = (m[1].match(/\bname="([^"]+)"/) || [])[1] || '?';
      const cls = (m[1].match(/\bclass="([^"]+)"/) || [])[1] || '';
      const attrs = f[2] ?? f[5] ?? '';
      const message = (attrs.match(/\bmessage="([^"]*)"/) || [])[1] || f[3] || '';
      out.failed.push({ name: cls ? `${cls}::${name}` : name, kind: f[1] || f[4], message: message.trim() });
    }
  }
  return out;
}

/* ------------------------------------------------------------------ */

export default async function backend(run) {
  const { cfg } = run;
  const B = cfg.backend;
  const local = cfg.site.environment === 'local';
  const state = (run.state ||= {});

  await run.check({ id: 'backend.rest', title: 'REST API: custom routes, unauthenticated GET', category: CAT, tool: 'fetch', requires: { url: true } }, async (c) => {
    const ns = new Set([...customNamespaces(run.customFiles((d) => walkFiles(d, { exts: ['.php'] }))), ...(Array.isArray(B.restNamespaces) ? B.restNamespaces : [])]);
    const idx = await restIndex(run);
    if (!idx.index) {
      c.toolError('REST index', { command: `GET ${cfg.site.url}/wp-json/`, code: idx.raw?.status, stdout: truncate(idx.raw?.text || '', 4000), stderr: idx.error || '' }, 'did not return the REST index (is the REST API disabled or blocked for anonymous users?)');
    }
    const routes = Object.entries(idx.index.routes || {});
    const allNs = idx.index.namespaces || [];
    const thirdParty = allNs.filter((n) => !CORE_NAMESPACES.has(n) && !ns.has(n));
    if (thirdParty.length) c.note(`other namespaces (core add-ons / third-party plugins, not probed): ${thirdParty.join(', ')}`);
    // Custom routes, without the namespace index route itself ("/myns/v1").
    const own = routes.filter(([route, r]) => r && ns.has(r.namespace) && route !== `/${r.namespace}`);
    if (!ns.size) return c.notApplicable('your code registers no REST namespaces (register_rest_route not found in scan.themes/scan.plugins)');
    if (!own.length) return c.notApplicable(`namespaces ${[...ns].join(', ')} found in your code, but none are registered on the site`);
    const probed = [];
    const results = [];
    const writeRoutes = [];
    for (const [route, r] of own) {
      const methods = [...new Set((r.endpoints || []).flatMap((e) => e.methods || []))];
      const writes = methods.filter((m) => m !== 'GET' && m !== 'HEAD' && m !== 'OPTIONS');
      if (writes.length) writeRoutes.push(`${writes.join('/')} ${route}`);
      const getEp = (r.endpoints || []).find((e) => (e.methods || []).includes('GET'));
      if (!getEp) continue;
      const ex = B.restExamples?.[route] || null;
      const required = Object.entries(getEp.args || {}).filter(([, a]) => a?.required).map(([k]) => k);
      if (/\(\?P</.test(route) && !ex?.path) { results.push({ route, kind: 'not-probed', why: 'route has path parameters — add backend.restExamples' }); continue; }
      if (required.length && !ex) { results.push({ route, kind: 'not-probed', why: `required args ${required.join(', ')} — add backend.restExamples` }); continue; }
      const url = withQuery(idx.routeUrl(ex?.path || route), ex?.query);
      probed.push(url);
      const resp = await run.http(url, { redirect: 'follow', timeoutMs: 20000 });
      const k = classifyRestResponse(resp);
      results.push({ route, url, status: resp.status, ...k });
      if (k.kind === 'public' && !k.json) c.finding({ severity: 'medium', rule: 'rest.invalid-json', title: `GET ${route} returns ${resp.status} but the body is not valid JSON`, url, evidence: redact(truncate(resp.text, 300)), recommendation: 'Something prints output before the REST response (PHP notices, echo, BOM). Check the PHP error log and the route callback.' });
      else if (k.kind === 'public') {
        c.finding({ severity: 'info', rule: 'rest.public', title: `Public REST endpoint: GET ${route} (answers without login — confirm the data is meant to be public)`, url, recommendation: 'Public is fine for catalogue/content data. If it returns personal or internal data, add a permission_callback that checks capabilities.' });
        (state.restPublic ||= []).push({ route, url });
      } else if (k.kind === 'server-error') c.finding({ severity: 'medium', rule: 'rest.server-error', title: `GET ${route} fails with HTTP ${resp.status}`, url, evidence: redact(truncate(resp.text, 300)), recommendation: 'Check the PHP error log for the fatal error behind this response.' });
      else if (k.kind === 'unreachable') c.finding({ severity: 'low', rule: 'rest.unreachable', title: `GET ${route}: no response (${k.detail})`, url });
    }
    c.scope(probed.length ? probed : [idx.indexUrl]);
    const n = (kind) => results.filter((x) => x.kind === kind).length;
    c.note(`${own.length} custom route(s) in ${[...ns].join(', ')}: ${n('public')} public GET, ${n('auth-required')} need login, ${n('rejected')} rejected without arguments (400), ${n('not-probed')} not probed${writeRoutes.length ? `; write routes (never called here): ${writeRoutes.join(', ')}` : ''}`);
    for (const x of results.filter((r) => r.kind === 'not-probed')) c.note(`not probed: ${x.route} (${x.why})`);
    c.stats = { routes: results, writeRoutes };
  });

  await run.check({ id: 'backend.rest-latency', title: 'REST API response time (p95)', category: CAT, tool: 'fetch', requires: { url: true } }, async (c) => {
    const pub = state.restPublic || [];
    if (!pub.length) return c.notApplicable('no public custom GET routes to time (routes that need parameters: add backend.restExamples)');
    const samples = Math.max(3, Math.min(50, B.restSamples || 10));
    c.scope(pub.map((p) => p.url));
    for (const p of pub) {
      await run.http(p.url, { timeoutMs: 30000, readBody: false }); // warm-up (not counted)
      const times = [];
      let errors = 0;
      for (let i = 0; i < samples; i++) {
        const r = await run.http(p.url, { timeoutMs: 30000, readBody: false });
        if (r.ok && r.status < 500) times.push(r.totalMs ?? r.ttfbMs ?? 0); else errors++;
      }
      if (!times.length) { c.finding({ severity: 'medium', rule: 'rest.latency-errors', title: `GET ${p.route}: all ${samples} timing requests failed`, url: p.url }); continue; }
      const p95 = Math.round(percentile(times, 95));
      const p50 = Math.round(median(times));
      c.note(`${p.route}: p50 ${p50} ms, p95 ${p95} ms over ${times.length} requests${errors ? `, ${errors} errors` : ''}${local ? ' (local lab measurement)' : ''}`);
      if (p95 > B.restP95Ms) c.finding({ severity: 'medium', rule: 'rest.slow', title: `GET ${p.route} p95 ${p95} ms (target < ${B.restP95Ms} ms)${local ? ' — local machine, not production' : ''}`, url: p.url, evidence: `p50 ${p50} ms, p95 ${p95} ms, ${times.length} samples`, recommendation: 'Cache the response (transients/object cache), avoid unbounded queries, and check slow plugins hooked into REST requests.' });
    }
  });

  await run.check({ id: 'backend.write-probes', title: 'Unauthenticated write probes (configured routes only)', category: CAT, tool: 'fetch', requires: { url: true } }, async (c) => {
    const eps = cfg.safety.allowedWriteEndpoints || [];
    if (!eps.length) return c.notApplicable('no routes listed in safety.allowedWriteEndpoints (write probes only call routes you list)');
    const base = cfg.site.url.replace(/\/$/, '');
    if (!(await c.requireApproval('write-probe', base + '/'))) return;
    const probed = [];
    for (const ep of eps) {
      const method = String(ep.method || 'POST').toUpperCase();
      if (!['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) || !ep.route) { c.note(`ignored invalid entry: ${JSON.stringify(ep).slice(0, 120)}`); continue; }
      const url = `${base}/wp-json${ep.route.startsWith('/') ? ep.route : '/' + ep.route}`;
      probed.push(url);
      const body = ep.body === undefined ? undefined : JSON.stringify(ep.body).replaceAll('{{runId}}', run.runId);
      const r = await run.http(url, { method, headers: { 'content-type': 'application/json' }, body, timeoutMs: 20000 });
      if (!r.ok) { c.note(`${method} ${ep.route}: no response (${r.error})`); continue; }
      if (r.status >= 200 && r.status < 300) {
        c.finding({ severity: 'high', rule: 'rest.unauth-write', title: `${method} ${ep.route} accepted an unauthenticated request (HTTP ${r.status})`, url, evidence: redact(truncate(r.text, 300)), recommendation: 'Add a permission_callback that checks a capability (or, for public forms, a nonce plus rate limiting) and validate every argument.' });
        if (ep.cleanup?.wpcli?.length) {
          const cl = await run.wp(ep.cleanup.wpcli.map((a) => String(a).replaceAll('{{runId}}', run.runId)));
          if (cl.code !== 0) c.finding({ severity: 'high', rule: 'rest.probe-cleanup', title: `Cleanup after ${method} ${ep.route} failed — remove the test data by hand`, evidence: redact(truncate(cl.stderr || cl.stdout, 400)) });
          else c.note(`cleanup for ${ep.route} ran`);
        } else c.note(`${ep.route}: no cleanup configured — check for test data containing "${run.runId}"`);
      } else c.note(`${method} ${ep.route}: refused with HTTP ${r.status} (expected)`);
    }
    c.scope(probed);
  });

  await run.check({ id: 'backend.db-health', title: 'Database health (read-only SQL)', category: CAT, tool: 'WP-CLI', requires: { wpcli: 'db' } }, async (c) => {
    const [auto] = await sqlRows(run, c, "SELECT COUNT(*) AS n, COALESCE(SUM(LENGTH(option_value)),0) AS bytes FROM {prefix}options WHERE autoload IN ('yes','on','auto-on','auto')");
    const kb = Math.round(Number(auto.bytes) / 1024);
    const top = await sqlRows(run, c, "SELECT option_name, LENGTH(option_value) AS bytes FROM {prefix}options WHERE autoload IN ('yes','on','auto-on','auto') ORDER BY bytes DESC LIMIT 10");
    const topTxt = top.map((o) => `${o.option_name}: ${Math.round(o.bytes / 1024)} KB`).join('\n');
    if (kb >= B.autoloadKbHigh) c.finding({ severity: 'high', rule: 'db.autoload', title: `Autoloaded options total ${kb} KB (loaded on every request; limit ${B.autoloadKbHigh} KB)`, evidence: topTxt, recommendation: 'Set autoload = off for large options that are not needed on every page (often left by removed plugins), or delete orphaned ones after checking.' });
    else if (kb >= B.autoloadKbWarn) c.finding({ severity: 'medium', rule: 'db.autoload', title: `Autoloaded options total ${kb} KB (warning above ${B.autoloadKbWarn} KB)`, evidence: topTxt, recommendation: 'Review the largest autoloaded options listed in the evidence.' });
    const [tr] = await sqlRows(run, c, "SELECT COUNT(*) AS n FROM {prefix}options WHERE (option_name LIKE '\\_transient\\_timeout\\_%' OR option_name LIKE '\\_site\\_transient\\_timeout\\_%') AND option_value < UNIX_TIMESTAMP()");
    const expired = Number(tr.n);
    if (expired >= B.transientsWarn) c.finding({ severity: 'low', rule: 'db.expired-transients', title: `${expired} expired transients still in the options table`, recommendation: 'WordPress removes them over time; a large number can mean cron does not run. "wp transient delete --expired" cleans them (a write — only with approval).' });
    const [rev] = await sqlRows(run, c, "SELECT COUNT(*) AS n FROM {prefix}posts WHERE post_type = 'revision'");
    const heavy = await sqlRows(run, c, `SELECT post_parent, COUNT(*) AS n FROM {prefix}posts WHERE post_type = 'revision' GROUP BY post_parent HAVING n > ${Number(B.revisionsWarn) | 0} ORDER BY n DESC LIMIT 10`);
    if (heavy.length) c.finding({ severity: 'low', rule: 'db.revisions', title: `${heavy.length} post(s) have more than ${B.revisionsWarn} revisions (${rev.n} revisions in total)`, evidence: heavy.map((h) => `post ${h.post_parent}: ${h.n} revisions`).join('\n'), recommendation: "Limit revisions with define( 'WP_POST_REVISIONS', 10 ); old ones can be cleaned up after a backup." });
    const engines = await sqlRows(run, c, "SELECT TABLE_NAME AS t, ENGINE AS e FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME LIKE '{prefix}%' AND ENGINE <> 'InnoDB'");
    if (engines.length) c.finding({ severity: 'low', rule: 'db.engine', title: `${engines.length} table(s) not using InnoDB`, evidence: engines.map((x) => `${x.t}: ${x.e}`).join('\n'), recommendation: 'Convert to InnoDB (row-level locking, crash safety) after a backup.' });
    c.stats = { autoloadKb: kb, autoloadCount: Number(auto.n), expiredTransients: expired, revisions: Number(rev.n) };
    c.note(`autoload ${kb} KB in ${auto.n} options; ${expired} expired transients; ${rev.n} revisions`);
  });

  await run.check({ id: 'backend.cron', title: 'WP-Cron: overdue events', category: CAT, tool: 'WP-CLI', requires: { wpcli: 'db' } }, async (c) => {
    const r = await run.wp(['cron', 'event', 'list', '--format=json', '--fields=hook,next_run_gmt,recurrence'], { bare: true });
    const events = r.code === 0 ? parseJsonLoose(r.stdout) : null;
    if (!Array.isArray(events)) c.toolError('wp cron event list', r, 'returned no JSON');
    const now = Date.now();
    const overdue = events.filter((e) => {
      const t = Date.parse(String(e.next_run_gmt).replace(' ', 'T') + 'Z');
      return Number.isFinite(t) && now - t > B.cronOverdueMin * 60000;
    });
    const disabled = run.facts.wpConfig?.DISABLE_WP_CRON === true;
    c.stats = { events: events.length, overdue: overdue.length, disabled };
    if (overdue.length) {
      c.finding({
        severity: local ? 'low' : 'medium', rule: 'cron.overdue',
        title: `${overdue.length} of ${events.length} WP-Cron event(s) overdue by more than ${B.cronOverdueMin} min${local ? ' (local site: WP-Cron only runs when pages are visited)' : ''}`,
        evidence: overdue.slice(0, 15).map((e) => `${e.hook} (due ${e.next_run_gmt} GMT, ${e.recurrence})`).join('\n'),
        recommendation: disabled ? 'DISABLE_WP_CRON is set: make sure a real system cron calls wp-cron.php (or "wp cron event run --due-now") every few minutes.' : 'On low-traffic sites set DISABLE_WP_CRON and run a system cron every 5 minutes; check for events that fail every time.',
      });
    }
    c.note(`${events.length} scheduled events, ${overdue.length} overdue${disabled ? '; DISABLE_WP_CRON is set' : ''}`);
  });

  await run.check({ id: 'backend.php-log', title: 'PHP error log (debug.log)', category: CAT, tool: 'wpqa' }, async (c) => {
    const setting = run.facts.wpConfig?.WP_DEBUG_LOG;
    const logPath = typeof setting === 'string' && setting && !/^(true|false|1|0)$/i.test(setting) ? path.resolve(cfg._wpRoot, setting) : path.join(cfg._wpRoot, 'wp-content', 'debug.log');
    let st;
    try { st = fs.statSync(logPath); } catch { return c.notApplicable(`no PHP error log at ${path.relative(cfg._root, logPath)}${setting ? '' : ' (WP_DEBUG_LOG is off)'}`); }
    c.scope([logPath]);
    const maxBytes = Math.max(1, B.debugLogMaxMb || 20) * 1024 * 1024;
    const start = Math.max(0, st.size - maxBytes);
    const fd = fs.openSync(logPath, 'r');
    const buf = Buffer.alloc(st.size - start);
    fs.readSync(fd, buf, 0, buf.length, start);
    fs.closeSync(fd);
    let text = buf.toString('utf8');
    if (start > 0) { text = text.slice(text.indexOf('\n') + 1); c.note(`log is ${Math.round(st.size / 1048576)} MB; analysed the last ${B.debugLogMaxMb} MB`); }
    const since = Date.now() - (B.debugLogDays || 7) * 864e5;
    const res = parseDebugLog(text, { since });
    c.stats = { totalEntries: res.total, inWindow: res.inWindow, byClass: res.byClass, groups: res.groups.length };
    c.note(`last ${B.debugLogDays} days: ${res.inWindow} entries — ${res.byClass.fatal} fatal, ${res.byClass.warning} warnings, ${res.byClass.deprecated} deprecations, ${res.byClass.notice} notices (${res.groups.length} distinct messages)`);
    for (const g of res.groups) {
      const o = origin(g.file, cfg);
      const severity = logSeverity(g.cls, o.kind);
      const lp = localPath(g.file, cfg._wpRoot);
      c.finding({
        severity, rule: `php-log.${g.cls}${o.kind === 'custom' ? '' : '.' + o.kind}`, title: `PHP ${g.cls} (${g.count}× in ${B.debugLogDays} days) in ${o.label}: ${truncate(redact(g.message), 140)}`,
        file: lp && fs.existsSync(lp) ? lp : null, line: lp && fs.existsSync(lp) ? g.line : null,
        component: o.label,
        fingerprintExtra: `${g.cls}:${g.message}:${g.file ? g.file.split(/[\\/]wp-content[\\/]|[\\/]wp-includes[\\/]|[\\/]wp-admin[\\/]/).pop() : ''}:${g.line}`,
        evidence: `${g.count} occurrence(s), first ${new Date(g.first).toISOString()}, last ${new Date(g.last).toISOString()}\n${redact(truncate(g.sample, 600))}`,
        recommendation: o.kind === 'custom' ? 'Fix it in your code — the log points to the file and line.' : o.kind === 'core' ? 'Usually caused by a plugin/theme passing bad data to core; check the stack trace.' : `Update ${o.label} or report it to its author; it is not your code.`,
        // Your own code is listed message by message; third-party/core noise is grouped per class.
        aggregate: o.kind !== 'custom' && (severity === 'info' || severity === 'low'),
      });
    }
  });

  await run.check({ id: 'backend.phpunit', title: 'PHPUnit (project tests, never against the real database)', category: CAT, tool: 'phpunit' }, async (c) => {
    const suites = run.customDirs.filter((d) => ['phpunit.xml', 'phpunit.xml.dist'].some((f) => fs.existsSync(path.join(d.dir, f))));
    if (!suites.length) return c.notApplicable('no phpunit.xml(.dist) in your themes/plugins');
    if (!B.phpunit?.enabled) return c.skip(`PHPUnit config found in ${suites.map((s) => s.slug).join(', ')} but backend.phpunit.enabled is false`, 'Set backend.phpunit.enabled = true once the tests use their own test database.');
    if (cfg.site.environment === 'production') return c.skip('refusing to run PHPUnit on a production environment');
    const siteDb = run.facts.wpConfig?.DB_NAME;
    const scope = [];
    for (const s of suites) {
      const bin = ['vendor/bin/phpunit', 'vendor/phpunit/phpunit/phpunit'].map((p) => path.join(s.dir, p)).find((p) => fs.existsSync(p));
      if (!bin) { c.note(`${s.slug}: no vendor/bin/phpunit (run "composer install" in that folder yourself)`); continue; }
      const db = testDbName(s.dir);
      if (!db) { c.note(`${s.slug}: cannot find the test DB name (wp-tests-config.php or WP_TESTS_DB_NAME) — not run`); continue; }
      if (!siteDb || db.name === siteDb) { c.note(`${s.slug}: test DB "${db.name}" (${db.source}) ${siteDb ? 'is the real site database' : 'cannot be compared (site DB_NAME unknown)'} — refusing to run`); continue; }
      const junit = path.join(run.artifactDir('backend.phpunit'), `${s.slug}-junit.xml`);
      const r = await run.php([bin, '--log-junit', junit], { cwd: s.dir, timeoutMs: 20 * 60 * 1000 });
      scope.push(s.dir);
      if (!fs.existsSync(junit)) c.toolError(`PHPUnit (${s.slug})`, r, 'produced no JUnit report');
      c.artifact(junit, `${s.slug} JUnit`);
      const j = parseJunit(fs.readFileSync(junit, 'utf8'));
      c.note(`${s.slug}: ${j.tests} tests, ${j.failures} failures, ${j.errors} errors, ${j.skipped} skipped (test DB ${db.name})`);
      for (const f of j.failed) c.finding({ severity: 'medium', rule: `phpunit.${f.kind}`, title: `PHPUnit ${f.kind}: ${f.name}`, component: s.slug, evidence: redact(truncate(f.message, 800)), recommendation: 'Fix the code or the test; re-run the suite.' });
    }
    if (!scope.length) return c.skip('no suite could run safely (see notes)', 'Each suite needs vendor/bin/phpunit and a test database different from the site database.');
    c.scope(scope);
  });
}
