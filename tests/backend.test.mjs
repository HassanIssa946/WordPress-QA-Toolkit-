// Backend module: REST discovery and classification, latency, write-probe gate, read-only SQL, DB health,
// WP-Cron, debug.log grouping and redaction, PHPUnit safety. WP-CLI and HTTP are replaced with recorded data.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import backend, { readOnlySql, customNamespaces, parseDebugLog, logSeverity, testDbName, parseJunit } from '../modules/backend.mjs';
import { makeRun, tempDir, fixturePlugin } from './helpers.mjs';

/* ---------------- helpers ---------------- */

/** Recorded REST index: two custom namespaces (sf/v1 from safe-plugin, vf/v1 from vuln-plugin) + core + third party. */
const INDEX = {
  namespaces: ['wp/v2', 'oembed/1.0', 'yoast/v1', 'sf/v1', 'vf/v1'],
  routes: {
    '/': { namespace: '', endpoints: [{ methods: ['GET'] }] },
    '/wp/v2/posts': { namespace: 'wp/v2', endpoints: [{ methods: ['GET'] }] },
    '/yoast/v1/meta': { namespace: 'yoast/v1', endpoints: [{ methods: ['GET'] }] },
    '/sf/v1': { namespace: 'sf/v1', endpoints: [{ methods: ['GET'] }] },
    '/sf/v1/contact': { namespace: 'sf/v1', endpoints: [{ methods: ['POST'], args: { name: { required: true } } }] },
    '/sf/v1/items': { namespace: 'sf/v1', endpoints: [{ methods: ['GET'], args: { page: { required: false } } }] },
    '/sf/v1/private': { namespace: 'sf/v1', endpoints: [{ methods: ['GET'] }] },
    '/sf/v1/needs-arg': { namespace: 'sf/v1', endpoints: [{ methods: ['GET'], args: { brand: { required: true } } }] },
    '/sf/v1/item/(?P<id>\\d+)': { namespace: 'sf/v1', endpoints: [{ methods: ['GET'] }] },
    '/vf/v1/broken': { namespace: 'vf/v1', endpoints: [{ methods: ['GET'] }] },
    '/vf/v1/notjson': { namespace: 'vf/v1', endpoints: [{ methods: ['GET'] }] },
  },
};
const res = (status, text = '', extra = {}) => ({ ok: true, status, headers: { 'content-type': 'application/json' }, text, url: 'x', totalMs: 50, ...extra });

/** A run with WP-CLI/DB/site reachability faked and HTTP served from `routes` (path → response or fn). */
function fakeRun({ config = {}, flags = {}, routes = {}, wp = null, only }) {
  const run = makeRun({ config: { site: { url: 'http://fixture.local', environment: 'local' }, ...config }, mode: 'backend', flags: { ...flags, only } });
  run.siteReachable = async () => ({ ok: true, status: 200 });
  run.wpCli = async () => ({ ok: true, db: true, siteurl: 'http://fixture.local' });
  run.resolve = async (h) => (h === 'fixture.local' ? ['127.0.0.1'] : []);
  const calls = [];
  run.http = async (url, opts = {}) => {
    calls.push({ url, method: opts.method || 'GET' });
    const u = new URL(url);
    const key = `${opts.method || 'GET'} ${u.pathname}${u.search}`;
    const r = routes[key] ?? routes[`${opts.method || 'GET'} ${u.pathname}`];
    if (typeof r === 'function') return r(url, opts);
    return r || res(404, '{"code":"rest_no_route"}');
  };
  run.wp = wp || (async () => ({ code: 1, stdout: '', stderr: 'not faked' }));
  return { run, calls };
}

/* ---------------- read-only SQL ---------------- */

describe('readOnlySql', () => {
  test('allows single SELECT/SHOW/DESCRIBE/EXPLAIN, including keywords inside string literals', () => {
    for (const ok of ["SELECT COUNT(*) FROM {prefix}options WHERE autoload IN ('yes','on')", 'SHOW TABLES', 'DESCRIBE wp_posts', "select 'drop table x' as s;", 'EXPLAIN SELECT 1'])
      assert.doesNotThrow(() => readOnlySql(ok), ok);
  });
  test('rejects writes, multiple statements, comments and tricks', () => {
    const bad = [
      'DELETE FROM wp_options', 'UPDATE wp_options SET x=1', 'DROP TABLE wp_posts', 'INSERT INTO t VALUES(1)',
      'SELECT 1; DROP TABLE wp_users', 'SELECT 1 -- x', 'SELECT 1 /* x */', 'SELECT 1 # x',
      'SELECT * INTO OUTFILE \'/tmp/x\' FROM wp_users', 'SELECT SLEEP(10)', 'SELECT BENCHMARK(1000000, MD5(1))',
      'SET autocommit=0', 'LOCK TABLES wp_posts READ', 'TRUNCATE wp_options', 'REPLACE INTO t VALUES (1)', 'CALL p()',
      'WITH x AS (SELECT 1) DELETE FROM t', '', 'GRANT ALL ON *.* TO x',
    ];
    for (const b of bad) assert.throws(() => readOnlySql(b), undefined, b);
  });
});

/* ---------------- REST ---------------- */

describe('backend.rest', () => {
  test('custom namespaces are found in the project code (multi-line register_rest_route)', () => {
    const ns = customNamespaces([path.join(fixturePlugin('safe-plugin'), 'includes', 'rest.php'), path.join(fixturePlugin('vuln-plugin'), 'includes', 'rest-closure.php')]);
    assert.deepEqual(ns.sort(), ['sf/v1', 'vf/v1']);
  });

  test('detects: invalid JSON, server error; public = info only; never calls write routes or third-party routes', async () => {
    const { run, calls } = fakeRun({
      config: { scan: { plugins: ['safe-plugin', 'vuln-plugin'] } },
      only: ['backend.rest'],
      routes: {
        'GET /wp-json/': res(200, JSON.stringify(INDEX)),
        'GET /wp-json/sf/v1/items': res(200, '[{"id":1}]'),
        'GET /wp-json/sf/v1/private': res(401, '{"code":"rest_forbidden"}'),
        'GET /wp-json/vf/v1/broken': res(500, '{"code":"internal_server_error"}'),
        'GET /wp-json/vf/v1/notjson': res(200, '<br /><b>Warning</b>: x {"ok":1}'),
      },
    });
    await backend(run);
    const rules = run.findings.map((f) => `${f.severity}:${f.rule}`).sort();
    assert.deepEqual(rules, ['info:rest.public', 'medium:rest.invalid-json', 'medium:rest.server-error']);
    assert.ok(!calls.some((c) => c.method !== 'GET'), 'only GET requests');
    assert.ok(!calls.some((c) => /yoast|wp\/v2|contact|needs-arg|item\//.test(c.url)), 'no third-party, core, write or parameterised routes');
    const rec = run.checks.find((c) => c.id === 'backend.rest');
    assert.match(rec.notes.join('\n'), /POST \/sf\/v1\/contact/);
    assert.match(rec.notes.join('\n'), /not probed: \/sf\/v1\/needs-arg \(required args brand/);
  });

  test('clean: custom routes that need login → zero findings, check passes', async () => {
    const idx = { namespaces: ['sf/v1'], routes: { '/sf/v1/private': { namespace: 'sf/v1', endpoints: [{ methods: ['GET'] }] } } };
    const { run } = fakeRun({ config: { scan: { plugins: ['safe-plugin'] } }, only: ['backend.rest'], routes: { 'GET /wp-json/': res(200, JSON.stringify(idx)), 'GET /wp-json/sf/v1/private': res(403, '{}') } });
    await backend(run);
    assert.equal(run.findings.length, 0);
    assert.equal(run.checks[0].status, 'passed');
  });

  test('REST index unavailable → error with raw artifact, never passed', async () => {
    const { run } = fakeRun({ config: { scan: { plugins: ['safe-plugin'] } }, only: ['backend.rest'], routes: { 'GET /wp-json/': res(403, 'blocked'), 'GET /': res(403, 'blocked') } });
    await backend(run);
    assert.equal(run.checks[0].status, 'error');
    assert.equal(run.checks[0].artifacts.length, 1);
  });

  test('no custom namespaces → not applicable', async () => {
    const { run } = fakeRun({ only: ['backend.rest'], routes: { 'GET /wp-json/': res(200, JSON.stringify(INDEX)) } });
    await backend(run);
    assert.equal(run.checks[0].status, 'not_applicable');
  });
});

describe('backend.rest-latency', () => {
  const idx = { namespaces: ['sf/v1'], routes: { '/sf/v1/items': { namespace: 'sf/v1', endpoints: [{ methods: ['GET'] }] } } };
  const go = async (ms) => {
    const { run } = fakeRun({ config: { scan: { plugins: ['safe-plugin'] }, backend: { restSamples: 5, restP95Ms: 800 } }, only: ['backend.rest', 'backend.rest-latency'], routes: { 'GET /wp-json/': res(200, JSON.stringify(idx)), 'GET /wp-json/sf/v1/items': res(200, '[]', { totalMs: ms }) } });
    await backend(run);
    return run;
  };
  test('p95 above the threshold → medium, labelled local', async () => {
    const run = await go(1500);
    const f = run.findings.find((x) => x.rule === 'rest.slow');
    assert.equal(f.severity, 'medium');
    assert.match(f.title, /local machine, not production/);
  });
  test('fast route → no latency finding', async () => {
    const run = await go(120);
    assert.equal(run.findings.filter((x) => x.rule === 'rest.slow').length, 0);
    assert.match(run.checks.find((c) => c.id === 'backend.rest-latency').notes[0], /p95 120 ms/);
  });
});

describe('backend.write-probes (approval-gated)', () => {
  const eps = [{ route: '/sf/v1/contact', method: 'POST', body: { name: 'wpqa {{runId}}' } }];
  test('no configured routes → not applicable (nothing is invented)', async () => {
    const { run, calls } = fakeRun({ only: ['backend.write-probes'], flags: { approve: true } });
    await backend(run);
    assert.equal(run.checks[0].status, 'not_applicable');
    assert.equal(calls.length, 0);
  });
  test('without --approve: skipped, waiting for approval, no request sent', async () => {
    const { run, calls } = fakeRun({ config: { safety: { allowedHosts: ['fixture.local'], allowedWriteEndpoints: eps } }, only: ['backend.write-probes'] });
    await backend(run);
    assert.equal(run.checks[0].status, 'skipped');
    assert.equal(run.needsApproval.length, 1);
    assert.equal(calls.length, 0);
  });
  test('host not allowlisted: blocked, no request sent', async () => {
    const { run, calls } = fakeRun({ config: { safety: { allowedHosts: [], allowedWriteEndpoints: eps } }, only: ['backend.write-probes'], flags: { approve: true } });
    await backend(run);
    assert.match(run.checks[0].reason, /blocked/);
    assert.equal(calls.length, 0);
  });
  test('approved: a 2xx to an unauthenticated write is high; 401 is fine', async () => {
    const mk = (status) => fakeRun({ config: { safety: { allowedHosts: ['fixture.local'], allowedWriteEndpoints: eps } }, only: ['backend.write-probes'], flags: { approve: true }, routes: { 'POST /wp-json/sf/v1/contact': res(status, '{}') } });
    const bad = mk(201);
    await backend(bad.run);
    assert.equal(bad.run.findings[0].severity, 'high');
    assert.equal(bad.calls[0].method, 'POST');
    const good = mk(401);
    await backend(good.run);
    assert.equal(good.run.findings.length, 0);
  });
});

/* ---------------- database + cron ---------------- */

/** Fake WP-CLI: answers the read-only SQL by pattern; records every query. */
function fakeWp(answers, { cron = '[]' } = {}) {
  const seen = [];
  const wp = async (args, opts = {}) => {
    if (args[0] === 'cron') return { code: 0, stdout: cron, stderr: '' };
    const sql = opts.env?.WPQA_SQL || '';
    seen.push(sql);
    for (const [re, rows] of answers) if (re.test(sql)) return { code: 0, stdout: JSON.stringify(rows), stderr: '' };
    return { code: 0, stdout: '[]', stderr: '' };
  };
  return { wp, seen };
}

describe('backend.db-health', () => {
  test('unhealthy: big autoload, many expired transients, heavy revisions, MyISAM', async () => {
    const { wp, seen } = fakeWp([
      [/SUM\(LENGTH/, [{ n: 900, bytes: 3 * 1024 * 1024 }]],
      [/ORDER BY bytes/, [{ option_name: 'old_plugin_cache', bytes: 2 * 1024 * 1024 }]],
      [/transient/, [{ n: 5000 }]],
      [/^SELECT COUNT\(\*\) AS n FROM \{prefix\}posts/, [{ n: 900 }]],
      [/GROUP BY post_parent/, [{ post_parent: 12, n: 300 }]],
      [/ENGINE/, [{ t: 'wp_old', e: 'MyISAM' }]],
    ]);
    const { run } = fakeRun({ only: ['backend.db-health'], wp });
    await backend(run);
    assert.deepEqual(run.findings.map((f) => `${f.severity}:${f.rule}`).sort(), ['high:db.autoload', 'low:db.engine', 'low:db.expired-transients', 'low:db.revisions']);
    for (const q of seen) assert.match(q, /^(SELECT|SHOW)/i, 'every query is read-only');
  });
  test('healthy database → zero findings', async () => {
    const { wp } = fakeWp([[/SUM\(LENGTH/, [{ n: 300, bytes: 200 * 1024 }]], [/transient/, [{ n: 3 }]], [/^SELECT COUNT\(\*\) AS n FROM \{prefix\}posts/, [{ n: 40 }]]]);
    const { run } = fakeRun({ only: ['backend.db-health'], wp });
    await backend(run);
    assert.equal(run.findings.length, 0);
    assert.equal(run.checks[0].status, 'passed');
  });
  test('SQL error → check errors (raw output saved)', async () => {
    const { run } = fakeRun({ only: ['backend.db-health'], wp: async () => ({ code: 1, stdout: '', stderr: 'SQL error: Table missing' }) });
    await backend(run);
    assert.equal(run.checks[0].status, 'error');
  });
});

describe('backend.cron', () => {
  const ev = (mins) => ({ hook: 'h', next_run_gmt: new Date(Date.now() - mins * 60000).toISOString().slice(0, 19).replace('T', ' '), recurrence: 'hourly' });
  test('overdue events: low on local (only runs on visits), medium on staging', async () => {
    const { wp } = fakeWp([], { cron: JSON.stringify([ev(300), ev(5)]) });
    const a = fakeRun({ only: ['backend.cron'], wp });
    await backend(a.run);
    assert.equal(a.run.findings[0].severity, 'low');
    const b = fakeRun({ only: ['backend.cron'], wp, config: { site: { url: 'http://fixture.local', environment: 'staging' } } });
    await backend(b.run);
    assert.equal(b.run.findings[0].severity, 'medium');
  });
  test('nothing overdue → zero findings', async () => {
    const { wp } = fakeWp([], { cron: JSON.stringify([ev(-30), ev(10)]) });
    const { run } = fakeRun({ only: ['backend.cron'], wp });
    await backend(run);
    assert.equal(run.findings.length, 0);
  });
});

/* ---------------- debug.log ---------------- */

function tempWp(files = {}) {
  const root = tempDir('wpqa-wp-');
  const w = (p, t) => { fs.mkdirSync(path.dirname(path.join(root, p)), { recursive: true }); fs.writeFileSync(path.join(root, p), t); };
  w('wp-includes/version.php', "<?php\n$wp_version = '6.8.1';\n");
  w('wp-config.php', "<?php\ndefine( 'DB_NAME', 'site_db' );\ndefine( 'WP_DEBUG_LOG', true );\n$table_prefix = 'wp_';\n");
  w('wp-content/plugins/mine/mine.php', "<?php\n/* Plugin Name: Mine */\n$x = $undefined['k'];\n");
  for (const [p, t] of Object.entries(files)) w(p, t);
  return root;
}
const stamp = (d) => { const m = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']; const p = (n) => String(n).padStart(2, '0'); return `[${p(d.getUTCDate())}-${m[d.getUTCMonth()]}-${d.getUTCFullYear()} ${p(d.getUTCHours())}:${p(d.getUTCMinutes())}:${p(d.getUTCSeconds())} UTC]`; };

describe('backend.php-log', () => {
  const now = new Date();
  const old = new Date(Date.now() - 30 * 864e5);
  const LOG = [
    `${stamp(now)} PHP Fatal error:  Uncaught Error: Call to undefined function foo() in /srv/www/wp-content/plugins/mine/mine.php:3`,
    'Stack trace:',
    '#0 {main}',
    `${stamp(now)} PHP Warning:  Undefined array key "k" in /srv/www/wp-content/plugins/mine/mine.php on line 3`,
    `${stamp(now)} PHP Warning:  Undefined array key "k" in /srv/www/wp-content/plugins/mine/mine.php on line 3`,
    `${stamp(now)} PHP Deprecated:  Creation of dynamic property X::$y is deprecated in /srv/www/wp-content/plugins/thirdparty/a.php on line 12`,
    `${stamp(now)} PHP Warning:  mail(): login failed for admin@example.com password=hunter2 from 203.0.113.9 in /srv/www/wp-content/plugins/mine/mine.php on line 3`,
    `${stamp(old)} PHP Fatal error:  ancient error in /srv/www/wp-content/plugins/mine/mine.php on line 3`,
  ].join('\n');

  test('groups by class and location, counts repeats, honours the time window', () => {
    const r = parseDebugLog(LOG, { since: Date.now() - 7 * 864e5 });
    assert.equal(r.inWindow, 5);
    assert.deepEqual(r.byClass, { fatal: 1, warning: 3, deprecated: 1, notice: 0, other: 0 });
    const warn = r.groups.find((g) => g.cls === 'warning' && /Undefined array key/.test(g.message));
    assert.equal(warn.count, 2);
    assert.equal(warn.line, 3);
  });

  test('severity: fatal high; your warnings medium; third-party deprecations info', () => {
    assert.equal(logSeverity('fatal', 'third-party'), 'high');
    assert.equal(logSeverity('warning', 'custom'), 'medium');
    assert.equal(logSeverity('deprecated', 'third-party'), 'info');
  });

  test('module: findings point at your file; evidence is redacted (no email, password, IP)', async () => {
    const root = tempWp({ 'wp-content/debug.log': LOG });
    const run = makeRun({ config: { project: { wpPath: root }, scan: { plugins: ['mine'] } }, mode: 'backend', flags: { only: ['backend.php-log'] } });
    await backend(run);
    const sev = run.findings.map((f) => f.severity).sort();
    assert.deepEqual(sev, ['high', 'info', 'medium', 'medium']);
    const all = JSON.stringify(run.findings);
    for (const secret of ['admin@example.com', 'hunter2', '203.0.113.9']) assert.ok(!all.includes(secret), `${secret} must be redacted`);
    assert.ok(run.findings.find((f) => f.severity === 'high').file.endsWith('mine.php'));
  });

  test('clean: empty log → zero findings; no log → not applicable', async () => {
    const a = makeRun({ config: { project: { wpPath: tempWp({ 'wp-content/debug.log': '' }) } }, mode: 'backend', flags: { only: ['backend.php-log'] } });
    await backend(a);
    assert.equal(a.findings.length, 0);
    assert.equal(a.checks[0].status, 'passed');
    const b = makeRun({ config: { project: { wpPath: tempWp() } }, mode: 'backend', flags: { only: ['backend.php-log'] } });
    await backend(b);
    assert.equal(b.checks[0].status, 'not_applicable');
  });
});

/* ---------------- PHPUnit ---------------- */

describe('backend.phpunit', () => {
  test('refuses when the test DB is the real site DB', async () => {
    const root = tempWp({
      'wp-content/plugins/mine/phpunit.xml.dist': '<phpunit/>',
      'wp-content/plugins/mine/vendor/bin/phpunit': '#!/usr/bin/env php',
      'wp-content/plugins/mine/tests/wp-tests-config.php': "<?php define( 'DB_NAME', 'site_db' );",
    });
    const run = makeRun({ config: { project: { wpPath: root }, scan: { plugins: ['mine'] }, backend: { phpunit: { enabled: true } } }, mode: 'backend', flags: { only: ['backend.phpunit'] } });
    let ran = false;
    run.php = async () => { ran = true; return { code: 0, stdout: '', stderr: '' }; };
    await backend(run);
    assert.equal(ran, false);
    assert.equal(run.checks[0].status, 'skipped');
    assert.match(run.checks[0].notes.join(), /is the real site database — refusing/);
  });
  test('disabled by default even when a suite exists; not applicable without one', async () => {
    const root = tempWp({ 'wp-content/plugins/mine/phpunit.xml': '<phpunit/>' });
    const a = makeRun({ config: { project: { wpPath: root }, scan: { plugins: ['mine'] } }, mode: 'backend', flags: { only: ['backend.phpunit'] } });
    await backend(a);
    assert.match(a.checks[0].reason, /enabled is false/);
    const b = makeRun({ config: { project: { wpPath: tempWp() }, scan: { plugins: ['mine'] } }, mode: 'backend', flags: { only: ['backend.phpunit'] } });
    await backend(b);
    assert.equal(b.checks[0].status, 'not_applicable');
  });
  test('test DB name and JUnit parsing', () => {
    const dir = tempDir();
    fs.writeFileSync(path.join(dir, 'phpunit.xml'), '<phpunit><php><env name="WP_TESTS_DB_NAME" value="tests_db"/></php></phpunit>');
    assert.deepEqual(testDbName(dir), { name: 'tests_db', source: 'phpunit.xml' });
    const j = parseJunit('<testsuites><testsuite name="all" tests="3" failures="1" errors="0" skipped="1"><testcase name="ok" class="A"/><testcase name="bad" class="A"><failure message="expected 1 got 2">trace</failure></testcase></testsuite></testsuites>');
    assert.deepEqual([j.tests, j.failures, j.skipped], [3, 1, 1]);
    assert.deepEqual(j.failed, [{ name: 'A::bad', kind: 'failure', message: 'expected 1 got 2' }]);
  });
});
