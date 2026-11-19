// Stack mode: inventory, status from public sources (recorded), compatibility, drift, client-IP check,
// upgrade plan, dependency audits. No network: HTTP, PHP, WP-CLI and tools are faked.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import stack, { decideStatus, upgradePlan, detectCdn, observeVersions, parseDbServer, parseServerHeader, SOURCES } from '../modules/stack.mjs';
import dependencies, { parseComposerAudit, parseNpmAudit } from '../modules/dependencies.mjs';
import { satisfies, cycleFor, eolInfo, affectingVulns, STATUS } from '../lib/versions.mjs';
import { cachedJson } from '../lib/cache.mjs';
import { makeRun } from './helpers.mjs';

/* ---------------- pure helpers ---------------- */

describe('version constraints', () => {
  const cases = [
    ['8.2.10', '>=8.1', 'composer', true], ['8.0.30', '>=8.1', 'composer', false], ['8.2.10', '>= 8.1', 'composer', true],
    ['8.2.10', '^8.1', 'composer', true], ['9.0.0', '^8.1', 'composer', false], ['8.3.0', '~8.1', 'composer', true],
    ['8.1.9', '~8.1.3', 'composer', true], ['8.2.0', '~8.1.3', 'composer', false],
    ['7.4.33', '^7.4 || ^8.0', 'composer', true], ['8.2.1', '^7.4|^8.0', 'composer', true], ['7.3.0', '>=7.4, <9', 'composer', false],
    ['20.11.0', '>=18', 'npm', true], ['16.0.0', '>=18', 'npm', false], ['20.1.0', '^20.10', 'npm', false], ['20.12.0', '^20.10', 'npm', true],
    ['18.2.0', '~18.1', 'npm', false], ['18.1.5', '~18.1', 'npm', true], ['20.0.0', '18 - 20', 'npm', true], ['22.0.0', '18.x || 20.x', 'npm', false],
    ['24.18.0', '*', 'npm', true],
  ];
  for (const [v, c, flavor, want] of cases) test(`${v} ${flavor} "${c}" → ${want}`, () => assert.equal(satisfies(v, c, flavor), want));
  test('unknown syntax is null, never a guess', () => assert.equal(satisfies('8.2.0', 'dev-main', 'composer'), null));
});

describe('release cycles and vulnerabilities', () => {
  const cycles = [{ cycle: '8.4', eol: '2028-12-31' }, { cycle: '8.2', eol: '2026-12-31' }, { cycle: '24', eol: '2028-04-30' }];
  test('longest matching cycle', () => {
    assert.equal(cycleFor('8.2.29', cycles).cycle, '8.2');
    assert.equal(cycleFor('24.18.0', cycles).cycle, '24');
    assert.equal(cycleFor('8.24.1', cycles), null);
  });
  test('eol dates, booleans and days left', () => {
    const now = new Date('2026-11-19T00:00:00Z');
    assert.deepEqual(eolInfo({ eol: '2026-12-31' }, now), { ended: false, date: '2026-12-31', daysLeft: 42 });
    assert.equal(eolInfo({ eol: '2025-12-31' }, now).ended, true);
    assert.equal(eolInfo({ eol: true }).ended, true);
    assert.equal(eolInfo({ eol: false }).ended, false);
  });
  test('core records named only by version take their title from the source', () => {
    const v = affectingVulns({ vulnerability: [{ uuid: 'u', name: '7.1.4', source: [{ id: 'x', name: 'WordPress Core 6.9.0 - 7.1.4 - Stored XSS', link: 'https://example.org/a' }] }] }, '7.1.4');
    assert.equal(v[0].name, 'WordPress Core 6.9.0 - 7.1.4 - Stored XSS');
    assert.deepEqual(v[0].cves, [], 'a vendor record hash is not a CVE');
  });
  test('only vulnerabilities whose range includes the version', () => {
    const data = { vulnerability: [
      { uuid: 'a', name: 'PHP 8.2 < 8.2.9', operator: { max_version: '8.2.9', max_operator: 'lt' }, source: [{ id: 'CVE-1' }] },
      { uuid: 'b', name: 'PHP 8.2 < 8.2.31', operator: { max_version: '8.2.31', max_operator: 'lt' }, impact: { cvss: { severity: 'm' } } },
      { uuid: 'c', name: 'MySQL == 8.4.1', operator: { max_version: '8.4.1', max_operator: 'eq' } },
    ] };
    const v = affectingVulns(data, '8.2.29');
    assert.deepEqual(v.map((x) => x.id), ['b']);
    assert.equal(v[0].severity, 'medium');
    assert.equal(v[0].fixedIn, '8.2.31');
  });
});

describe('status decision', () => {
  test('order: incompatible > security > EOL > update > current; missing data is UNKNOWN', () => {
    assert.equal(decideStatus({ version: '1', compat: [{ text: 'x' }], vulns: [{}] }).status, STATUS.INCOMPATIBLE);
    assert.equal(decideStatus({ version: '1', vulns: [{}], eol: { ended: true } }).status, STATUS.SECURITY);
    assert.equal(decideStatus({ name: 'PHP', version: '8.0.1', eol: { ended: true, cycle: '8.0', date: '2023-11-26' }, latest: '8.0.30' }).status, STATUS.EOL);
    assert.equal(decideStatus({ version: '8.2.1', latest: '8.2.35' }).status, STATUS.UPDATE);
    assert.equal(decideStatus({ version: '8.2.35', latest: '8.2.35' }).status, STATUS.CURRENT);
    assert.equal(decideStatus({ version: null }).status, STATUS.UNKNOWN);
    assert.equal(decideStatus({ version: '1.0', lookupErrors: ['x: timeout'] }).status, STATUS.UNKNOWN);
  });
  test('a failed vulnerability lookup never yields CURRENT', () => {
    assert.equal(decideStatus({ version: '8.2.35', latest: '8.2.35', vulnLookupFailed: true }).status, STATUS.UNKNOWN);
  });
  test('upgrade plan order: security, PHP/DB, core, plugins, build tools', () => {
    const items = [
      { key: 'node', name: 'Node.js', kind: 'tool', version: '20.1.0', latest: '20.19.0', status: STATUS.UPDATE },
      { key: 'plugin:x', name: 'plugin x', kind: 'plugin', version: '1', latest: '2', status: STATUS.UPDATE, latestRequiresPhp: '8.3' },
      { key: 'wordpress', name: 'WordPress', kind: 'core', version: '7.1.4', latest: '7.1.5', status: STATUS.UPDATE },
      { key: 'php', name: 'PHP', kind: 'runtime', version: '8.2.1', latest: '8.2.35', status: STATUS.UPDATE, eol: { soon: true, ended: false, cycle: '8.2', date: '2026-12-31' } },
      { key: 'plugin:y', name: 'plugin y', kind: 'plugin', version: '1', status: STATUS.SECURITY, vulns: [{ fixedIn: '1.2' }, { fixedIn: '1.10' }, { fixedIn: null }] },
      { key: 'theme:z', name: 'theme z', kind: 'theme', version: '1', latest: '1', status: STATUS.CURRENT },
    ];
    const plan = upgradePlan(items);
    assert.deepEqual(plan.map((p) => p.title[0]), ['1', '2', '3', '4', '5']);
    assert.equal(plan[0].steps[0].key, 'plugin:y');
    assert.equal(plan[0].steps[0].to, '1.10', 'the version that fixes every listed vulnerability');
    assert.match(plan[1].steps[0].notes.join(' '), /ends 2026-12-31/);
    assert.match(plan[3].steps[0].notes.join(' '), /needs PHP 8\.3/);
    assert.ok(!plan.flatMap((p) => p.steps).some((s) => s.key === 'theme:z'));
  });
});

describe('header parsing', () => {
  test('CDN detection, and no evidence is null', () => {
    assert.equal(detectCdn({ server: 'hcdn', 'x-hcdn-cache-status': 'HIT' }), 'Hostinger CDN');
    assert.equal(detectCdn({ 'cf-ray': 'x' }), 'Cloudflare');
    assert.equal(detectCdn({ server: 'LiteSpeed', 'x-litespeed-cache': 'hit' }), null);
  });
  test('versions observed from a public page', () => {
    const o = observeVersions({ headers: { 'x-powered-by': 'PHP/8.3.36', server: 'LiteSpeed' }, text: '<link href="/wp-includes/css/dist/block-library/style.min.css?ver=7.1.4">' });
    assert.equal(o.php, '8.3.36');
    assert.equal(o.wp, '7.1.4');
    assert.equal(o.server.name, 'LiteSpeed');
  });
  test('database and server strings', () => {
    assert.deepEqual(parseDbServer('5.5.5-10.6.12-MariaDB-log').version, '10.6.12');
    assert.equal(parseDbServer('8.4.0').name, 'MySQL');
    assert.equal(parseServerHeader('nginx/1.26.1').version, '1.26.1');
    assert.equal(parseServerHeader('nginx').version, null);
  });
});

/* ---------------- module runs ---------------- */

const json = (data) => ({ ok: true, status: 200, headers: { 'content-type': 'application/json' }, text: JSON.stringify(data) });
const ALL_EXT = ['curl', 'dom', 'exif', 'fileinfo', 'hash', 'intl', 'json', 'mbstring', 'mysqli', 'openssl', 'pcre', 'xml', 'zip', 'imagick'];

/** World = installed versions + what the public sources say. */
function fakeStackRun({ config = {}, installed, sources, pages, exec, plugins }) {
  const run = makeRun({ config, mode: 'stack' });
  if (plugins) run.facts.plugins = run.facts.plugins.filter((p) => plugins.includes(p.slug));
  run.facts.themes = [];
  run.php = async () => ({ code: 0, stdout: JSON.stringify({ v: installed.php, ext: installed.ext || ALL_EXT }), stderr: '' });
  run.wpCli = async () => ({ ok: true, db: true });
  run.wp = async () => ({ code: 0, stdout: JSON.stringify({ server: installed.db }), stderr: '' });
  run.tool = async (name) => ({ ok: !!installed.tools[name], version: installed.tools[name] || null });
  const calls = [];
  run.http = async (url) => {
    calls.push(url);
    if (pages[url]) return pages[url];
    for (const [k, v] of Object.entries(sources)) if (url === k || url.startsWith(k)) return typeof v === 'function' ? v(url) : json(v);
    return { ok: false, status: 0, headers: {}, text: '', error: 'ENOTFOUND (not faked)' };
  };
  run.exec = exec || (async () => ({ code: 0, stdout: '{}', stderr: '' }));
  return { run, calls };
}

const NOW_FUTURE = '2099-12-31';
const commonSources = (o) => ({
  [SOURCES.eol('php')]: [{ cycle: '8.3', eol: NOW_FUTURE, latest: '8.3.36' }, { cycle: '8.2', eol: o.php82Eol || NOW_FUTURE, latest: '8.2.35' }],
  [SOURCES.eol('mysql')]: [{ cycle: '8.4', eol: NOW_FUTURE, latest: '8.4.7' }],
  [SOURCES.eol('nginx')]: [{ cycle: '1.26', eol: NOW_FUTURE, latest: '1.26.3' }],
  [SOURCES.eol('nodejs')]: [{ cycle: '24', eol: NOW_FUTURE, latest: '24.22.3' }],
  [SOURCES.eol('wordpress')]: [{ cycle: '6.8', eol: false, latest: '6.8.1' }],
  [SOURCES.wpCore]: { offers: [{ response: o.coreLatest === '6.8.1' ? 'latest' : 'upgrade', current: o.coreLatest }] },
  [SOURCES.node]: o.nodeIndex || [{ version: 'v24.22.3', security: false }, { version: 'v24.18.0', security: false }],
  [SOURCES.npm]: { version: '11.16.0' },
  [SOURCES.composer]: { stable: [{ version: '2.9.0', lts: false }] },
  [SOURCES.wpcli]: { tag_name: 'v2.12.0' },
  'https://www.wpvulnerability.net/php/': { error: 0, data: { vulnerability: o.phpVulns || [] } },
  'https://www.wpvulnerability.net/mysql/': { error: 0, data: { vulnerability: [] } },
  'https://www.wpvulnerability.net/nginx/': { error: 0, data: { vulnerability: [] } },
  'https://www.wpvulnerability.net/core/': { error: 0, data: { vulnerability: [] } },
  'https://www.wpvulnerability.net/plugin/': { error: 0, data: null },
  'https://api.wordpress.org/plugins/info/1.2/': { error: 'Plugin not found.' },
});

describe('stack mode — fixture that must be flagged', async () => {
  const { run } = fakeStackRun({
    config: { scan: { plugins: ['stack-plugin'] }, publicSite: { url: 'https://shop.example' } },
    plugins: ['stack-plugin', 'safe-plugin'],
    installed: { php: '8.2.10', ext: ALL_EXT.filter((e) => e !== 'intl' && e !== 'imagick'), db: '8.4.0', tools: { node: 'v24.18.0', npm: '11.16.0', composer: 'Composer version 2.9.0 2026-01-01', wp: 'WP-CLI 2.12.0' } },
    pages: {
      'http://fixture.local': { ok: true, status: 200, headers: { server: 'nginx/1.26.1' }, text: '' },
      'https://shop.example': { ok: true, status: 200, headers: { server: 'hcdn', 'x-hcdn-cache-status': 'HIT', 'x-powered-by': 'PHP/8.3.5' }, text: '<meta name="generator" content="WordPress 6.9.1" />' },
    },
    sources: commonSources({ coreLatest: '7.1.5', php82Eol: '2020-01-01', phpVulns: [{ uuid: 'p1', name: 'PHP 8.2 < 8.2.20', operator: { max_version: '8.2.20', max_operator: 'lt' }, source: [{ id: 'CVE-2099-1' }] }], nodeIndex: [{ version: 'v24.22.3', security: true }, { version: 'v24.18.0', security: false }] }),
    exec: async (tool, args) => {
      if (tool === 'composer') return { code: 1, stdout: JSON.stringify({ advisories: { 'guzzlehttp/guzzle': [{ advisoryId: 'PKSA-1', title: 'Cookie leak', cve: 'CVE-2022-1', severity: 'high', affectedVersions: '<7.4.5', link: 'https://x' }] }, abandoned: { 'old/pkg': null } }), stderr: '' };
      if (args.includes('--omit=dev')) return { code: 1, stdout: JSON.stringify({ vulnerabilities: { lodash: { severity: 'high', isDirect: true, via: [{ source: 1, title: 'Prototype pollution', severity: 'high', url: 'https://gh/1', range: '<4.17.21' }], fixAvailable: true } } }), stderr: '' };
      return { code: 1, stdout: JSON.stringify({ vulnerabilities: { lodash: { severity: 'high', isDirect: true, via: [{ source: 1, title: 'Prototype pollution', severity: 'high', url: 'https://gh/1', range: '<4.17.21' }], fixAvailable: true }, webpack: { severity: 'moderate', isDirect: false, via: [{ source: 2, title: 'DOM clobbering', severity: 'moderate', url: 'https://gh/2' }], fixAvailable: true } } }), stderr: '' };
    },
  });
  await stack(run);
  await dependencies(run);
  run.finalizeFindings();
  const byRule = (r) => run.findings.filter((f) => f.rule === r);
  const check = (id) => run.checks.find((c) => c.id === id);

  test('every check ran', () => {
    for (const id of ['stack.inventory', 'stack.compatibility', 'stack.status', 'stack.drift', 'stack.client-ip', 'dependencies.composer-audit', 'dependencies.npm-audit']) assert.equal(check(id)?.status, 'failed', `${id}: ${check(id)?.status} ${check(id)?.reason || ''}`);
  });
  test('incompatible plugin (PHP, production PHP, WordPress) is high', () => {
    const t = byRule('stack.incompatible').map((f) => f.title).join('\n');
    assert.match(t, /requires PHP 8\.4, but this site runs 8\.2\.10/);
    assert.match(t, /requires PHP 8\.4, but production runs 8\.3\.5/);
    assert.match(t, /requires WordPress 7\.2, but this site runs 6\.8\.1/);
    assert.ok(byRule('stack.incompatible').every((f) => f.severity === 'high'));
  });
  test('composer/npm constraints of your own code', () => {
    assert.equal(byRule('stack.composer-php')[0]?.severity, 'medium');
    assert.equal(byRule('stack.node-engine')[0]?.severity, 'low');
  });
  test('missing PHP extensions', () => assert.match(byRule('stack.php-extensions')[0].title, /intl, imagick or gd/));
  test('local PHP: one grouped security finding, low because it is the local environment', () => {
    const sec = byRule('stack.security.runtime').filter((f) => /PHP 8\.2\.10/.test(f.title));
    assert.equal(sec.length, 1);
    assert.ok(sec[0].severity === 'low' && /local development/.test(sec[0].title) && /1 known vulnerability \(fixed in 8\.2\.20\)/.test(sec[0].title));
    assert.match(sec[0].message, /CVE-2099-1/);
    assert.equal(byRule('stack.eol').length, 0, 'security outranks EOL for the same item');
  });
  test('core update is UPDATE AVAILABLE (low), never a vulnerability by itself', () => {
    const f = byRule('stack.update.core')[0];
    assert.equal(f.severity, 'low');
    assert.match(f.title, /6\.8\.1 → 7\.1\.5/);
  });
  test('Node security release flagged for the build tool (low)', () => {
    assert.ok(byRule('stack.security.tool').some((f) => /Node\.js/.test(f.title) && f.severity === 'low'));
  });
  test('drift: PHP and WordPress branches differ (medium)', () => {
    assert.match(byRule('stack.drift-php')[0].title, /local 8\.2\.10, production 8\.3\.5/);
    assert.equal(byRule('stack.drift-wp')[0].severity, 'medium');
  });
  test('client IP: REMOTE_ADDR rate limit behind the CDN and a spoofable header', () => {
    const ra = byRule('stack.ratelimit-remote-addr');
    assert.ok(ra.some((f) => /Hostinger CDN/.test(f.title) && f.file.endsWith('limits.php') && f.line === 7));
    assert.doesNotMatch(ra[0].recommendation, /use X-Forwarded-For/i);
    assert.match(ra[0].recommendation, /Do not trust X-Forwarded-For/);
    assert.equal(byRule('stack.client-ip-header')[0].severity, 'medium');
  });
  test('dependency audits: runtime at its severity, build-only one level lower', () => {
    assert.equal(byRule('composer.advisory')[0].severity, 'high');
    assert.equal(byRule('composer.abandoned').length, 1);
    assert.equal(byRule('npm.advisory')[0].severity, 'high');
    assert.equal(byRule('npm.advisory-dev')[0].severity, 'low');
  });
  test('report section: inventory with sources and an ordered upgrade plan', () => {
    const sec = run.sections.find((s) => s.id === 'stack');
    const php = sec.data.items.find((i) => i.key === 'php');
    assert.equal(php.status, STATUS.SECURITY);
    assert.ok(php.sources.every((s) => s.url && s.fetchedAt));
    assert.equal(sec.data.items.find((i) => i.key === 'plugin:stack-plugin').status, STATUS.INCOMPATIBLE);
    assert.equal(sec.data.items.find((i) => i.key === 'webserver@production').status, STATUS.UNKNOWN);
    assert.equal(sec.data.plan[0].title, '1. Security updates');
    assert.match(sec.lines.join('\n'), /never installs or upgrades/);
  });
});

describe('stack mode — clean fixture has zero findings', async () => {
  const { run } = fakeStackRun({
    config: { scan: { plugins: ['safe-plugin'] } },
    plugins: ['safe-plugin', 'vuln-plugin'],
    installed: { php: '8.3.36', db: '8.4.7', tools: { node: 'v24.22.3', npm: '11.16.0', composer: 'Composer version 2.9.0', wp: 'WP-CLI 2.12.0' } },
    pages: { 'http://fixture.local': { ok: true, status: 200, headers: { server: 'nginx' }, text: '' } },
    sources: { ...commonSources({ coreLatest: '6.8.1', nodeIndex: [{ version: 'v24.22.3', security: false }] }), 'https://api.wordpress.org/plugins/info/1.2/': (url) => json({ version: url.includes('vuln-plugin') ? '1.0.0' : '9.9.9' }) },
  });
  await stack(run);
  await dependencies(run);
  run.finalizeFindings();
  test('no findings at all', () => assert.deepEqual(run.findings.map((f) => `${f.rule}: ${f.title}`), []));
  test('REMOTE_ADDR rate limit without a CDN is a note, not a finding', () => {
    assert.match(run.checks.find((c) => c.id === 'stack.client-ip').notes.join(' '), /no CDN\/proxy detected/);
  });
  test('drift N/A without publicSite; audits N/A without lock files', () => {
    assert.equal(run.checks.find((c) => c.id === 'stack.drift').status, 'not_applicable');
    assert.equal(run.checks.find((c) => c.id === 'dependencies.npm-audit').status, 'not_applicable');
  });
  test('nginx without a version is UNKNOWN, not CURRENT', () => {
    assert.equal(run.sections[0].data.items.find((i) => i.key === 'webserver').status, STATUS.UNKNOWN);
  });
});

describe('failed lookups are UNKNOWN, never passed', async () => {
  test('all lookups fail → stack.status skipped and every item UNKNOWN', async () => {
    const { run } = fakeStackRun({ config: { scan: { plugins: ['safe-plugin'] } }, plugins: ['safe-plugin'], installed: { php: '8.3.36', db: '8.4.7', tools: {} }, pages: { 'http://fixture.local': { ok: true, status: 200, headers: {}, text: '' } }, sources: {} });
    await stack(run);
    const st = run.checks.find((c) => c.id === 'stack.status');
    assert.equal(st.status, 'skipped');
    assert.ok(run.sections[0].data.items.filter((i) => !i.custom && i.status !== STATUS.INCOMPATIBLE).every((i) => i.status === STATUS.UNKNOWN));
    assert.equal(run.findings.filter((f) => f.rule.startsWith('stack.update') || f.rule.startsWith('stack.security')).length, 0);
  });
  test('--offline uses the cache only', async () => {
    const { run, calls } = fakeStackRun({ config: {}, installed: { php: '8.3.36', tools: {} }, pages: {}, sources: { 'https://a.example/x.json': { v: 1 } } });
    const first = await cachedJson(run, 'https://a.example/x.json');
    assert.ok(first.ok && !first.source.fromCache && first.source.fetchedAt);
    const again = await cachedJson(run, 'https://a.example/x.json', { offline: true });
    assert.ok(again.ok && again.source.fromCache);
    const miss = await cachedJson(run, 'https://a.example/other.json', { offline: true });
    assert.equal(miss.ok, false);
    assert.equal(calls.length, 1);
  });
});

describe('dependency audit parsers', () => {
  test('composer: empty advisories list and abandoned packages', () => {
    assert.deepEqual(parseComposerAudit({ advisories: [] }).advisories, []);
    assert.equal(parseComposerAudit({ advisories: {}, abandoned: { 'a/b': 'c/d' } }).abandoned[0].replacement, 'c/d');
  });
  test('npm: transitive "via" strings are reported at their source only', () => {
    const r = parseNpmAudit({ vulnerabilities: { a: { severity: 'high', via: ['b'] }, b: { severity: 'moderate', via: [{ source: 9, title: 't', severity: 'moderate' }], fixAvailable: false } } });
    assert.deepEqual(r.map((x) => [x.pkg, x.severity, x.fix]), [['b', 'medium', 'no fix available']]);
  });
});

describe('regressions found on a real site', () => {
  test('advisories sharing one uuid keep distinct IDs (source ID first)', () => {
    const recs = ['a1', 'b2', 'c3'].map((id) => ({ uuid: 'same-uuid', name: '7.1.4', source: [{ id, name: `Core issue ${id}` }] }));
    const ids = affectingVulns({ vulnerability: recs.map((r) => ({ ...r, operator: null })) }, '7.1.4').map((v) => v.id);
    assert.deepEqual(ids, ['a1', 'b2', 'c3']);
  });
  test('site answering 5xx or database down → inventory skipped (INCOMPLETE), not passed', async () => {
    const { run } = fakeStackRun({ config: { scan: { plugins: ['safe-plugin'] } }, plugins: ['safe-plugin'], installed: { php: '8.3.36', db: '8.4.7', tools: {} }, pages: { 'http://fixture.local': { ok: true, status: 502, headers: { server: 'nginx' }, text: 'Bad Gateway' } }, sources: {} });
    run.wpCli = async () => ({ ok: true, db: false, dbError: 'Error establishing a database connection' });
    await stack(run);
    const inv = run.checks.find((c) => c.id === 'stack.inventory');
    assert.equal(inv.status, 'skipped');
    assert.match(inv.reason, /HTTP 502/);
    assert.match(inv.reason, /database not reachable/);
  });
});
