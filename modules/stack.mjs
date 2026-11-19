// Stack health: what runs the site (WordPress, PHP + extensions, database, web server, Node, Composer, WP-CLI,
// plugins, themes, WooCommerce), the status of each from public sources, compatibility, local-vs-production drift,
// client-IP handling in rate limits, and an upgrade plan. Read-only: it never installs or upgrades anything.
import path from 'node:path';
import { walkFiles, readText, readJson, compareVersions, pMap, parseJsonLoose, lineOf } from '../lib/util.mjs';
import { cachedJson } from '../lib/cache.mjs';
import { STATUS, cleanVersion, cycleFor, eolInfo, affectingVulns, satisfies, meetsMinimum } from '../lib/versions.mjs';

const CAT = 'stack';
const enc = encodeURIComponent;

export const SOURCES = {
  eol: (product) => `https://endoflife.date/api/${product}.json`,
  wpCore: 'https://api.wordpress.org/core/version-check/1.7/',
  wpPlugin: (slug) => `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${enc(slug)}&request[fields][sections]=0`,
  wpTheme: (slug) => `https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=${enc(slug)}`,
  node: 'https://nodejs.org/dist/index.json',
  npm: 'https://registry.npmjs.org/npm/latest',
  composer: 'https://getcomposer.org/versions',
  wpcli: 'https://api.github.com/repos/wp-cli/wp-cli/releases/latest',
  vuln: (type, id) => `https://www.wpvulnerability.net/${type}/${enc(id)}/`,
};

// Extensions WordPress needs or recommends (WordPress hosting handbook). One image library is enough.
const RECOMMENDED_EXT = ['curl', 'dom', 'exif', 'fileinfo', 'hash', 'intl', 'json', 'mbstring', 'mysqli', 'openssl', 'pcre', 'xml', 'zip'];

/* ------------------------------ helpers ------------------------------ */

/** Which CDN / proxy answered, from response headers. null = no evidence (which is not proof there is none). */
export function detectCdn(h = {}) {
  const has = (k) => Object.prototype.hasOwnProperty.call(h, k);
  const server = String(h.server || '').toLowerCase();
  if (has('cf-ray') || server.includes('cloudflare')) return 'Cloudflare';
  if (Object.keys(h).some((k) => k.startsWith('x-hcdn')) || server === 'hcdn') return 'Hostinger CDN';
  if (has('x-sucuri-id')) return 'Sucuri';
  if (has('x-amz-cf-id')) return 'Amazon CloudFront';
  if (has('x-fastly-request-id') || /cache-[a-z]{3}\d/.test(String(h['x-served-by'] || ''))) return 'Fastly';
  if (Object.keys(h).some((k) => k.startsWith('x-akamai'))) return 'Akamai';
  if (has('x-bunny-cache') || server.includes('bunnycdn')) return 'Bunny CDN';
  if (/varnish/i.test(String(h.via || '')) || has('x-varnish')) return 'Varnish proxy';
  return null;
}

/** Web server product from a Server header ("nginx/1.26.1", "Apache/2.4.62 (Unix)", "LiteSpeed"). */
export function parseServerHeader(v) {
  const s = String(v || '');
  let m;
  if ((m = s.match(/nginx(?:\/([\d.]+))?/i))) return { name: 'nginx', version: m[1] || null, eol: 'nginx', vuln: 'nginx' };
  if ((m = s.match(/apache(?:\/([\d.]+))?/i))) return { name: 'Apache', version: m[1] || null, eol: 'apache-http-server', vuln: 'apache' };
  if (/litespeed/i.test(s)) return { name: 'LiteSpeed', version: (s.match(/litespeed\/([\d.]+)/i) || [])[1] || null };
  if (/^microsoft-iis\/([\d.]+)/i.test(s)) return { name: 'IIS', version: s.split('/')[1] };
  return s ? { name: s.slice(0, 40), version: null } : null;
}

/** PHP / WordPress versions a public page reveals (X-Powered-By, generator meta, core asset ?ver=). */
export function observeVersions(res) {
  const h = res?.headers || {};
  const html = res?.text || '';
  const out = { php: null, wp: null, server: parseServerHeader(h.server), cdn: detectCdn(h), evidence: [] };
  const pb = String(h['x-powered-by'] || '').match(/PHP\/([\d.]+)/i);
  if (pb) { out.php = pb[1]; out.evidence.push(`X-Powered-By: PHP/${pb[1]}`); }
  const gen = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([\d.]+)/i);
  const asset = html.match(/wp-includes\/(?:css\/dist\/block-library\/style(?:\.min)?\.css|js\/wp-emoji-release\.min\.js)\?ver=([\d.]+)/i);
  if (gen) { out.wp = gen[1]; out.evidence.push(`generator meta: WordPress ${gen[1]}`); }
  else if (asset) { out.wp = asset[1]; out.evidence.push(`core asset ?ver=${asset[1]}`); }
  return out;
}

/** "5.5.5-10.6.12-MariaDB" → MariaDB 10.6.12; "8.4.0" → MySQL 8.4.0. */
export function parseDbServer(info) {
  const s = String(info || '');
  if (/mariadb/i.test(s)) {
    const m = s.replace(/^5\.5\.5-/, '').match(/(\d+\.\d+\.\d+)/);
    return { name: 'MariaDB', version: m ? m[1] : null, eol: 'mariadb', vuln: 'mariadb' };
  }
  const v = cleanVersion(s);
  return v ? { name: 'MySQL', version: v, eol: 'mysql', vuln: 'mysql' } : null;
}

/**
 * Final status of an inventory item from what the lookups found. Order matters:
 * INCOMPATIBLE > SECURITY > EOL > UPDATE > CURRENT; UNKNOWN when the data to decide is missing.
 * "Not the latest version" is UPDATE AVAILABLE, never a security problem by itself.
 */
export function decideStatus(it) {
  if (it.compat?.length) return { status: STATUS.INCOMPATIBLE, why: it.compat.map((x) => x.text).join('; ') };
  if (!it.version) return { status: STATUS.UNKNOWN, why: it.unknownReason || 'version not detected' };
  if (it.vulns?.length) return { status: STATUS.SECURITY, why: `${it.vulns.length} known vulnerabilit${it.vulns.length === 1 ? 'y' : 'ies'} affect ${it.version}` };
  if (it.eol?.ended) return { status: STATUS.EOL, why: `${it.eol.cycle ? `${it.name} ${it.eol.cycle}` : it.name} ${it.eol.date ? `ended on ${it.eol.date}` : 'is no longer supported'}` };
  if (it.latest && compareVersions(cleanVersion(it.version), cleanVersion(it.latest)) < 0) return { status: STATUS.UPDATE, why: `latest ${it.latest}` };
  if (it.vulnLookupFailed) return { status: STATUS.UNKNOWN, why: 'security data unavailable (vulnerability lookup failed)' };
  if (it.latest) return { status: STATUS.CURRENT, why: `latest ${it.latest}` };
  return { status: STATUS.UNKNOWN, why: it.unknownReason || (it.lookupErrors?.length ? `lookup failed: ${it.lookupErrors.join('; ')}` : 'no public release data') };
}

/** Upgrade order: security → PHP/DB/web server → WordPress core → plugins/themes → build tools. */
export function upgradePlan(items) {
  const phase = (it) => {
    if (it.status === STATUS.SECURITY) return 0;
    if (it.kind === 'runtime') return 1;
    if (it.kind === 'core') return 2;
    if (it.kind === 'plugin' || it.kind === 'theme') return 3;
    return 4;
  };
  const actionable = items.filter((it) => [STATUS.SECURITY, STATUS.EOL, STATUS.UPDATE, STATUS.INCOMPATIBLE].includes(it.status) || it.eol?.soon);
  const names = ['1. Security updates', '2. PHP, database and web server', '3. WordPress core', '4. Plugins and themes', '5. Build tools'];
  return names.map((title, i) => ({
    title,
    steps: actionable.filter((it) => phase(it) === i).map((it) => {
      // The version that fixes every listed vulnerability (the highest "fixed in").
      const to = it.status === STATUS.SECURITY && (it.vulns || []).map((v) => v.fixedIn).filter(Boolean).sort(compareVersions).pop();
      const target = to || it.latest || null;
      const notes = [];
      if (it.eol?.soon && !it.eol.ended) notes.push(`${it.name} ${it.eol.cycle} ends ${it.eol.date}: plan a move to a supported version`);
      if (it.latestRequiresPhp) notes.push(`the new version needs PHP ${it.latestRequiresPhp}`);
      if (it.where === 'local') notes.push('local development environment');
      if (it.where === 'production') notes.push('production server (your host)');
      return { key: it.key, name: it.name, from: it.version, to: target, status: it.status, why: it.why, notes };
    }),
  })).filter((p) => p.steps.length);
}

/* ------------------------------ module ------------------------------ */

export default async function stack(run) {
  const { cfg, facts } = run;
  const sc = cfg.stack;
  const env = cfg.site.environment;
  const offline = !!run.flags.offline;
  const lowImpact = (it) => it.kind === 'tool' || it.where === 'local';
  const state = { items: [], prod: null, local: null };
  const lookup = (url) => cachedJson(run, url, { ttlHours: sc.cacheHours, offline });

  /* ---------- inventory ---------- */
  await run.check({ id: 'stack.inventory', title: 'Stack inventory (WordPress, PHP, database, web server, tools, plugins, themes)', category: CAT, tool: 'PHP, WP-CLI, HTTP headers' }, async (c) => {
    const items = [];
    const add = (it) => { items.push({ sources: [], lookupErrors: [], ...it }); };
    const serverWhere = env; // the PHP/DB/web server at site.url belongs to that environment

    add({ key: 'wordpress', name: 'WordPress', kind: 'core', version: facts.wpVersion, eolProduct: 'wordpress', vulnType: 'core', where: 'site', file: facts.wpRoot ? path.join(facts.wpRoot, 'wp-includes', 'version.php') : null });

    // PHP (the CLI binary configured for this site; LocalWP uses the same build and php.ini for the web server).
    const phpRes = await run.php(['-r', 'echo json_encode(["v"=>PHP_VERSION,"ext"=>array_map("strtolower",get_loaded_extensions())]);'], { timeoutMs: 30000 });
    const phpJ = phpRes.code === 0 ? parseJsonLoose(phpRes.stdout) : null;
    add({ key: 'php', name: 'PHP', kind: 'runtime', version: phpJ?.v || null, eolProduct: 'php', vulnType: 'php', where: serverWhere, extensions: phpJ?.ext || [], unknownReason: phpJ ? null : 'PHP not available (tools.php)' });
    if (phpJ) {
      const ext = new Set(phpJ.ext);
      const missing = RECOMMENDED_EXT.filter((e) => !ext.has(e) && !(e === 'mysqli' && ext.has('mysqlnd') && ext.has('pdo_mysql')));
      if (!ext.has('imagick') && !ext.has('gd')) missing.push('imagick or gd');
      if (missing.length) c.finding({ severity: env === 'local' ? 'low' : 'medium', rule: 'stack.php-extensions', title: `PHP is missing extension(s) WordPress recommends: ${missing.join(', ')}`, fingerprintExtra: 'php-ext', recommendation: 'Enable them in php.ini (or ask your host). Missing image/intl/zip extensions cause failed uploads, broken translations or failed updates.' });
    }

    // Database (through WordPress, read-only).
    const w = await run.wpCli();
    if (w.db) {
      const r = await run.wp(['eval', 'global $wpdb; echo json_encode(["server"=>$wpdb->db_server_info()]);'], { bare: true });
      const j = r.code === 0 ? parseJsonLoose(r.stdout) : null;
      const db = parseDbServer(j?.server);
      add({ key: 'database', name: db?.name || 'Database', kind: 'runtime', version: db?.version || null, eolProduct: db?.eol, vulnType: db?.vuln, where: serverWhere, unknownReason: db ? null : 'database version not readable' });
    } else add({ key: 'database', name: 'Database', kind: 'runtime', version: null, where: serverWhere, unknownReason: `WP-CLI cannot reach the database${w.dbError ? ` (${w.dbError.slice(0, 120)})` : ''}` });

    // Web server at site.url, and what the public site reveals.
    const sres = await run.http(cfg.site.url, { timeoutMs: 15000, redirect: 'follow' });
    if (sres.ok) c.scope([cfg.site.url]);
    state.local = sres.ok ? observeVersions(sres) : null;
    const ws = state.local?.server;
    add({ key: 'webserver', name: ws?.name || 'Web server', kind: 'runtime', version: ws?.version || null, eolProduct: ws?.eol, vulnType: ws?.vuln, where: serverWhere, unknownReason: !sres.ok ? `site not reachable (${sres.error})` : !ws ? 'no Server header' : `${ws.name} does not reveal its version` });
    if (cfg.publicSite?.url && env !== 'production') {
      const pres = await run.http(cfg.publicSite.url, { timeoutMs: 20000, redirect: 'follow' });
      if (pres.ok) {
        c.scope([cfg.publicSite.url]);
        state.prod = observeVersions(pres);
        if (state.prod.php) add({ key: 'php@production', name: 'PHP (production)', kind: 'runtime', version: state.prod.php, eolProduct: 'php', vulnType: 'php', where: 'production', note: state.prod.evidence.find((e) => e.startsWith('X-Powered')) });
        const ps = state.prod.server;
        if (ps) add({ key: 'webserver@production', name: `${ps.name} (production)`, kind: 'runtime', version: ps.version, eolProduct: ps.eol, vulnType: ps.vuln, where: 'production', unknownReason: `${ps.name} does not reveal its version`, note: state.prod.cdn ? `behind ${state.prod.cdn}` : null });
      } else c.note(`public site not reachable (${pres.error}) — production versions not observed`);
    }

    // Build and maintenance tools.
    for (const [key, name, re] of [['node', 'Node.js', /v?(\d+\.\d+\.\d+)/], ['npm', 'npm', /(\d+\.\d+\.\d+)/], ['composer', 'Composer', /(\d+\.\d+\.\d+)/], ['wp', 'WP-CLI', /(\d+\.\d+\.\d+)/]]) {
      const t = await run.tool(key);
      const v = t.ok ? (String(t.version).match(re) || [])[1] || null : null;
      add({ key: key === 'wp' ? 'wp-cli' : key, name, kind: 'tool', version: v, eolProduct: key === 'node' ? 'nodejs' : null, where: 'tool', unknownReason: t.ok ? 'version not parsed' : 'not installed' });
    }

    // Plugins and themes (all installed, custom ones marked).
    for (const p of facts.plugins) {
      const custom = cfg.scan.plugins.includes(p.slug);
      add({ key: `plugin:${p.slug}`, name: p.slug === 'woocommerce' ? 'WooCommerce' : `plugin ${p.slug}`, slug: p.slug, kind: 'plugin', version: p.version, requiresPhp: p.requiresPhp, requiresWp: p.requiresWp, requiresWc: p.requiresWc, custom, where: 'site', file: p.path, unknownReason: custom ? 'your own code (no public release feed)' : null });
    }
    for (const t of facts.themes) {
      const custom = cfg.scan.themes.includes(t.slug);
      add({ key: `theme:${t.slug}`, name: `theme ${t.slug}`, slug: t.slug, kind: 'theme', version: t.version, requiresPhp: t.requiresPhp, requiresWp: t.requiresWp, custom, where: 'site', file: t.path, unknownReason: custom ? 'your own code (no public release feed)' : null });
    }
    state.items = items;
    // Partial inventory (site down or database unreachable) must not count as a pass.
    const missing = [];
    if (!sres.ok || sres.status >= 500) missing.push(`site ${cfg.site.url} ${sres.ok ? `answered HTTP ${sres.status}` : `not reachable (${sres.error})`}`);
    if (!w.db) missing.push('database not reachable through WP-CLI');
    if (!phpJ) missing.push('PHP version not readable');
    if (missing.length) c.skip(`inventory incomplete: ${missing.join('; ')}`, 'Start the site (LocalWP: Start site) and rerun; components not read are UNKNOWN.');
    c.stats = { components: items.length, plugins: facts.plugins.length, themes: facts.themes.length };
    c.note(items.filter((i) => i.kind !== 'plugin' && i.kind !== 'theme').map((i) => `${i.name} ${i.version || '?'}`).join(' · '));
  });

  const haveInventory = () => state.items.length > 0;

  /* ---------- compatibility ---------- */
  await run.check({ id: 'stack.compatibility', title: 'Compatibility: Requires PHP / Requires at least, Composer and npm constraints', category: CAT }, async (c) => {
    if (!haveInventory()) return c.skip('inventory did not run');
    const php = state.items.find((i) => i.key === 'php')?.version;
    const prodPhp = state.items.find((i) => i.key === 'php@production')?.version;
    const wc = state.items.find((i) => i.key === 'plugin:woocommerce')?.version;
    const node = state.items.find((i) => i.key === 'node')?.version;
    let compared = 0;
    for (const it of state.items.filter((i) => i.kind === 'plugin' || i.kind === 'theme')) {
      it.compat = [];
      const label = `${it.kind} ${it.slug} ${it.version || ''}`.trim();
      const checks = [
        ['PHP', it.requiresPhp, php, 'Requires PHP', null],
        ['PHP (production)', it.requiresPhp, prodPhp, 'Requires PHP', 'production'],
        ['WordPress', it.requiresWp, facts.wpVersion, 'Requires at least', null],
        ['WooCommerce', it.requiresWc, wc, 'WC requires at least', null],
      ];
      for (const [what, need, have, header, where] of checks) {
        const ok = meetsMinimum(have, need);
        if (ok === null) continue;
        compared++;
        if (ok) continue;
        it.compat.push({ text: `${header}: ${need}, installed ${what} ${have}` });
        c.finding({ severity: 'high', rule: 'stack.incompatible', title: `${label} requires ${what === 'PHP (production)' ? 'PHP' : what} ${need}, but ${where === 'production' ? 'production runs' : 'this site runs'} ${have}`, file: it.file, fingerprintExtra: `${it.key}:${header}:${where || 'site'}`, recommendation: `WordPress refuses to activate (or may break) a ${it.kind} whose "${header}" is not met. Upgrade ${what.replace(' (production)', '')} first, or keep a version of the ${it.kind} that supports ${have}.` });
      }
    }
    // Your own code's declared constraints.
    for (const d of run.customDirs) {
      const cj = readJson(path.join(d.dir, 'composer.json'));
      const phpReq = cj?.require?.php;
      if (phpReq && php) {
        const ok = satisfies(php, phpReq, 'composer');
        compared++;
        if (ok === false) c.finding({ severity: 'medium', rule: 'stack.composer-php', title: `${d.slug}: composer.json requires PHP "${phpReq}", installed ${php}`, file: path.join(d.dir, 'composer.json'), fingerprintExtra: `composer-php:${d.slug}`, recommendation: 'Align the constraint with the PHP versions you actually run (local and production), or upgrade PHP.' });
        if (ok === null) c.note(`${d.slug}: composer.json PHP constraint "${phpReq}" not understood — not compared`);
      }
      const pj = readJson(path.join(d.dir, 'package.json'));
      const nodeReq = pj?.engines?.node;
      if (nodeReq && node) {
        const ok = satisfies(node, nodeReq, 'npm');
        compared++;
        if (ok === false) c.finding({ severity: 'low', rule: 'stack.node-engine', title: `${d.slug}: package.json engines.node "${nodeReq}", installed Node ${node}`, file: path.join(d.dir, 'package.json'), fingerprintExtra: `node-engine:${d.slug}`, recommendation: 'Builds may fail or differ. Use a Node version in the declared range (e.g. with nvm / .nvmrc), or update the constraint.' });
        if (ok === null) c.note(`${d.slug}: engines.node "${nodeReq}" not understood — not compared`);
      }
    }
    c.stats = { comparisons: compared };
    if (!compared) c.note('no version requirements declared that could be compared');
  });

  /* ---------- status from public sources ---------- */
  await run.check({ id: 'stack.status', title: 'Status per component (current, update, security update, end of life)', category: CAT, tool: 'endoflife.date, api.wordpress.org, nodejs.org, WPVulnerability' }, async (c) => {
    if (!haveInventory()) return c.skip('inventory did not run');
    let attempted = 0, failed = 0;
    const get = async (it, url) => {
      attempted++;
      const r = await lookup(url);
      if (r.ok) it.sources.push({ url, fetchedAt: r.source.fetchedAt, ...(r.stale ? { stale: true } : {}) });
      else { failed++; it.lookupErrors.push(`${new URL(url).hostname}: ${r.error}`); }
      return r.ok ? r.data : null;
    };
    const now = new Date();
    await pMap(state.items.filter((it) => it.version && !it.custom), async (it) => {
      const v = cleanVersion(it.version);
      if (it.eolProduct) {
        const cycles = await get(it, SOURCES.eol(it.eolProduct));
        const cy = cycleFor(v, cycles);
        if (cy) {
          const e = eolInfo(cy, now);
          it.eol = { cycle: String(cy.cycle), ...e, soon: e.ended === false && e.daysLeft != null && e.daysLeft <= sc.eolWarnDays };
          if (it.kind !== 'core' && cy.latest) it.latest = cy.latest; // core: api.wordpress.org is fresher
        } else if (cycles) it.unknownReason = `release cycle of ${it.version} not listed on endoflife.date`;
      }
      if (it.vulnType) {
        const data = await get(it, SOURCES.vuln(it.vulnType, v));
        if (data === null) it.vulnLookupFailed = true;
        else if (data?.error && data.error !== 0) it.vulnLookupFailed = true;
        else it.vulns = it.vulnType === 'core' ? affectingVulns({ vulnerability: (data?.data?.vulnerability || []).map((x) => ({ ...x, operator: null })) }, v) : affectingVulns(data?.data, v);
      }
      if (it.kind === 'core') {
        const vc = await get(it, SOURCES.wpCore);
        const offer = vc?.offers?.find((o) => o.response === 'upgrade' || o.response === 'latest') || vc?.offers?.[0];
        if (offer?.current) it.latest = offer.current;
      }
      if (it.kind === 'plugin' || it.kind === 'theme') {
        const info = await get(it, it.kind === 'plugin' ? SOURCES.wpPlugin(it.slug) : SOURCES.wpTheme(it.slug));
        if (info && !info.error && info.version) {
          it.latest = info.version;
          if (info.requires_php && !meetsMinimum(state.items.find((i) => i.key === 'php')?.version, info.requires_php)) it.latestRequiresPhp = info.requires_php;
        } else if (info) it.unknownReason = 'not on wordpress.org (premium or private) — no public release feed';
        const vd = await get(it, SOURCES.vuln(it.kind, it.slug));
        if (vd === null || (vd?.error && vd.error !== 0)) it.vulnLookupFailed = true;
        else it.vulns = affectingVulns(vd?.data, v);
      }
      if (it.key === 'node') {
        const rel = await get(it, SOURCES.node);
        if (Array.isArray(rel)) {
          const major = v.split('.')[0];
          const same = rel.filter((r) => /^v\d+\.\d+\.\d+$/.test(r.version) && r.version.slice(1).split('.')[0] === major);
          if (same.length) it.latest = same[0].version.slice(1);
          const sec = same.filter((r) => r.security && compareVersions(r.version.slice(1), v) > 0);
          if (sec.length) it.vulns = sec.map((r) => ({ id: `node-${r.version}`, name: `Node.js security release ${r.version}`, severity: 'high', fixedIn: r.version.slice(1), cves: [], links: ['https://nodejs.org/en/blog/vulnerability'] }));
        }
      }
      if (it.key === 'npm') { const j = await get(it, SOURCES.npm); if (j?.version) it.latest = j.version; }
      if (it.key === 'composer') {
        const j = await get(it, SOURCES.composer);
        const st = j?.stable || [];
        const branch = st.find((s) => s.lts && s.version.split('.').slice(0, 2).join('.') === v.split('.').slice(0, 2).join('.'));
        it.latest = (branch || st.find((s) => !s.lts) || st[0])?.version || null;
      }
      if (it.key === 'wp-cli') { const j = await get(it, SOURCES.wpcli); if (j?.tag_name) it.latest = j.tag_name.replace(/^v/, ''); }
    }, 5);

    const wpVulnRan = run.checks.some((x) => x.id === 'wordpress.vulnerabilities' && (x.status === 'passed' || x.status === 'failed'));
    for (const it of state.items) {
      const d = decideStatus(it);
      it.status = d.status;
      it.why = d.why;
      if (it.custom || it.status === STATUS.INCOMPATIBLE) continue; // compatibility check already reported it
      const where = it.where === 'local' ? ' (local development environment)' : '';
      const base = { file: it.file, references: it.sources.map((s) => s.url).slice(0, 3) };
      const typeSlug = it.kind === 'plugin' || it.kind === 'theme' ? `${it.kind}:${it.slug}` : it.key;
      if (it.status === STATUS.SECURITY) {
        const site = ['core', 'plugin', 'theme'].includes(it.kind);
        if (site && wpVulnRan) { c.note(`${it.name} ${it.version}: ${it.vulns.length} known vulnerabilities — listed individually by wordpress.vulnerabilities`); continue; }
        const rank = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
        const worst = [...it.vulns].sort((a, b) => rank[a.severity] - rank[b.severity])[0].severity;
        const fixes = it.vulns.map((v) => v.fixedIn).filter(Boolean).sort(compareVersions);
        const target = fixes.length ? fixes[fixes.length - 1] : it.latest;
        const n = it.vulns.length;
        c.finding({ ...base, severity: lowImpact(it) ? 'low' : worst, rule: `stack.security.${it.kind}`, title: `${it.name} ${it.version}${where}: ${n} known vulnerabilit${n === 1 ? 'y' : 'ies'}${target ? ` (fixed in ${target})` : ''}`, message: it.vulns.slice(0, 8).map((v) => `${v.name}${v.cves.length ? ` [${v.cves.slice(0, 2).join(', ')}]` : ''}`).join(' · ') + (n > 8 ? ` · … ${n - 8} more in report.json` : ''), fingerprintExtra: `security:${typeSlug}`, dedupeKey: `vuln:${typeSlug}`, references: it.vulns.flatMap((v) => v.links).slice(0, 3), recommendation: target ? `Update ${it.name} to ${target} or later${lowImpact(it) ? ' (local environment: update the LocalWP service, or match production)' : ''}.` : `Update ${it.name} to the latest version.` });
      } else if (it.status === STATUS.EOL) {
        c.finding({ ...base, severity: lowImpact(it) ? 'low' : 'high', rule: 'stack.eol', title: `${it.name} ${it.version}${where} is end of life (${it.why})`, fingerprintExtra: `eol:${typeSlug}:${it.eol.cycle}`, recommendation: `${it.name} ${it.eol.cycle} gets no more security fixes. Move to a supported version (see the upgrade plan).` });
      } else if (it.status === STATUS.UPDATE) {
        c.finding({ ...base, severity: lowImpact(it) ? 'info' : 'low', rule: `stack.update.${it.kind}`, title: `${it.name} ${it.version} → ${it.latest} available${where}`, fingerprintExtra: `update:${typeSlug}`, dedupeKey: it.kind === 'plugin' || it.kind === 'theme' ? `update:${it.kind}:${it.slug}` : it.kind === 'core' ? 'update:core' : undefined, recommendation: 'Not a security problem by itself. Update in the order of the upgrade plan, on staging first.' });
      }
      if (it.eol?.soon && it.status !== STATUS.EOL) {
        c.finding({ ...base, severity: lowImpact(it) ? 'low' : 'medium', rule: 'stack.eol-soon', title: `${it.name} ${it.eol.cycle}${where} reaches end of life on ${it.eol.date} (${it.eol.daysLeft} days)`, fingerprintExtra: `eol-soon:${typeSlug}:${it.eol.cycle}`, recommendation: 'Plan the move to a supported version now; after that date there are no security fixes.' });
      }
    }
    c.stats = { lookups: attempted, failedLookups: failed, unknown: state.items.filter((i) => i.status === STATUS.UNKNOWN).length };
    if (attempted && failed === attempted) {
      for (const it of state.items) if (!it.custom && it.status !== STATUS.INCOMPATIBLE) { it.status = STATUS.UNKNOWN; it.why = 'all lookups failed'; }
      return c.skip(offline ? 'offline and nothing cached — status not determined' : `all ${failed} lookups failed — status not determined (UNKNOWN)`, 'Check internet access to endoflife.date, api.wordpress.org and www.wpvulnerability.net');
    }
    if (failed) c.note(`${failed} of ${attempted} lookups failed — those components are UNKNOWN or partly checked`);
    c.note(`sources cached ${sc.cacheHours} h in ${path.join(cfg._outRoot, 'cache')}`);
  });

  /* ---------- local vs production ---------- */
  await run.check({ id: 'stack.drift', title: 'Local vs production versions (PHP, WordPress)', category: CAT, tool: 'HTTP headers' }, async (c) => {
    if (!cfg.publicSite?.url) return c.notApplicable('no publicSite.url configured');
    if (env === 'production') return c.notApplicable('the audited site is production');
    if (!state.prod) return c.skip('public site not reachable — production versions not observed');
    const php = state.items.find((i) => i.key === 'php')?.version;
    const pairs = [['PHP', php, state.prod.php, 'stack.drift-php'], ['WordPress', facts.wpVersion, state.prod.wp, 'stack.drift-wp']];
    let observed = 0;
    for (const [name, here, there, rule] of pairs) {
      if (!there) { c.note(`production ${name} version not observable (not revealed in headers/HTML — good for security)`); continue; }
      if (!here) { c.note(`local ${name} version unknown`); continue; }
      observed++;
      const mm = (v) => cleanVersion(v).split('.').slice(0, 2).join('.');
      if (compareVersions(cleanVersion(here), cleanVersion(there)) === 0) { c.note(`${name}: same version locally and in production (${here})`); continue; }
      const branch = mm(here) !== mm(there);
      c.finding({ severity: branch ? 'medium' : 'low', rule, title: `${name} differs: local ${here}, production ${there}`, url: cfg.publicSite.url, fingerprintExtra: `${rule}:${mm(here)}:${mm(there)}`, message: `Observed: ${state.prod.evidence.join('; ')}`, recommendation: branch ? `Develop and test on the same ${name} branch as production (${mm(there)}): behaviour and deprecations differ between branches.` : `Patch levels differ; align them when convenient so tests reflect production.` });
    }
    if (!observed) return c.notApplicable('production does not reveal its PHP or WordPress version');
  });

  /* ---------- client IP for rate limits ---------- */
  await run.check({ id: 'stack.client-ip', title: 'Rate limiting by client IP behind a CDN / proxy', category: 'security', requires: { customCode: true } }, async (c) => {
    const files = run.customFiles((d) => walkFiles(d, { exts: ['.php'], exclude: cfg.scan.exclude }));
    c.scope(run.customDirs.map((d) => d.dir));
    const cdn = state.prod?.cdn || (env !== 'local' ? state.local?.cdn : null) || null;
    let remoteAddrLimits = 0;
    for (const f of files) {
      const text = readText(f) || '';
      if (!/REMOTE_ADDR|HTTP_X_FORWARDED_FOR|HTTP_X_REAL_IP|HTTP_CLIENT_IP|HTTP_CF_CONNECTING_IP/.test(text)) continue;
      const lines = text.split('\n');
      const near = (i) => lines.slice(Math.max(0, i - 15), i + 30).join('\n');
      const limitish = /set_transient|wp_cache_(?:set|incr)|rate.?limit|throttl|too many|attempts?\b|\blockout/i;
      const re = /\$_SERVER\s*\[\s*['"](REMOTE_ADDR|HTTP_X_FORWARDED_FOR|HTTP_X_REAL_IP|HTTP_CLIENT_IP|HTTP_CF_CONNECTING_IP)['"]\s*\]/g;
      let m;
      const seen = new Set();
      while ((m = re.exec(text))) {
        const line = lineOf(text, m.index);
        const key = `${m[1]}:${line}`;
        if (seen.has(key)) continue;
        seen.add(key);
        const ctx = near(line - 1);
        if (m[1] === 'REMOTE_ADDR') {
          if (!limitish.test(ctx)) continue;
          remoteAddrLimits++;
          if (!cdn) continue; // no evidence of a proxy in front: REMOTE_ADDR is the right source
          c.finding({ severity: 'medium', confidence: 'heuristic', rule: 'stack.ratelimit-remote-addr', title: `Rate limit keyed on REMOTE_ADDR while production is behind ${cdn}`, file: f, line, message: `Behind a CDN or reverse proxy, REMOTE_ADDR can be the address of the edge server, not the visitor — unless the web server restores the client address. Then many visitors share one limit (real users get blocked) and the limit says little about who is sending. Whether that happens here depends on the host's configuration.`, recommendation: `Check once what REMOTE_ADDR contains on production for a test request. If it is a ${cdn} address: let the web server restore the client IP from the CDN's own header only for requests that come from the CDN's published IP ranges (nginx real_ip with set_real_ip_from, Apache mod_remoteip with trusted proxies, LiteSpeed "Use Client IP in Header" with trusted IPs), or in PHP read that header only after checking REMOTE_ADDR is one of those ranges. Do not trust X-Forwarded-For as sent: any client can set it.` });
        } else {
          if (/trusted|set_real_ip|ip_in_range|cidr/i.test(ctx)) continue; // header read after a proxy check
          c.finding({ severity: limitish.test(ctx) ? 'medium' : 'low', confidence: 'heuristic', rule: 'stack.client-ip-header', title: `Client IP read from ${m[1].replace('HTTP_', '').replace(/_/g, '-')}, a header the client can set`, file: f, line, recommendation: 'Only use this header when the request comes from a proxy/CDN you trust (check REMOTE_ADDR against its published IP ranges). Otherwise anyone can pick their own "IP", bypass rate limits or poison logs.' });
        }
      }
    }
    if (remoteAddrLimits && !cdn) c.note(`${remoteAddrLimits} rate limit(s) use REMOTE_ADDR; no CDN/proxy detected in front of ${cfg.publicSite?.url || cfg.site.url} (that is the right source unless a proxy is added later)`);
    c.stats = { files: files.length, remoteAddrLimits, cdn: cdn || 'none detected' };
  });

  /* ---------- report section: inventory + upgrade plan ---------- */
  if (!state.items.length) return;
  for (const it of state.items) if (!it.status) Object.assign(it, (({ status, why }) => ({ status, why }))(decideStatus(it)));
  const plan = upgradePlan(state.items);
  const L = [];
  L.push('Status from public sources (cached 24 h; source and date per row in report.json). "UPDATE AVAILABLE" alone is not a security problem.');
  L.push('');
  L.push('| Component | Installed | Status | Detail | Where |');
  L.push('|---|---|---|---|---|');
  const order = { core: 0, runtime: 1, tool: 2, plugin: 3, theme: 4 };
  for (const it of [...state.items].sort((a, b) => order[a.kind] - order[b.kind])) {
    L.push(`| ${it.name} | ${it.version || '?'} | ${it.status} | ${(it.why || '').replace(/\|/g, '/')}${it.note ? ` · ${it.note}` : ''} | ${it.where} |`);
  }
  L.push('');
  L.push('### Upgrade plan');
  L.push('');
  if (!plan.length) L.push('_Nothing to upgrade._');
  for (const p of plan) {
    L.push(`**${p.title}**`);
    for (const s of p.steps) L.push(`- ${s.name}: ${s.from || '?'}${s.to ? ` → ${s.to}` : ''} — ${s.status}${s.notes.length ? ` (${s.notes.join('; ')})` : ''}`);
    L.push('');
  }
  L.push('The toolkit never installs or upgrades anything. Back up, apply each step on staging (or the sandbox) first, rerun the audit, then repeat on production.');
  run.sections.push({
    id: 'stack',
    title: 'Stack inventory',
    lines: L,
    data: {
      items: state.items.map(({ key, name, kind, version, status, why, latest, eol, where, custom, sources, vulns, compat }) => ({ key, name, kind, version, status, why, latest: latest || null, eol: eol || null, where, custom: !!custom, sources, vulns: (vulns || []).map((v) => ({ name: v.name, fixedIn: v.fixedIn, cves: v.cves, links: v.links })), compat: compat || [] })),
      plan,
      production: state.prod ? { php: state.prod.php, wp: state.prod.wp, server: state.prod.server?.name || null, cdn: state.prod.cdn, evidence: state.prod.evidence } : null,
    },
  });
}
