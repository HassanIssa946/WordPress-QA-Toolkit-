// WordPress static checks: themes, plugins, Gutenberg blocks (block.json), theme.json, known vulnerabilities, wp.org status.
import path from 'node:path';
import { walkFiles, readText, readJson, exists, httpFetch, compareVersions, pMap } from '../lib/util.mjs';
import { discoverBlocks } from '../lib/discover.mjs';

const CAT = 'wordpress';
const ASSET_FIELDS = ['editorScript', 'script', 'viewScript', 'viewScriptModule', 'scriptModule', 'editorStyle', 'style', 'viewStyle', 'render'];

export default async function wordpress(run) {
  const { cfg, facts } = run;
  const themes = run.customDirs.filter((d) => d.type === 'theme');
  const plugins = run.customDirs.filter((d) => d.type === 'plugin');

  await run.check({ id: 'wordpress.theme', title: 'Custom theme structure and WordPress integration', category: CAT, requires: { customCode: true } }, async (c) => {
    if (!themes.length) return c.notApplicable('no custom theme configured');
    c.scope(themes.map((t) => t.dir));
    for (const t of themes) {
      const info = facts.themes.find((x) => x.slug === t.slug) || {};
      const style = path.join(t.dir, 'style.css');
      if (!exists(style)) { c.finding({ severity: 'critical', rule: 'theme.style-css', title: `Theme ${t.slug} has no style.css`, file: t.dir }); continue; }
      for (const [k, v] of [['Text Domain', info.textDomain], ['Version', info.version], ['Requires PHP', info.requiresPhp]]) {
        if (!v) c.finding({ severity: 'low', rule: 'theme.header', title: `style.css missing "${k}" header (${t.slug})`, file: style, recommendation: `Add "${k}:" to the style.css header.` });
      }
      if (info.template && !facts.themes.find((x) => x.slug === info.template)) c.finding({ severity: 'critical', rule: 'theme.parent-missing', title: `Parent theme "${info.template}" is not installed`, file: style });
      if (info.isBlockTheme) {
        const tj = readJson(path.join(t.dir, 'theme.json'));
        if (tj === undefined) c.finding({ severity: 'high', rule: 'theme.json-invalid', title: 'theme.json is not valid JSON', file: path.join(t.dir, 'theme.json') });
        else if (tj && (tj.version ?? 0) < 2) c.finding({ severity: 'medium', rule: 'theme.json-version', title: 'theme.json uses an old schema version', file: path.join(t.dir, 'theme.json'), recommendation: 'Use "version": 3 (WP 6.6+).' });
        continue;
      }
      const php = walkFiles(t.dir, { exts: ['.php'], exclude: cfg.scan.exclude });
      const all = php.map((f) => ({ f, text: readText(f) || '' }));
      const joined = all.map((x) => x.text).join('\n');
      if (!/wp_head\s*\(\s*\)/.test(joined)) c.finding({ severity: 'high', rule: 'theme.wp_head', title: 'wp_head() is never called', file: t.dir, recommendation: 'Call wp_head() before </head>; without it plugins, SEO tags and enqueued CSS/JS break.' });
      if (!/wp_footer\s*\(\s*\)/.test(joined)) c.finding({ severity: 'high', rule: 'theme.wp_footer', title: 'wp_footer() is never called', file: t.dir, recommendation: 'Call wp_footer() before </body>; footer scripts (forms, analytics, blocks) depend on it.' });
      if (!/wp_body_open\s*\(\s*\)/.test(joined)) c.finding({ severity: 'low', rule: 'theme.wp_body_open', title: 'wp_body_open() not called after <body>', file: t.dir });
      if (!/add_theme_support\s*\(\s*['"]title-tag/.test(joined)) c.finding({ severity: 'medium', rule: 'theme.title-tag', title: "add_theme_support( 'title-tag' ) missing", file: t.dir, recommendation: 'Let WordPress/SEO plugins manage <title>; remove hard-coded <title>.' });
      for (const { f, text } of all) {
        const re = /<script[^>]+src=|<link[^>]+rel=["']stylesheet/gi;
        let m;
        while ((m = re.exec(text))) c.finding({ severity: 'medium', rule: 'theme.hardcoded-asset', title: 'Script/stylesheet hard-coded in a template instead of enqueued', file: f, line: text.slice(0, m.index).split('\n').length, aggregate: true, recommendation: 'Use wp_enqueue_script/style in functions.php (with version + dependencies).' });
        if (/code\.jquery\.com|ajax\.googleapis\.com\/ajax\/libs\/jquery/.test(text)) c.finding({ severity: 'medium', rule: 'theme.jquery-cdn', title: 'Loads its own jQuery from a CDN', file: f, recommendation: "Depend on WordPress's bundled 'jquery' handle." });
      }
      if (!exists(path.join(t.dir, 'screenshot.png')) && !exists(path.join(t.dir, 'screenshot.jpg'))) c.finding({ severity: 'info', rule: 'theme.screenshot', title: 'No screenshot.png', file: t.dir });
    }
  });

  await run.check({ id: 'wordpress.plugin', title: 'Custom plugin structure', category: CAT, requires: { customCode: true } }, async (c) => {
    if (!plugins.length) return c.notApplicable('no custom plugin configured');
    c.scope(plugins.map((p) => p.dir));
    for (const p of plugins) {
      const info = facts.plugins.find((x) => x.slug === p.slug);
      if (!info) { c.finding({ severity: 'high', rule: 'plugin.header', title: `No main file with a "Plugin Name:" header in ${p.slug}`, file: p.dir }); continue; }
      for (const [k, v] of [['Version', info.version], ['Requires PHP', info.requiresPhp], ['Text Domain', info.textDomain]]) {
        if (!v) c.finding({ severity: 'low', rule: 'plugin.header', title: `Plugin header missing "${k}" (${p.slug})`, file: info.path });
      }
      if (!info.updateUri && !info.stableTag) c.finding({ severity: 'low', rule: 'plugin.update-uri', title: `Custom plugin ${p.slug} has no "Update URI" header`, file: info.path, recommendation: 'Add "Update URI: false" so a same-named wordpress.org plugin can never overwrite it via updates.' });
    }
  });

  await run.check({ id: 'wordpress.blocks', title: 'Gutenberg blocks (block.json validity, assets, apiVersion)', category: CAT, requires: { customCode: true } }, async (c) => {
    const blocks = discoverBlocks(run.customDirs.map((d) => d.dir));
    const src = blocks.filter((b) => !b.inBuild);
    const built = blocks.filter((b) => b.inBuild);
    if (!blocks.length) return c.notApplicable('no block.json in custom code');
    c.scope(run.customDirs.map((d) => d.dir));
    const names = new Map();
    const builtNames = new Set(built.map((b) => readJson(b.path)?.name).filter(Boolean));
    for (const b of blocks) {
      const j = readJson(b.path);
      // When a build copy exists, WordPress registers that one — check it and skip the source duplicate.
      if (!b.inBuild && j?.name && builtNames.has(j.name)) continue;
      if (!j) { c.finding({ severity: 'high', rule: 'block.json-invalid', title: 'block.json is not valid JSON', file: b.path }); continue; }
      if (!j.name || !/^[a-z0-9-]+\/[a-z0-9-]+$/.test(j.name)) c.finding({ severity: 'high', rule: 'block.name', title: `Invalid block name "${j.name}"`, file: b.path, recommendation: 'Use "namespace/block-name" in lowercase.' });
      if (b.inBuild || !built.length) {
        if (names.has(j.name) && names.get(j.name) !== path.dirname(b.path)) c.finding({ severity: 'high', rule: 'block.duplicate', title: `Block "${j.name}" defined twice`, file: b.path });
        names.set(j.name, path.dirname(b.path));
      }
      if ((j.apiVersion ?? 1) < 3) c.finding({ severity: 'low', rule: 'block.apiVersion', title: `Block ${j.name} uses apiVersion ${j.apiVersion ?? 1}`, file: b.path, recommendation: 'Use apiVersion 3 so the block works in the iframed editor (WP 6.3+).' });
      if (!j.textdomain) c.finding({ severity: 'low', rule: 'block.textdomain', title: `Block ${j.name} has no textdomain`, file: b.path });
      // Asset references must exist next to the block.json that WordPress registers.
      if (b.inBuild || !built.length) {
        for (const field of ASSET_FIELDS) {
          for (const ref of [].concat(j[field] || [])) {
            if (typeof ref !== 'string' || !ref.startsWith('file:')) continue;
            const target = path.resolve(path.dirname(b.path), ref.slice(5));
            if (!exists(target)) c.finding({ severity: 'high', rule: 'block.asset-missing', title: `Block ${j.name}: ${field} file missing (${ref})`, file: b.path, recommendation: built.length ? 'Run the build (npm run build) and commit/deploy the build folder.' : 'Fix the path or build the asset.' });
          }
        }
      }
    }
    if (src.length && !built.length && src.some((b) => exists(path.join(path.dirname(b.path), 'index.js')) && /import\s/.test(readText(path.join(path.dirname(b.path), 'index.js')) || ''))) {
      c.finding({ severity: 'medium', rule: 'block.no-build', title: 'Block source uses ES imports/JSX but no build output was found', file: src[0].path, recommendation: 'Run @wordpress/scripts build and register blocks from the build/ folder.' });
    }
    c.stats = { blocks: blocks.length };
  });

  await run.check({ id: 'wordpress.vulnerabilities', title: 'Known vulnerabilities in core, plugins and themes (WPVulnerability)', category: 'dependencies', tool: 'wpvulnerability.net' }, async (c) => {
    if (!cfg.vulnerabilityLookup) return c.skip('disabled (vulnerabilityLookup: false)');
    const items = [
      ...(facts.wpVersion ? [{ type: 'core', slug: 'wordpress', version: facts.wpVersion.replace(/-.*/, ''), url: `https://www.wpvulnerability.net/core/${facts.wpVersion.replace(/-.*/, '')}/` }] : []),
      ...facts.plugins.filter((p) => p.version && !cfg.scan.plugins.includes(p.slug)).map((p) => ({ type: 'plugin', slug: p.slug, version: p.version, file: p.path, url: `https://www.wpvulnerability.net/plugin/${p.slug}/` })),
      ...facts.themes.filter((t) => t.version && !cfg.scan.themes.includes(t.slug)).map((t) => ({ type: 'theme', slug: t.slug, version: t.version, file: t.path, url: `https://www.wpvulnerability.net/theme/${t.slug}/` })),
    ];
    let failures = 0;
    await pMap(items, async (it) => {
      const r = await httpFetch(it.url, { timeoutMs: 20000, redirect: 'follow' });
      if (!r.ok || r.status !== 200) { failures++; return; }
      let data; try { data = JSON.parse(r.text)?.data; } catch { failures++; return; }
      for (const v of data?.vulnerability || []) {
        if (!affects(v.operator, it.version, it.type === 'core')) continue;
        const sevCode = v.impact?.cvss?.severity || '';
        const severity = { c: 'critical', h: 'high', m: 'medium', l: 'low' }[sevCode] || 'high';
        const fixed = v.operator?.max_version && /lt/.test(v.operator?.max_operator || '') ? v.operator.max_version : null;
        c.finding({ severity, rule: `vuln.${it.type}`, title: `${it.type === 'core' ? 'WordPress core' : `${it.type} ${it.slug}`} ${it.version}: ${v.name || 'known vulnerability'}`, file: it.file, fingerprintExtra: v.uuid || v.name, message: (v.source || []).map((s) => s.id || s.name).filter(Boolean).slice(0, 3).join(', ') || null, references: (v.source || []).map((s) => s.link).filter(Boolean).slice(0, 3), recommendation: fixed ? `Update to ${fixed} or later.` : v.operator?.unfixed === '1' ? 'No fix available — remove or replace this component.' : 'Update to the latest version.' });
      }
    }, 5);
    c.stats = { components: items.length, lookupFailures: failures };
    if (failures === items.length && items.length) return c.skip(`vulnerability database unreachable (${failures} lookups failed)`, 'Check internet access to www.wpvulnerability.net');
    if (failures) c.note(`${failures} lookup(s) failed — those components were not checked`);
  });

  await run.check({ id: 'wordpress.wporg-status', title: 'Outdated, closed or abandoned plugins/themes (wordpress.org)', category: 'dependencies', tool: 'api.wordpress.org' }, async (c) => {
    const items = [
      ...facts.plugins.filter((p) => p.stableTag && !cfg.scan.plugins.includes(p.slug)).map((p) => ({ type: 'plugin', ...p })),
      ...facts.themes.filter((t) => !cfg.scan.themes.includes(t.slug) && t.version).map((t) => ({ type: 'theme', ...t })),
    ];
    if (!items.length) return c.notApplicable('no wordpress.org components detected');
    let failures = 0;
    await pMap(items, async (it) => {
      const url = it.type === 'plugin'
        ? `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${it.slug}&request[fields][sections]=0`
        : `https://api.wordpress.org/themes/info/1.2/?action=theme_information&request[slug]=${it.slug}`;
      const r = await httpFetch(url, { timeoutMs: 20000, redirect: 'follow' });
      if (!r.ok) { failures++; return; }
      let j; try { j = JSON.parse(r.text); } catch { failures++; return; }
      if (j?.error) {
        if (/closed/i.test(j.error) || j.closed) c.finding({ severity: 'high', rule: 'wporg.closed', title: `${it.type} ${it.slug} was closed on wordpress.org`, file: it.path, recommendation: 'Closed plugins often have unfixed security problems — replace it.' });
        return; // not on wp.org (premium/custom)
      }
      if (j.version && it.version && compareVersions(it.version, j.version) < 0) c.finding({ severity: 'medium', rule: 'wporg.outdated', title: `${it.type} ${it.slug} ${it.version} is outdated (latest ${j.version})`, file: it.path, aggregate: false, dedupeKey: `update:${it.type}:${it.slug}`, recommendation: 'Update on staging first, then production.' });
      const updated = j.last_updated ? new Date(j.last_updated.replace(/(\d{4}-\d{2}-\d{2}) (\d{1,2}:\d{2})(am|pm)? GMT/i, '$1T00:00:00Z')) : null;
      if (updated && !isNaN(updated) && Date.now() - updated > 2 * 365 * 864e5) c.finding({ severity: 'medium', rule: 'wporg.abandoned', title: `${it.type} ${it.slug} not updated for over 2 years`, file: it.path, recommendation: 'Look for a maintained alternative.' });
    }, 5);
    if (failures === items.length) return c.skip('wordpress.org API unreachable', 'Check internet access');
  });
}

/** Does a WPVulnerability "operator" range include version? */
export function affects(op, version, isCore) {
  if (isCore) return true; // core endpoint is version-specific already
  if (!op) return true;
  const cmp = (o, v) => {
    const r = compareVersions(version, v);
    return { lt: r < 0, le: r <= 0, gt: r > 0, ge: r >= 0, eq: r === 0 }[o] ?? true;
  };
  if (op.min_version && op.min_operator && !cmp(op.min_operator, op.min_version)) return false;
  if (op.max_version && op.max_operator && !cmp(op.max_operator, op.max_version)) return false;
  return true;
}
