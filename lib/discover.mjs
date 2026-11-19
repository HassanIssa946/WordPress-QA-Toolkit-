// Project discovery: works from the filesystem only (no WP-CLI/DB needed).
import fs from 'node:fs';
import path from 'node:path';
import { readText, exists, parseWpHeaders, walkFiles, readJson } from './util.mjs';

const THEME_HEADERS = ['Theme Name', 'Version', 'Template', 'Requires PHP', 'Requires at least', 'Text Domain', 'Author', 'Tested up to'];
const PLUGIN_HEADERS = ['Plugin Name', 'Version', 'Requires PHP', 'Requires at least', 'Text Domain', 'Author', 'Network', 'Update URI', 'WC requires at least', 'Requires Plugins'];

const KNOWN = {
  builders: ['elementor', 'elementor-pro', 'js_composer', 'beaver-builder-lite-version', 'bb-plugin', 'divi-builder', 'oxygen', 'bricks', 'breakdance', 'kadence-blocks', 'spectra', 'ultimate-addons-for-gutenberg', 'generateblocks', 'stackable-ultimate-gutenberg-blocks', 'greenshift-animation-and-page-builder-blocks'],
  seo: ['wordpress-seo', 'seo-by-rank-math', 'all-in-one-seo-pack', 'autodescription', 'wp-seopress'],
  cache: ['wp-rocket', 'litespeed-cache', 'w3-total-cache', 'wp-super-cache', 'wp-fastest-cache', 'sg-cachepress', 'breeze', 'cache-enabler', 'hummingbird-performance', 'flying-press', 'nitropack', 'autoptimize', 'perfmatters', 'redis-cache', 'docket-cache'],
  security: ['wordfence', 'better-wp-security', 'sucuri-scanner', 'all-in-one-wp-security-and-firewall', 'solid-security', 'defender-security', 'limit-login-attempts-reloaded', 'wps-hide-login', 'two-factor', 'wp-2fa'],
  forms: ['contact-form-7', 'wpforms-lite', 'wpforms', 'gravityforms', 'ninja-forms', 'fluentform', 'formidable', 'forminator'],
  qa: ['plugin-check', 'theme-check', 'query-monitor', 'debug-bar'],
  multilingual: ['sitepress-multilingual-cms', 'polylang', 'translatepress-multilingual', 'weglot', 'gtranslate'],
  ecommerce: ['woocommerce', 'easy-digital-downloads'],
};

/** Find the WordPress root from a starting directory (handles LocalWP's app/public layout). */
export function findWpRoot(start) {
  const isRoot = (d) => exists(path.join(d, 'wp-includes', 'version.php')) || exists(path.join(d, 'wp-config.php')) && exists(path.join(d, 'wp-content'));
  const s = path.resolve(start);
  const down = [s, path.join(s, 'app', 'public'), path.join(s, 'public'), path.join(s, 'web'), path.join(s, 'wordpress'), path.join(s, 'htdocs'), path.join(s, 'public_html')];
  for (const d of down) if (isRoot(d)) return d;
  let d = s;
  for (let i = 0; i < 8; i++) {
    if (isRoot(d)) return d;
    const parent = path.dirname(d);
    if (parent === d) break;
    d = parent;
  }
  return null;
}

function parseWpConfig(text) {
  if (!text) return null;
  const def = (name) => {
    const m = text.match(new RegExp(`define\\s*\\(\\s*['"]${name}['"]\\s*,\\s*([^)]+?)\\s*\\)\\s*;`, 'i'));
    if (!m) return undefined;
    const v = m[1].trim();
    if (/^true$/i.test(v)) return true;
    if (/^false$/i.test(v)) return false;
    const s = v.match(/^['"](.*)['"]$/s);
    return s ? s[1] : v;
  };
  const prefix = text.match(/\$table_prefix\s*=\s*['"]([^'"]*)['"]/);
  return {
    WP_DEBUG: def('WP_DEBUG'),
    WP_DEBUG_DISPLAY: def('WP_DEBUG_DISPLAY'),
    WP_DEBUG_LOG: def('WP_DEBUG_LOG'),
    SCRIPT_DEBUG: def('SCRIPT_DEBUG'),
    DISALLOW_FILE_EDIT: def('DISALLOW_FILE_EDIT'),
    DISALLOW_FILE_MODS: def('DISALLOW_FILE_MODS'),
    FORCE_SSL_ADMIN: def('FORCE_SSL_ADMIN'),
    WP_ENVIRONMENT_TYPE: def('WP_ENVIRONMENT_TYPE'),
    WP_HOME: def('WP_HOME'),
    WP_SITEURL: def('WP_SITEURL'),
    WP_CACHE: def('WP_CACHE'),
    DISABLE_WP_CRON: def('DISABLE_WP_CRON'),
    WP_POST_REVISIONS: def('WP_POST_REVISIONS'),
    DB_NAME: def('DB_NAME'),
    DB_HOST: def('DB_HOST'),
    tablePrefix: prefix ? prefix[1] : undefined,
    saltsPlaceholder: /put your unique phrase here/i.test(text),
    hasSalts: /define\s*\(\s*['"]AUTH_KEY['"]/i.test(text),
  };
}

function readmeInfo(dir) {
  const t = readText(path.join(dir, 'readme.txt')) || readText(path.join(dir, 'README.txt'));
  if (!t) return { hasReadme: false };
  const stable = t.match(/^\s*Stable tag:\s*(.+)$/im);
  return { hasReadme: true, stableTag: stable ? stable[1].trim() : null };
}

function discoverThemes(wpContent) {
  const dir = path.join(wpContent, 'themes');
  const out = [];
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const tdir = path.join(dir, e.name);
    const css = readText(path.join(tdir, 'style.css'));
    if (!css) continue;
    const h = parseWpHeaders(css, THEME_HEADERS);
    const rm = readmeInfo(tdir);
    out.push({
      slug: e.name,
      name: h['Theme Name'] || e.name,
      version: h.Version || null,
      template: h.Template || null,
      requiresPhp: h['Requires PHP'] || null,
      requiresWp: h['Requires at least'] || null,
      textDomain: h['Text Domain'] || null,
      author: h.Author || null,
      isBlockTheme: exists(path.join(tdir, 'templates', 'index.html')) || exists(path.join(tdir, 'block-templates', 'index.html')),
      hasThemeJson: exists(path.join(tdir, 'theme.json')),
      isGit: exists(path.join(tdir, '.git')),
      hasPackageJson: exists(path.join(tdir, 'package.json')),
      ...rm,
      likelyCustom: !rm.stableTag || exists(path.join(tdir, '.git')),
      path: tdir,
    });
  }
  // Bundled default themes are never "custom".
  for (const t of out) if (/^twenty[a-z]+$/.test(t.slug) && !t.isGit) t.likelyCustom = false;
  return out;
}

function discoverPlugins(wpContent) {
  const dir = path.join(wpContent, 'plugins');
  const out = [];
  let entries = [];
  try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const p = path.join(dir, e.name);
    if (e.isFile() && e.name.endsWith('.php')) {
      const h = parseWpHeaders(readText(p), PLUGIN_HEADERS);
      if (h['Plugin Name']) out.push({ slug: e.name.replace(/\.php$/, ''), file: e.name, name: h['Plugin Name'], version: h.Version || null, requiresPhp: h['Requires PHP'] || null, requiresWp: h['Requires at least'] || null, requiresWc: h['WC requires at least'] || null, textDomain: h['Text Domain'] || null, single: true, hasReadme: false, likelyCustom: e.name !== 'hello.php', path: p });
      continue;
    }
    if (!e.isDirectory()) continue;
    let main = null;
    let headers = null;
    let files = [];
    try { files = fs.readdirSync(p).filter((f) => f.endsWith('.php')); } catch { /* skip */ }
    // Prefer <slug>.php, then any file with a Plugin Name header.
    files.sort((a, b) => (a === `${e.name}.php` ? -1 : b === `${e.name}.php` ? 1 : 0));
    for (const f of files) {
      const h = parseWpHeaders(readText(path.join(p, f)), PLUGIN_HEADERS);
      if (h['Plugin Name']) { main = f; headers = h; break; }
    }
    if (!main) continue;
    const rm = readmeInfo(p);
    out.push({
      slug: e.name,
      file: `${e.name}/${main}`,
      name: headers['Plugin Name'],
      version: headers.Version || null,
      requiresPhp: headers['Requires PHP'] || null,
      requiresWp: headers['Requires at least'] || null,
      requiresWc: headers['WC requires at least'] || null,
      textDomain: headers['Text Domain'] || null,
      author: headers.Author || null,
      updateUri: headers['Update URI'] || null,
      isGit: exists(path.join(p, '.git')),
      hasPackageJson: exists(path.join(p, 'package.json')),
      ...rm,
      likelyCustom: !rm.stableTag || exists(path.join(p, '.git')),
      path: p,
    });
  }
  return out;
}

export function discoverBlocks(dirs) {
  const blocks = [];
  for (const d of dirs) {
    for (const f of walkFiles(d, { exts: ['.json'], exclude: ['node_modules', 'vendor', '.git'] })) {
      if (path.basename(f) !== 'block.json') continue;
      const j = readJson(f);
      blocks.push({ path: f, name: j?.name || null, apiVersion: j?.apiVersion ?? null, valid: j !== undefined && j !== null, inBuild: /[\\/](build|dist)[\\/]/.test(f) });
    }
  }
  return blocks;
}

export function discover(startDir) {
  const wpRoot = findWpRoot(startDir);
  if (!wpRoot) return { wpRoot: null };
  const wpContent = path.join(wpRoot, 'wp-content');
  const versionPhp = readText(path.join(wpRoot, 'wp-includes', 'version.php')) || '';
  const wpVersion = (versionPhp.match(/\$wp_version\s*=\s*'([^']+)'/) || [])[1] || null;
  const requiredPhp = (versionPhp.match(/\$required_php_version\s*=\s*'([^']+)'/) || [])[1] || null;
  let wpConfigPath = path.join(wpRoot, 'wp-config.php');
  if (!exists(wpConfigPath) && exists(path.join(path.dirname(wpRoot), 'wp-config.php'))) wpConfigPath = path.join(path.dirname(wpRoot), 'wp-config.php');
  const wpConfig = parseWpConfig(readText(wpConfigPath));
  const themes = discoverThemes(wpContent);
  const plugins = discoverPlugins(wpContent);
  const muDir = path.join(wpContent, 'mu-plugins');
  const muPlugins = exists(muDir) ? fs.readdirSync(muDir).filter((f) => f.endsWith('.php')) : [];
  const slugs = new Set(plugins.map((p) => p.slug));
  const pick = (list) => list.filter((s) => slugs.has(s));
  const localwp = /[\\/]Local Sites[\\/]/i.test(wpRoot) || (path.basename(wpRoot) === 'public' && path.basename(path.dirname(wpRoot)) === 'app' && exists(path.join(path.dirname(path.dirname(wpRoot)), 'conf')));
  const localSiteName = localwp ? path.basename(path.dirname(path.dirname(wpRoot))) : null;
  const customDirs = [...themes.filter((t) => t.likelyCustom), ...plugins.filter((p) => p.likelyCustom)].map((x) => x.path).filter((p) => fs.statSync(p).isDirectory());
  return {
    wpRoot,
    wpContent,
    wpConfigPath: exists(wpConfigPath) ? wpConfigPath : null,
    wpVersion,
    requiredPhp,
    wpConfig,
    themes,
    plugins,
    muPlugins,
    blocks: discoverBlocks(customDirs),
    stack: {
      builders: pick(KNOWN.builders),
      seo: pick(KNOWN.seo),
      cache: pick(KNOWN.cache),
      security: pick(KNOWN.security),
      forms: pick(KNOWN.forms),
      qa: pick(KNOWN.qa),
      multilingual: pick(KNOWN.multilingual),
      ecommerce: pick(KNOWN.ecommerce),
    },
    dropins: ['object-cache.php', 'advanced-cache.php', 'db.php', 'sunrise.php'].filter((f) => exists(path.join(wpContent, f))),
    debugLog: exists(path.join(wpContent, 'debug.log')) ? path.join(wpContent, 'debug.log') : null,
    localwp,
    localSiteName,
  };
}

/** Short human summary used in reports and `wpqa discover`. */
export function summarizeDiscovery(d) {
  if (!d.wpRoot) return 'No WordPress installation found.';
  const lines = [];
  lines.push(`WordPress ${d.wpVersion || '?'} at ${d.wpRoot}${d.localwp ? ` (LocalWP site "${d.localSiteName}")` : ''}`);
  if (d.wpConfig) {
    const c = d.wpConfig;
    lines.push(`wp-config: WP_DEBUG=${c.WP_DEBUG ?? 'unset'}, WP_DEBUG_LOG=${c.WP_DEBUG_LOG ?? 'unset'}, WP_ENVIRONMENT_TYPE=${c.WP_ENVIRONMENT_TYPE ?? 'unset'}, table_prefix=${c.tablePrefix ?? '?'}`);
  }
  lines.push(`Themes (${d.themes.length}): ` + d.themes.map((t) => `${t.slug}${t.version ? '@' + t.version : ''}${t.template ? ` (child of ${t.template})` : ''}${t.likelyCustom ? ' [custom?]' : ''}${t.isBlockTheme ? ' [block theme]' : ''}`).join(', '));
  lines.push(`Plugins (${d.plugins.length}): ` + d.plugins.map((p) => `${p.slug}${p.version ? '@' + p.version : ''}${p.likelyCustom ? ' [custom?]' : ''}`).join(', '));
  if (d.muPlugins.length) lines.push(`MU plugins: ${d.muPlugins.join(', ')}`);
  if (d.blocks.length) lines.push(`Custom blocks: ${d.blocks.filter((b) => !b.inBuild).map((b) => b.name || path.basename(path.dirname(b.path))).join(', ')}`);
  const stack = Object.entries(d.stack).filter(([, v]) => v.length).map(([k, v]) => `${k}: ${v.join(', ')}`);
  if (stack.length) lines.push(`Stack: ${stack.join(' | ')}`);
  if (d.dropins.length) lines.push(`Drop-ins: ${d.dropins.join(', ')}`);
  if (d.debugLog) lines.push(`debug.log present: ${d.debugLog}`);
  return lines.join('\n');
}
