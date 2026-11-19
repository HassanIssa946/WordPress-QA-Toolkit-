// LocalWP (localwp.com) integration: read the site's generated environment so PHP, WP-CLI and the
// database work from any terminal, not only from Local's "Open site shell".
import path from 'node:path';
import os from 'node:os';
import { readText, exists } from './util.mjs';

/** LocalWP site folder (the one holding app/, conf/, logs/) for a WordPress root at <site>/app/public. */
export function localSiteDir(wpRoot) {
  const app = path.dirname(wpRoot);
  return path.basename(app) === 'app' ? path.dirname(app) : null;
}

/**
 * Parse Local's app/.envrc (written each time the site starts):
 *   export PHPRC="C:/…/run/<id>/conf/php"
 *   export PATH="C:/…/php-8.2.29+0/bin/win64:$PATH"
 * Returns { vars: {NAME: value}, pathPrepend: [dirs in PATH order] }.
 */
export function parseEnvrc(text) {
  const vars = {};
  const pathPrepend = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    const m = line.match(/^\s*export\s+([A-Za-z_][A-Za-z0-9_]*)=(["']?)(.*)\2\s*$/);
    if (!m) continue;
    const [, name, , value] = m;
    if (name === 'PATH') {
      // Windows paths contain "C:", so strip the trailing ":$PATH" / ";$PATH" instead of splitting on ':'.
      const dir = value.replace(/[:;]\$\{?PATH\}?$/, '');
      if (dir && dir !== value) pathPrepend.unshift(dir); // later exports end up first on PATH
    } else vars[name] = value;
  }
  return { vars, pathPrepend };
}

/** Local's site registry (%APPDATA%\Local\sites.json on Windows, ~/Library/Application Support/Local on macOS). */
export function localSitesJson() {
  const candidates = [
    process.env.APPDATA && path.join(process.env.APPDATA, 'Local', 'sites.json'),
    path.join(os.homedir(), 'Library', 'Application Support', 'Local', 'sites.json'),
    path.join(os.homedir(), '.config', 'Local', 'sites.json'),
  ].filter(Boolean);
  for (const p of candidates) {
    const t = readText(p);
    if (!t) continue;
    try { return JSON.parse(t); } catch { /* ignore */ }
  }
  return null;
}

/** { id, name, domain } for a Local site folder, from sites.json. */
export function localSiteInfo(siteDir, sitesJson = localSitesJson()) {
  if (!sitesJson || !siteDir) return null;
  const norm = (p) => path.resolve(String(p).replace(/^~(?=[\\/])/, os.homedir())).toLowerCase();
  const want = norm(siteDir);
  for (const [id, s] of Object.entries(sitesJson)) {
    if (s?.path && norm(s.path) === want) return { id, name: s.name || null, domain: s.domain || null };
  }
  return null;
}

/**
 * Tool settings for wpqa.config.json derived from Local's environment.
 * Returns null when the site has no .envrc (site never started) or no PHP is found.
 */
export function localWpTools(siteDir) {
  const envrc = readText(path.join(siteDir, 'app', '.envrc'));
  if (!envrc) return null;
  const { vars, pathPrepend } = parseEnvrc(envrc);
  const fwd = (p) => p.replace(/\\/g, '/');
  const phpDir = pathPrepend.find((d) => /lightning-services[\\/]php-/i.test(d) && !/ImageMagick/i.test(d));
  const exe = process.platform === 'win32' ? 'php.exe' : 'php';
  const php = phpDir && exists(path.join(phpDir, exe)) ? fwd(path.join(phpDir, exe)) : null;
  if (!php) return null;
  const wpCliDir = pathPrepend.find((d) => /[\\/]wp-cli[\\/]/i.test(d));
  const composerDir = pathPrepend.find((d) => /[\\/]composer[\\/]/i.test(d));
  const phar = (dir, name) => {
    if (!dir) return null;
    for (const p of [path.join(dir, name), path.join(dir, '..', name)]) if (exists(p)) return fwd(path.resolve(p));
    return null;
  };
  const wpPhar = phar(wpCliDir, 'wp-cli.phar');
  const composerPhar = phar(composerDir, 'composer.phar');
  const env = {};
  for (const k of ['PHPRC', 'MYSQL_HOME', 'WP_CLI_CONFIG_PATH', 'WP_CLI_DISABLE_AUTO_CHECK_UPDATE', 'MAGICK_CODER_MODULE_PATH']) {
    if (vars[k] !== undefined) env[k] = fwd(vars[k]);
  }
  // PHP needs its ImageMagick folder (php_imagick.dll) and MySQL client tools for `wp db`; the PHP, WP-CLI and
  // Composer wrappers are referenced by absolute path above, so only the remaining folders go on PATH.
  const prepend = pathPrepend.filter((d) => /ImageMagick|[\\/]mysql-|[\\/]mariadb-/i.test(d)).map(fwd);
  return {
    php,
    wp: wpPhar ? [php, wpPhar] : 'wp',
    composer: composerPhar ? [php, composerPhar] : 'composer',
    env,
    pathPrepend: prepend,
  };
}

