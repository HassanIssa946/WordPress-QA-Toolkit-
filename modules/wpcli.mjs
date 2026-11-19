// WordPress runtime checks through WP-CLI (needs DB access).
// Every WP-CLI call is checked: output that cannot be parsed turns the check into "error" (raw output in
// artifacts) instead of being read as "nothing found".
import fs from 'node:fs';
import path from 'node:path';
import { parseJsonLoose } from '../lib/util.mjs';

const CAT = 'wordpress';

/**
 * Severity of a `wp plugin verify-checksums` problem.
 * Added/changed PHP (or JS) is how backdoors arrive → high. Plugins legitimately write non-code files at
 * runtime (All-in-One WP Migration's storage/.htaccess, web.config, index.html) → low.
 * `content` (optional, the added file's text): an added .php/.phtml/.inc file without a PHP open tag is
 * inert text — AIOWPM's storage/index.php is literally "Kangaroos cannot jump here" — so it is low too.
 */
export const hasPhpCode = (text) => /<\?(?:php\b|=)/i.test(text) || /^\s*<\?\s/.test(text);
export function classifyChecksum({ file = '', message = '', content } = {}) {
  const code = /\.(php\d?|phtml|phar|inc|js)$/i.test(file);
  if (/added|should not exist/i.test(message)) {
    const inertPhp = typeof content === 'string' && /\.(php\d?|phtml|inc)$/i.test(file) && !hasPhpCode(content);
    return code && !inertPhp ? 'high' : 'low';
  }
  if (/missing|doesn't exist|does not exist/i.test(message)) return 'medium';
  return code ? 'high' : 'medium'; // checksum mismatch
}

export default async function wpcli(run) {
  const { cfg } = run;
  const live = cfg.site.environment === 'production';
  const req = { wpcli: 'db' };
  const pluginsDir = path.join(cfg._wpRoot, 'wp-content', 'plugins');
  const themesDir = path.join(cfg._wpRoot, 'wp-content', 'themes');
  const json = (c, what, r, { allowEmpty = false } = {}) => {
    const j = parseJsonLoose(r.stdout);
    if (j !== null && j !== undefined) return j;
    if (allowEmpty && r.code === 0 && !r.stdout.trim()) return [];
    return c.toolError(what, r, 'returned no parseable JSON');
  };

  await run.check({ id: 'wpcli.core', title: 'Core integrity and updates', category: CAT, tool: 'WP-CLI', requires: req }, async (c) => {
    const u = await run.wp(['core', 'check-update', '--format=json']);
    const updates = u.code === 0 && (!u.stdout.trim() || /latest version/i.test(u.stdout)) ? [] : json(c, 'wp core check-update', u);
    if (Array.isArray(updates) && updates.length) c.finding({ severity: updates.some((x) => x.update_type === 'minor') ? 'high' : 'medium', rule: 'core.update', title: `WordPress core update available: ${updates.map((x) => `${x.version} (${x.update_type})`).join(', ')}`, recommendation: 'Minor releases are security fixes — apply promptly.' });
    const v = await run.wp(['core', 'verify-checksums']);
    if (v.code !== 0) {
      const bad = (v.stdout + '\n' + v.stderr).split('\n').filter((l) => /doesn't verify|should not exist|File doesn't exist/i.test(l));
      if (bad.length) c.finding({ severity: 'high', rule: 'core.checksums', title: `${bad.length} WordPress core file(s) modified or unexpected`, evidence: bad.slice(0, 15).join('\n'), recommendation: 'Core files must not be edited. Investigate (possible compromise), then run: wp core download --force --skip-content' });
      else c.toolError('wp core verify-checksums', v, 'failed without listing files (core integrity NOT verified)');
    }
  });

  await run.check({ id: 'wpcli.plugins', title: 'Plugins & themes: updates, inactive, checksums', category: CAT, tool: 'WP-CLI', requires: req }, async (c) => {
    const plr = await run.wp(['plugin', 'list', '--format=json', '--fields=name,status,version,update,update_version']);
    const pl = json(c, 'wp plugin list', plr);
    for (const p of pl) {
      if (p.update === 'available') c.finding({ severity: 'medium', rule: 'plugin.update', title: `Plugin ${p.name} ${p.version} → ${p.update_version} available`, file: path.join(pluginsDir, p.name), dedupeKey: `update:plugin:${p.name}`, recommendation: 'Update (staging first).' });
      if (p.status === 'inactive') c.finding({ severity: 'low', rule: 'plugin.inactive', title: `Inactive plugin installed: ${p.name}`, aggregate: true, recommendation: 'Delete unused plugins — inactive code can still be attacked directly.' });
    }
    const thr = await run.wp(['theme', 'list', '--format=json', '--fields=name,status,version,update,update_version']);
    const th = json(c, 'wp theme list', thr);
    for (const t of th) if (t.update === 'available') c.finding({ severity: 'medium', rule: 'theme.update', title: `Theme ${t.name} ${t.version} → ${t.update_version} available`, file: path.join(themesDir, t.name), dedupeKey: `update:theme:${t.name}` });
    // Exit 0 + empty stdout = everything verified. Exit 1 + JSON = some files differ.
    // Exit 1 + empty stdout + "(… skipped)" = only premium/custom plugins without wordpress.org checksums.
    const ck = await run.wp(['plugin', 'verify-checksums', '--all', '--format=json']);
    const onlySkipped = !ck.stdout.trim() && /Only verified \d+ of \d+ plugins? \((?:0 failed, )?\d+ skipped\)/i.test(ck.stderr);
    const bad = (ck.code === 0 && !ck.stdout.trim()) || onlySkipped ? [] : json(c, 'wp plugin verify-checksums', ck);
    if (!Array.isArray(bad)) c.toolError('wp plugin verify-checksums', ck, 'did not return a list');
    for (const b of bad.filter((x) => !cfg.scan.plugins.includes(x.plugin_name))) {
      const abs = path.join(pluginsDir, b.plugin_name, b.file);
      let content;
      try { if (fs.statSync(abs).size <= 1024 * 1024) content = fs.readFileSync(abs, 'latin1'); } catch { /* missing or unreadable → classify by name only */ }
      const severity = classifyChecksum({ ...b, content });
      const inert = severity === 'low' && /\.(php\d?|phtml|inc)$/i.test(b.file);
      c.finding({
        severity, rule: 'plugin.checksums', title: `Plugin ${b.plugin_name}: ${b.file} — ${b.message}${inert ? ' (no PHP code in it)' : ''}`, file: abs, aggregate: false,
        recommendation: severity === 'low'
          ? 'File that differs from the wordpress.org copy but contains no executable code; plugins often create these at runtime (e.g. an .htaccess or placeholder index.php protecting a backup folder). Confirm the content is harmless.'
          : 'Reinstall the plugin from wordpress.org and investigate why its files changed.',
      });
    }
    const unverifiable = (ck.stderr.match(/Could not retrieve the checksums for (?:version \S+ of )?plugin ([\w-]+)/gi) || []).length;
    if (unverifiable) c.note(`${unverifiable} plugin(s) have no wordpress.org checksums (premium/custom) and were not verified`);
    c.stats = { plugins: pl.length, themes: th.length };
  });

  await run.check({ id: 'wpcli.settings', title: 'Security & SEO-critical settings and users', category: CAT, tool: 'WP-CLI', requires: req }, async (c) => {
    const opt = async (k) => {
      const r = await run.wp(['option', 'get', k]);
      if (r.code !== 0) c.toolError(`wp option get ${k}`, r, 'failed');
      return r.stdout.trim();
    };
    if ((await opt('blog_public')) === '0') c.finding({ severity: live ? 'critical' : 'info', rule: 'settings.noindex', title: 'Search engines discouraged (Settings → Reading)', recommendation: live ? 'Untick "Discourage search engines" on the live site.' : 'Normal for local/staging; remember to untick it at launch.' });
    if ((await opt('users_can_register')) === '1') {
      const role = await opt('default_role');
      c.finding({ severity: ['administrator', 'editor', 'shop_manager'].includes(role) ? 'critical' : 'medium', rule: 'settings.registration', title: `Anyone can register (default role: ${role})`, recommendation: 'Disable "Anyone can register" unless needed; never with a privileged default role.' });
    }
    if (!(await opt('permalink_structure'))) c.finding({ severity: 'medium', rule: 'settings.permalinks', title: 'Plain permalinks (?p=123)', recommendation: 'Use /%postname%/ for SEO and clean REST URLs.' });
    const ur = await run.wp(['user', 'list', '--role=administrator', '--format=json', '--fields=user_login']);
    const admins = json(c, 'wp user list', ur);
    if (admins.some((u) => /^(admin|administrator)$/i.test(u.user_login))) c.finding({ severity: 'medium', rule: 'users.admin-login', title: 'An administrator uses the username "admin"', recommendation: 'Create a new admin with a unique username and delete "admin" (attribute content to the new user).' });
    if (admins.length > 3) c.finding({ severity: 'low', rule: 'users.many-admins', title: `${admins.length} administrator accounts`, recommendation: 'Reduce to the people who really need full access.' });
  });

  await run.check({ id: 'wpcli.plugin-check', title: 'Plugin Check (official) on custom plugins', category: CAT, tool: 'Plugin Check', requires: req }, async (c) => {
    const plugins = run.customDirs.filter((d) => d.type === 'plugin');
    if (!plugins.length) return c.notApplicable('no custom plugin configured');
    if ((await run.wp(['plugin', 'is-active', 'plugin-check'])).code !== 0) return c.skip('Plugin Check plugin not active', 'wp plugin install plugin-check --activate (local/staging only)');
    c.scope(plugins.map((p) => p.dir));
    for (const p of plugins) {
      const r = await run.wp(['plugin', 'check', p.slug, '--format=json'], { timeoutMs: 10 * 60 * 1000 });
      const blocks = (r.stdout.match(/FILE: .+\n\[[\s\S]*?\]\n?/g) || []);
      if (!blocks.length && !(r.code === 0 && /no errors|^\s*$/i.test(r.stdout))) c.toolError(`wp plugin check ${p.slug}`, r, 'output not recognised');
      for (const b of blocks) {
        const file = b.match(/FILE: (.+)/)[1].trim();
        const list = parseJsonLoose(b.slice(b.indexOf('[')));
        if (!Array.isArray(list)) c.toolError(`wp plugin check ${p.slug}`, r, `could not parse results for ${file}`);
        for (const m of list) c.finding({ severity: m.type === 'ERROR' ? 'medium' : 'low', rule: m.code, title: `Plugin Check: ${m.code}`, message: m.message, file: `${p.dir}/${file}`, line: m.line, aggregate: m.type !== 'ERROR', recommendation: m.docs || null });
      }
    }
  });

  await run.check({ id: 'wpcli.theme-check', title: 'Theme Check (official) on custom theme', category: CAT, tool: 'Theme Check', requires: req }, async (c) => {
    const themes = run.customDirs.filter((d) => d.type === 'theme');
    if (!themes.length) return c.notApplicable('no custom theme configured');
    if ((await run.wp(['plugin', 'is-active', 'theme-check'])).code !== 0) return c.skip('Theme Check plugin not active', 'wp plugin install theme-check --activate (local/staging only)');
    c.scope(themes.map((t) => t.dir));
    for (const t of themes) {
      const r = await run.wp(['theme-check', 'run', t.slug, '--format=json'], { timeoutMs: 10 * 60 * 1000 });
      const j = parseJsonLoose(r.stdout);
      const list = Array.isArray(j) ? j : j?.messages;
      if (!Array.isArray(list)) c.toolError(`wp theme-check run ${t.slug}`, r, 'output not recognised');
      for (const m of list) {
        const type = String(m.type || m.level || '').toUpperCase();
        if (/INFO|RECOMMENDED/.test(type)) continue;
        c.finding({ severity: /REQUIRED|ERROR/.test(type) ? 'medium' : 'low', rule: 'theme-check', title: `Theme Check: ${String(m.message || m.value || m).replace(/<[^>]+>/g, '').slice(0, 160)}`, file: t.dir, aggregate: false });
      }
    }
  });
}
