// Static security: built-in WordPress pattern scanner, secrets, wp-config hardening, Semgrep (optional).
import fs from 'node:fs';
import path from 'node:path';
import { TOOLKIT_ROOT, walkFiles, readText, lineOf, parseJsonLoose, exists } from '../lib/util.mjs';

const CAT = 'security';
const SUPERGLOBAL = /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/;
const ESCAPED = /\b(esc_html|esc_attr|esc_url|esc_js|esc_textarea|esc_xml|wp_kses\w*|intval|absint|floatval|sanitize_\w+|number_format|json_encode|wp_json_encode|htmlspecialchars|htmlentities|\(int\)|\(float\))\b/;

/** Return the text of a balanced (...) starting at index of '('. Skips strings and comments. */
export function balanced(text, openIdx, open = '(', close = ')') {
  let depth = 0;
  for (let i = openIdx; i < text.length; i++) {
    const ch = text[i];
    if (ch === "'" || ch === '"') {
      const q = ch; i++;
      while (i < text.length && text[i] !== q) { if (text[i] === '\\') i++; i++; }
      continue;
    }
    if (ch === '/' && text[i + 1] === '/') { while (i < text.length && text[i] !== '\n') i++; continue; }
    if (ch === '/' && text[i + 1] === '*') { const e = text.indexOf('*/', i + 2); i = e < 0 ? text.length : e + 1; continue; }
    if (ch === open) depth++;
    else if (ch === close) { depth--; if (depth === 0) return text.slice(openIdx, i + 1); }
  }
  return text.slice(openIdx);
}

/** Statement ending at ';' from idx (simple, for single-statement heuristics). */
function statementAt(text, idx) {
  let s = idx;
  while (s > 0 && !';{}\n'.includes(text[s - 1])) s--;
  let e = text.indexOf(';', idx);
  if (e < 0) e = Math.min(text.length, idx + 400);
  return text.slice(s, e + 1);
}

function findFunctionBody(allPhp, name) {
  const re = new RegExp(`function\\s+&?\\s*${name.replace(/[^\w]/g, '')}\\s*\\(`, 'g');
  for (const { file, text } of allPhp) {
    const m = re.exec(text); re.lastIndex = 0;
    if (m) {
      const brace = text.indexOf('{', m.index + m[0].length - 1 + balanced(text, m.index + m[0].length - 1).length);
      if (brace > 0) return { file, line: lineOf(text, m.index), body: balanced(text, brace, '{', '}') };
    }
  }
  return null;
}

const rel0 = (f) => String(f).split(path.sep).slice(-3).join('/');

/** Body of a register_rest_route() 'callback' (named function, static method string/array, or inline closure). */
function restCallbackBody(call, allPhp = []) {
  const m = call.match(/['"]callback['"]\s*=>\s*/);
  if (!m) return null;
  const rest = call.slice(m.index + m[0].length);
  const closure = rest.match(/^(?:static\s+)?(?:function\s*\([^)]*\)\s*(?:use\s*\([^)]*\)\s*)?(?::\s*[\w\\?|]+\s*)?|fn\s*\()/);
  if (closure) {
    const brace = rest.indexOf('{');
    return { name: 'closure', body: brace >= 0 ? balanced(rest, brace, '{', '}') : rest.slice(0, 400) };
  }
  const arg = rest.match(/^(array\s*\([^)]*\)|\[[^\]]*\]|['"][^'"]+['"])/);
  const name = arg ? handlerName(arg[1]) : null;
  const fn = name ? findFunctionBody(allPhp, name) : null;
  return fn ? { name, body: fn.body } : null;
}

function handlerName(arg) {
  const s = arg.trim();
  let m = s.match(/^['"]([\w\\]+)['"]$/); if (m) return m[1].split('\\').pop();
  m = s.match(/['"](\w+)['"]\s*\)?\s*\]?\s*$/); if (m) return m[1];
  return null;
}

export function scanPhp(file, text, ctx) {
  const out = [];
  const add = (idx, f) => out.push({ ...f, file, line: lineOf(text, idx), evidence: f.evidence ?? text.split('\n')[lineOf(text, idx) - 1]?.trim() });
  let m;

  // 1. Output of raw request data.
  const echoRe = /(?:\becho\b|\bprint\b|<\?=)([^;]*?)(?:;|\?>)/g;
  while ((m = echoRe.exec(text))) {
    if (SUPERGLOBAL.test(m[1]) && !ESCAPED.test(m[1])) add(m.index, { severity: 'high', rule: 'wp.xss.echo-request', title: 'Request data printed without escaping (reflected XSS)', dedupeKey: 'xss', confidence: 'likely', recommendation: 'Escape on output: esc_html( wp_unslash( $_GET[...] ) ), esc_attr() in attributes, esc_url() for URLs.' });
  }

  // 2. $wpdb queries built from variables without prepare().
  const dbRe = /\$wpdb\s*->\s*(query|get_results|get_row|get_var|get_col)\s*\(/g;
  while ((m = dbRe.exec(text))) {
    const call = balanced(text, m.index + m[0].length - 1);
    if (/\bprepare\s*\(/.test(call)) continue;
    // WordPress table names ({$wpdb->postmeta}, $wpdb->prefix . 'x') are trusted, not user input.
    const sql = call.replace(/\{\$wpdb\s*->\s*\w+\}|\$wpdb\s*->\s*\w+(?!\s*\()/g, 'WPDB_TABLE');
    const interpolated = /"[^"]*\$\w+[^"]*"/.test(sql) || /\.\s*\$\w+|\$\w+\s*\./.test(sql) || /\(\s*\$\w+\s*[,)]/.test(sql);
    if (!interpolated) continue;
    const userInput = SUPERGLOBAL.test(call) || SUPERGLOBAL.test(statementAt(text, m.index));
    add(m.index, { severity: userInput ? 'critical' : 'high', rule: 'wp.sqli.unprepared', title: userInput ? 'SQL injection: request data in $wpdb query without prepare()' : 'SQL query built from variables without $wpdb->prepare()', dedupeKey: 'sqli', confidence: userInput ? 'likely' : 'heuristic', evidence: call.slice(0, 300), recommendation: '$wpdb->get_results( $wpdb->prepare( "SELECT … WHERE id = %d AND slug = %s", $id, $slug ) ). Use %i for identifiers (WP 6.2+).' });
  }

  // 3. REST routes: missing or public permission_callback.
  const restRe = /register_rest_route\s*\(/g;
  while ((m = restRe.exec(text))) {
    const call = balanced(text, m.index + m[0].length - 1);
    const route = (call.match(/\(\s*['"]([^'"]+)['"]\s*,\s*['"]([^'"]+)['"]/) || []).slice(1).join('');
    const write = /(POST|PUT|PATCH|DELETE|CREATABLE|EDITABLE|DELETABLE|ALLMETHODS)/.test(call);
    if (!/permission_callback/.test(call)) {
      add(m.index, { severity: write ? 'critical' : 'high', rule: 'wp.rest.no-permission-callback', title: `REST route ${route || ''} has no permission_callback${write ? ' and accepts writes' : ''}`, evidence: call.slice(0, 300), recommendation: "Add 'permission_callback' => fn() => current_user_can( 'edit_posts' ) (or the right capability). Use '__return_true' only for intentionally public read-only routes." });
    } else if (/permission_callback['"]\s*=>\s*['"]__return_true['"]/.test(call) || /permission_callback['"]\s*=>\s*(?:function\s*\([^)]*\)\s*\{\s*return\s+true|fn\s*\([^)]*\)\s*=>\s*true)/.test(call)) {
      if (!write) {
        ctx.notes?.push(`Public read-only REST route ${route} (${rel0(file)}:${lineOf(text, m.index)}) — confirm it never returns emails, private meta or drafts.`);
        continue;
      }
      // A public write route is normal for front-end forms if the callback itself verifies a nonce or a capability.
      const cb = restCallbackBody(call, ctx.allPhp);
      const guard = cb && /\b(wp_verify_nonce|check_ajax_referer|check_admin_referer|current_user_can)\s*\(/.exec(cb.body);
      if (guard) {
        ctx.notes?.push(`Public REST write route ${route} (${rel0(file)}:${lineOf(text, m.index)}) — callback ${cb.name}() checks ${guard[1]}(); confirm it also validates input and limits abuse (rate limit/spam).`);
        continue;
      }
      add(m.index, { severity: 'high', rule: 'wp.rest.public-write', title: `REST route ${route} allows unauthenticated writes (permission_callback always true, no nonce/capability check in the callback)`, evidence: call.slice(0, 300), recommendation: 'Check a capability, or verify a nonce in the callback (wp_verify_nonce). If it is a public form endpoint, add rate limiting, validation and spam protection.' });
    }
  }

  // 4. AJAX / admin-post handlers without nonce or capability checks.
  const ajaxRe = /add_action\s*\(\s*['"](wp_ajax_nopriv_|wp_ajax_|admin_post_nopriv_|admin_post_)([\w-]+)['"]\s*,([^;]+?)\)\s*;/g;
  while ((m = ajaxRe.exec(text))) {
    const pub = m[1].includes('nopriv');
    const fn = handlerName(m[3]);
    const body = fn ? findFunctionBody(ctx.allPhp, fn) : null;
    if (!body) continue;
    const hasNonce = /check_ajax_referer|wp_verify_nonce|check_admin_referer/.test(body.body);
    const hasCap = /current_user_can/.test(body.body);
    const changes = /update_option|update_(post|user|term)_meta|wp_insert_|wp_update_|wp_delete_|\$wpdb\s*->\s*(insert|update|delete|query)|wp_mail|move_uploaded_file|file_put_contents/.test(body.body);
    if (!hasNonce && (changes || !pub)) out.push({ severity: changes ? 'high' : 'medium', rule: 'wp.csrf.ajax-no-nonce', title: `${pub ? 'Public' : 'Logged-in'} AJAX/admin-post handler "${fn}" has no nonce check${changes ? ' and changes data' : ''} (CSRF)`, file: body.file, line: body.line, evidence: `add_action('${m[1]}${m[2]}', …) → ${fn}()`, confidence: 'likely', recommendation: "Send a nonce from the page (wp_create_nonce('action')) and call check_ajax_referer('action') first in the handler." });
    if (!pub && changes && !hasCap) out.push({ severity: 'high', rule: 'wp.authz.ajax-no-capability', title: `AJAX handler "${fn}" changes data without current_user_can() (any logged-in user, incl. subscribers)`, file: body.file, line: body.line, confidence: 'likely', recommendation: "Add if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( null, 403 ); }" });
  }

  // 5. Dangerous functions / patterns.
  const danger = [
    [/\beval\s*\(/g, 'critical', 'wp.rce.eval', 'eval() used', 'Remove eval(); it executes arbitrary PHP. Combined with base64_decode it is a typical backdoor signature.'],
    [/\b(shell_exec|passthru|system|proc_open|popen|pcntl_exec)\s*\(|`[^`\n]*\$\w+[^`\n]*`/g, 'high', 'wp.rce.shell', 'Shell command execution', 'Avoid shell execution; if unavoidable, use escapeshellarg() on every argument and never pass request data.'],
    [/\bexec\s*\(\s*[$'"]/g, 'high', 'wp.rce.shell', 'Shell command execution', 'Avoid shell execution; if unavoidable, use escapeshellarg().'],
    [/\b(unserialize|maybe_unserialize)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)/g, 'critical', 'wp.objinj.unserialize', 'unserialize() on request data (PHP object injection)', 'Use json_decode() for client data.'],
    [/\b(include|require)(_once)?\s*\(?[^;]*\$_(GET|POST|REQUEST|COOKIE)/g, 'critical', 'wp.lfi.include', 'File inclusion from request data', 'Never build include paths from input; map allowed values to fixed files.'],
    [/\bextract\s*\(\s*\$_(GET|POST|REQUEST)/g, 'high', 'wp.extract-request', 'extract() on request data (variable injection)', 'Read the needed keys explicitly and sanitize them.'],
    [/\b(wp_redirect|header\s*\(\s*['"]Location)[^;]*\$_(GET|POST|REQUEST)/g, 'medium', 'wp.open-redirect', 'Redirect target taken from request (open redirect)', 'Use wp_safe_redirect() + wp_validate_redirect().'],
    [/\b(file_get_contents|fopen|readfile|wp_remote_(get|post|request)|curl_setopt)\s*\([^;]*\$_(GET|POST|REQUEST)/g, 'high', 'wp.ssrf-file', 'File/URL access built from request data (SSRF / file disclosure)', 'Allow-list hosts/paths; use wp_safe_remote_get().'],
    [/\bcreate_function\s*\(|preg_replace\s*\(\s*['"]([^'"\w]).*\1[a-z]*e[a-z]*['"]/g, 'high', 'wp.rce.legacy', 'Removed/unsafe PHP code execution API', 'Replace with closures / preg_replace_callback.'],
    [/move_uploaded_file\s*\(/g, 'medium', 'wp.upload.raw', 'Raw move_uploaded_file() (bypasses WordPress upload checks)', 'Use wp_handle_upload()/media_handle_upload() with an allowed mime list and a capability check.'],
  ];
  for (const [re, severity, rule, title, recommendation] of danger) {
    re.lastIndex = 0;
    while ((m = re.exec(text))) add(m.index, { severity, rule, title, recommendation, confidence: 'likely' });
  }
  if (/\beval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress)/.test(text)) add(text.search(/\beval\s*\(/), { severity: 'critical', rule: 'wp.malware.obfuscated', title: 'Obfuscated eval — possible backdoor/malware', recommendation: 'Treat the site as compromised until this file is explained; compare with a clean copy.' });

  // 6. POST forms without nonce field (file level).
  const formIdx = text.search(/<form[^>]*method\s*=\s*["']?post/i);
  // settings_fields() prints the options.php nonce; wp_nonce_field()/wp_create_nonce() are the manual way.
  if (formIdx >= 0 && !/wp_nonce_field|wp_create_nonce|_wpnonce|settings_fields\s*\(/.test(text) && !/wpcf7|gform|wpforms/i.test(text)) add(formIdx, { severity: 'medium', rule: 'wp.csrf.form-no-nonce', title: 'POST form without a WordPress nonce field', confidence: 'heuristic', recommendation: "Add wp_nonce_field( 'my_action', 'my_nonce' ) and verify it in the handler." });

  // 7. Direct access guard (plugins only).
  if (ctx.type === 'plugin' && /^\s*<\?php/.test(text) && !/defined\s*\(\s*['"](ABSPATH|WPINC|WP_UNINSTALL_PLUGIN)['"]\s*\)/.test(text) && /(add_action|add_filter|echo|\$_(GET|POST))/.test(text)) {
    add(0, { severity: 'low', rule: 'wp.direct-access', title: 'Plugin file executes code without an ABSPATH guard', confidence: 'heuristic', evidence: '', recommendation: "Add at the top: defined( 'ABSPATH' ) || exit;" });
  }
  return out;
}

const SECRET_PATTERNS = [
  [/AKIA[0-9A-Z]{16}/, 'AWS access key'],
  [/AIza[0-9A-Za-z_-]{35}/, 'Google API key'],
  [/sk_live_[0-9a-zA-Z]{20,}/, 'Stripe live secret key'],
  [/-----BEGIN (RSA |EC |OPENSSH |)PRIVATE KEY-----/, 'Private key'],
  [/xox[baprs]-[0-9A-Za-z-]{10,}/, 'Slack token'],
  [/gh[pousr]_[0-9A-Za-z]{36}/, 'GitHub token'],
  [/SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/, 'SendGrid API key'],
  [/(?:api[_-]?key|secret|token|passw(?:or)?d|client_secret)['"]?\s*(?:=>|=|:)\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/i, 'Hard-coded credential'],
];

export default async function security(run) {
  const { cfg } = run;
  const phpFiles = run.customFiles((d) => walkFiles(d, { exts: ['.php'], exclude: cfg.scan.exclude }));
  const textFiles = run.customFiles((d) => walkFiles(d, { exts: ['.php', '.js', '.mjs', '.json', '.env', '.ini', '.yml', '.yaml', '.txt'], exclude: cfg.scan.exclude }));

  await run.check({ id: 'security.wp-patterns', title: 'WordPress security patterns (XSS, SQLi, REST, AJAX/CSRF, RCE)', category: CAT, tool: 'wpqa scanner', requires: { customCode: true } }, async (c) => {
    if (!phpFiles.length) return c.notApplicable('no PHP files in scope');
    // Handlers may live in files other than where add_action is called → index all custom PHP.
    const allPhp = run.customFiles((d) => walkFiles(d, { exts: ['.php'], exclude: cfg.scan.exclude })).map((f) => ({ file: f, text: readText(f) || '' }));
    const typeOf = (f) => run.customDirs.find((d) => f.startsWith(d.dir))?.type;
    const notes = [];
    c.scope(phpFiles);
    for (const f of phpFiles) {
      const text = readText(f);
      if (!text) continue;
      for (const finding of scanPhp(f, text, { allPhp, type: typeOf(f), notes })) c.finding({ ...finding, tool: 'wpqa scanner' });
    }
    c.stats.files = phpFiles.length;
    c.note('Heuristic scanner: confirm each finding by reading the code before fixing.');
    for (const n of notes) c.note(n);
  });

  await run.check({ id: 'security.secrets', title: 'Hard-coded secrets and keys', category: CAT, tool: 'wpqa scanner', requires: { customCode: true } }, async (c) => {
    c.scope(textFiles);
    c.scope(['.env', '.env.local', '.env.production', 'auth.json', '.git/config'].map((f) => path.join(cfg._wpRoot, f)));
    for (const f of textFiles) {
      const text = readText(f, 2 * 1024 * 1024);
      if (!text) continue;
      const lines = text.split('\n');
      lines.forEach((ln, i) => {
        if (ln.length > 2000) return;
        for (const [re, label] of SECRET_PATTERNS) {
          if (re.test(ln) && !/(example|placeholder|your[_-]?key|xxxx|changeme|<[^>]+>|getenv|\$_ENV|defined\()/i.test(ln)) {
            c.finding({ severity: label === 'Hard-coded credential' ? 'medium' : 'high', rule: 'secret.' + label.toLowerCase().replace(/\W+/g, '-'), title: `${label} in source code`, file: f, line: i + 1, evidence: ln.trim().replace(/(['"])[A-Za-z0-9_\-+/=]{8,}(['"])/g, '$1•••redacted•••$2').slice(0, 200), confidence: label === 'Hard-coded credential' ? 'heuristic' : 'likely', recommendation: 'Move it to wp-config.php constants or environment variables, rotate the key, and purge it from git history.' });
            break;
          }
        }
      });
    }
    const pub = cfg._wpRoot;
    for (const f of ['.env', '.env.local', '.env.production', 'auth.json', '.git/config']) {
      if (exists(path.join(pub, f))) c.finding({ severity: 'high', rule: 'secret.webroot-file', title: `${f} inside the web root`, file: path.join(pub, f), recommendation: 'Move it outside the public folder or block it in the server config; verify with the infrastructure exposure check.' });
    }
  });

  await run.check({ id: 'security.wp-config', title: 'wp-config.php hardening', category: CAT, tool: 'wpqa' }, async (c) => {
    const w = run.facts.wpConfig;
    if (!w) return c.skip('wp-config.php not found', 'Set project.wpPath to the WordPress root.');
    const file = run.facts.wpConfigPath;
    const live = cfg.site.environment !== 'local';
    if (w.saltsPlaceholder || !w.hasSalts) c.finding({ severity: 'critical', rule: 'wpconfig.salts', title: 'Authentication keys/salts missing or still placeholders', file, recommendation: 'Generate new ones: https://api.wordpress.org/secret-key/1.1/salt/' });
    if (w.WP_DEBUG === true && w.WP_DEBUG_DISPLAY !== false) c.finding({ severity: live ? 'high' : 'info', rule: 'wpconfig.debug-display', title: 'WP_DEBUG on with errors displayed', file, recommendation: live ? "On staging/production: WP_DEBUG false, or WP_DEBUG_DISPLAY false + WP_DEBUG_LOG to a non-public path." : 'OK for local development; make sure it is off on the live server.' });
    if (w.DISALLOW_FILE_EDIT !== true) c.finding({ severity: live ? 'medium' : 'low', rule: 'wpconfig.file-edit', title: 'Theme/plugin file editor enabled (DISALLOW_FILE_EDIT not set)', file, recommendation: "define( 'DISALLOW_FILE_EDIT', true ); — an admin-account takeover then can't directly edit PHP." });
    if (w.tablePrefix === 'wp_') c.finding({ severity: 'info', rule: 'wpconfig.prefix', title: 'Default table prefix wp_', file, recommendation: 'Low value hardening; only change on new installs.' });
    if (live && cfg.site.url.startsWith('https') && w.FORCE_SSL_ADMIN === false) c.finding({ severity: 'medium', rule: 'wpconfig.ssl-admin', title: 'FORCE_SSL_ADMIN explicitly disabled', file });
    if (live && !w.WP_ENVIRONMENT_TYPE) c.finding({ severity: 'info', rule: 'wpconfig.env-type', title: 'WP_ENVIRONMENT_TYPE not set', file, recommendation: "define( 'WP_ENVIRONMENT_TYPE', 'staging' ) on staging so plugins can disable emails/indexing." });
  });

  await run.check({ id: 'security.semgrep', title: 'Semgrep taint rules (WordPress + PHP)', category: CAT, tool: 'Semgrep', requires: { customCode: true, tools: ['semgrep'] } }, async (c) => {
    const rules = path.join(TOOLKIT_ROOT, 'rules', 'semgrep', 'wordpress.yml');
    const targets = run.changedFiles ? phpFiles : run.customDirs.map((d) => d.dir);
    if (!targets.length) return c.notApplicable('no files in scope');
    const { runTool } = await import('../lib/util.mjs');
    c.scope(run.changedFiles ? phpFiles : run.customDirs.map((d) => d.dir));
    const r = await runTool(cfg.tools.semgrep, ['scan', '--config', rules, '--json', '--metrics=off', '--quiet', '--disable-version-check', '--exclude=vendor', '--exclude=node_modules', '--exclude=build', ...targets], { timeoutMs: 15 * 60 * 1000, cwd: cfg._root, env: { SEMGREP_SEND_METRICS: 'off', ...run.toolEnv() } });
    const json = parseJsonLoose(r.stdout);
    if (!json?.results || r.timedOut || ![0, 1].includes(r.code)) c.toolError('Semgrep', r, json?.results ? 'exited abnormally' : 'produced no JSON report');
    for (const x of json.results) {
      const sev = { ERROR: 'high', WARNING: 'medium', INFO: 'low' }[x.extra?.severity] || 'medium';
      const rule = x.check_id.split('.').pop();
      c.finding({ severity: x.extra?.metadata?.wpqa_severity || sev, tool: 'Semgrep', rule, title: x.extra?.message?.split('\n')[0] || rule, file: x.path, line: x.start?.line, evidence: x.extra?.lines, dedupeKey: x.extra?.metadata?.dedupe, confidence: 'likely', recommendation: x.extra?.metadata?.fix });
    }
  });
}

export const _test = { scanPhp, balanced, fs };
