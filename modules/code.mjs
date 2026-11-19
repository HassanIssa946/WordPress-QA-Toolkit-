// Code quality: PHP lint, PHPCS (WPCS + PHPCompatibility), PHPStan, ESLint, Stylelint.
import fs from 'node:fs';
import path from 'node:path';
import { TOOLKIT_ROOT, walkFiles, pMap, parseJsonLoose, exists, rel, readText } from '../lib/util.mjs';

const CAT = 'code';
const VENDOR = path.join(TOOLKIT_ROOT, 'vendor');

export default async function code(run) {
  const { cfg } = run;
  const phpFiles = run.customFiles((d) => walkFiles(d, { exts: ['.php'], exclude: cfg.scan.exclude }));
  const jsFiles = run.customFiles((d) => walkFiles(d, { exts: ['.js', '.mjs', '.cjs', '.jsx'], exclude: cfg.scan.exclude }));
  const cssFiles = run.customFiles((d) => walkFiles(d, { exts: ['.css'], exclude: cfg.scan.exclude }));
  const targets = run.changedFiles ? null : run.customDirs.map((d) => d.dir);

  /* --------------------------- php -l --------------------------- */
  await run.check({ id: 'code.php-lint', title: 'PHP syntax (php -l)', category: CAT, tool: 'php -l', requires: { customCode: true, tools: ['php'] } }, async (c) => {
    if (!phpFiles.length) return c.notApplicable('no PHP files in scope');
    c.scope(phpFiles);
    c.stats.files = phpFiles.length;
    const failures = [];
    await pMap(phpFiles, async (f) => {
      const r = await run.php(['-l', f], { timeoutMs: 30000 });
      if (r.code === 0) return;
      const out = (r.stdout + '\n' + r.stderr).trim();
      if (/Parse error|syntax error|Fatal error/i.test(out)) {
        const m = out.match(/on line (\d+)/);
        c.finding({ severity: 'critical', rule: 'php-syntax', title: 'PHP syntax error (fatal on load)', file: f, line: m ? Number(m[1]) : null, evidence: out.split('\n').find((l) => /error/i.test(l)) || out, recommendation: 'Fix the syntax error; this file will crash any request that loads it.' });
      } else failures.push(r);
    }, 6);
    // php itself failed (crash, timeout, missing extension) — that is not a syntax error and not a pass.
    if (failures.length) c.toolError('php -l', failures[0], `failed on ${failures.length} file(s) without reporting a syntax error`);
    c.note(`${phpFiles.length} PHP file(s) linted`);
  });

  /* --------------------------- PHPCS ---------------------------- */
  const phpcsBin = path.join(VENDOR, 'squizlabs', 'php_codesniffer', 'bin', 'phpcs');
  await run.check({ id: 'code.phpcs', title: 'WordPress Coding Standards + PHP compatibility (PHPCS)', category: CAT, tool: 'PHPCS/WPCS', requires: { customCode: true, tools: ['php'] } }, async (c) => {
    if (!exists(phpcsBin)) return c.skip('PHPCS not installed in toolkit', `Run "composer install" in ${TOOLKIT_ROOT}`);
    const files = run.changedFiles ? phpFiles : targets;
    if (!files.length || !phpFiles.length) return c.notApplicable('no PHP files in scope');
    c.scope(phpFiles);
    const standard = cfg.code.phpcsStandard ? path.resolve(cfg._root, cfg.code.phpcsStandard) : path.join(TOOLKIT_ROOT, 'config', 'phpcs.xml');
    const installed = ['wp-coding-standards/wpcs', 'phpcompatibility/php-compatibility', 'phpcompatibility/phpcompatibility-paragonie', 'phpcompatibility/phpcompatibility-wp', 'phpcsstandards/phpcsutils', 'phpcsstandards/phpcsextra']
      .map((p) => path.join(VENDOR, ...p.split('/'))).filter(exists);
    const args = ['-d', 'memory_limit=1G', phpcsBin, `--standard=${standard}`, '--report=json', '-q', '--no-colors',
      '--runtime-set', 'testVersion', cfg.code.phpVersion, '--runtime-set', 'installed_paths', installed.join(','), ...files];
    const r = await run.php(args, { timeoutMs: 15 * 60 * 1000, cwd: cfg._root });
    const json = parseJsonLoose(r.stdout);
    // PHPCS exits 0 (clean), 1/2 (violations); anything else, or no JSON, means it did not finish.
    if (!json?.files || r.timedOut || ![0, 1, 2].includes(r.code)) c.toolError('PHPCS', r, json?.files ? 'exited abnormally' : 'produced no JSON report');
    let fixable = 0;
    const internal = [];
    for (const [file, data] of Object.entries(json.files)) {
      for (const m of data.messages || []) {
        if (m.source?.startsWith('Internal.')) {
          if (/Internal\.(Exception|Tokenizer)/.test(m.source)) internal.push(`${file}: ${m.message}`);
          continue;
        }
        if (m.fixable) fixable++;
        const map = classifyPhpcs(m, file);
        const group = (m.source || '').split('.').slice(0, 3).join('.');
        c.finding({ ...map, tool: 'PHPCS', rule: map.rule || (map.title ? group : m.source), title: map.title || m.message, message: map.title ? m.message : null, file, line: m.line, fingerprintExtra: map.aggregate ? '' : map.title ? m.line : m.message });
      }
    }
    if (internal.length) {
      // A sniff crashed on these files: they were only partly checked.
      const art = path.join(run.artifactDir('code.phpcs'), 'phpcs-internal-errors.txt');
      fs.writeFileSync(art, internal.join('\n') + '\n');
      c.artifact(art, 'PHPCS internal errors');
      c.finding({ severity: 'low', rule: 'phpcs.internal', title: `PHPCS could not fully check ${internal.length} file(s) (sniff crashed)`, evidence: internal.slice(0, 5).join('\n'), recommendation: 'See the artifact; these files may hide unreported issues.' });
    }
    c.stats = { errors: json.totals?.errors, warnings: json.totals?.warnings, fixable };
    if (fixable) c.note(`${fixable} issue(s) auto-fixable with phpcbf`);
    const phpcbf = path.join(VENDOR, 'squizlabs', 'php_codesniffer', 'bin', 'phpcbf');
    if (fixable) c.finding({ severity: 'info', rule: 'phpcbf', title: `${fixable} coding-standard issue(s) can be fixed automatically`, recommendation: `php "${phpcbf}" --standard="${standard}" --runtime-set installed_paths "${installed.join(',')}" <path> (review the diff before committing)` });
  });

  /* --------------------------- PHPStan -------------------------- */
  const phpstanBin = path.join(VENDOR, 'phpstan', 'phpstan', 'phpstan');
  await run.check({ id: 'code.phpstan', title: `Static analysis (PHPStan level ${cfg.code.phpstanLevel} + WordPress extension)`, category: CAT, tool: 'PHPStan', requires: { customCode: true, tools: ['php'] } }, async (c) => {
    if (!exists(phpstanBin)) return c.skip('PHPStan not installed in toolkit', `Run "composer install" in ${TOOLKIT_ROOT}`);
    const files = run.changedFiles ? phpFiles : targets;
    if (!files.length || !phpFiles.length) return c.notApplicable('no PHP files in scope');
    c.scope(phpFiles);
    const dir = run.artifactDir('phpstan');
    const neon = path.join(dir, 'phpstan.neon');
    const generated = path.join(VENDOR, 'phpstan', 'extension-installer', 'src', 'GeneratedConfig.php');
    const wpExt = path.join(VENDOR, 'szepeviktor', 'phpstan-wordpress', 'extension.neon');
    const autoIncluded = exists(generated) && fs.readFileSync(generated, 'utf8').includes('szepeviktor');
    const phpVer = (cfg.code.phpVersion.match(/^(\d+)\.(\d+)/) || [null, '8', '1']).slice(1).map(Number);
    // Constants the project defines at runtime (define('MY_DIR', plugin_dir_path(__FILE__))) are unknown to
    // PHPStan unless bootstrapped; declare them and keep their type general.
    const constants = projectConstants(run.customDirs.map((d) => d.dir), cfg.scan.exclude);
    const bootstrap = path.join(dir, 'wpqa-constants.php');
    fs.writeFileSync(bootstrap, '<?php\n// Generated by the WordPress QA toolkit: constants defined by the project code.\n' + constants.map((k) => `if ( ! defined( '${k}' ) ) { define( '${k}', '' ); }`).join('\n') + '\n');
    const stubDir = path.join(VENDOR, 'php-stubs', 'wp-cli-stubs');
    // Full WP-CLI stubs if installed (composer require --dev php-stubs/wp-cli-stubs), else the toolkit's minimal ones.
    const stubs = exists(stubDir)
      ? fs.readdirSync(stubDir).filter((f) => /stubs\.php$/.test(f)).map((f) => path.join(stubDir, f))
      : [path.join(TOOLKIT_ROOT, 'config', 'stubs', 'wp-cli-min.php')];
    const scanDirs = (cfg.code.phpstanScanDirectories || []).map((d) => path.resolve(cfg._root, d)).filter(exists);
    const scanFiles = [...stubs, ...(cfg.code.phpstanScanFiles || []).map((f) => path.resolve(cfg._root, f)).filter(exists)];
    const q = (p) => JSON.stringify(p.split(path.sep).join('/'));
    const lines = [];
    if (!autoIncluded && exists(wpExt)) lines.push('includes:', `  - ${q(wpExt)}`);
    lines.push('parameters:', `  level: ${cfg.code.phpstanLevel}`, `  phpVersion: ${phpVer[0] * 10000 + phpVer[1] * 100}`,
      '  treatPhpDocTypesAsCertain: false', '  reportUnmatchedIgnoredErrors: false',
      '  excludePaths:', '    analyseAndScan:', '      - */vendor/*', '      - */node_modules/*', '      - */build/*', '      - */dist/*',
      '  bootstrapFiles:', `    - ${q(bootstrap)}`);
    if (constants.length) lines.push('  dynamicConstantNames:', ...constants.map((k) => `    - ${k}`));
    if (scanDirs.length) lines.push('  scanDirectories:', ...scanDirs.map((d) => `    - ${q(d)}`));
    if (scanFiles.length) lines.push('  scanFiles:', ...scanFiles.map((d) => `    - ${q(d)}`));
    if (cfg.code.phpstanIgnore?.length) lines.push('  ignoreErrors:', ...cfg.code.phpstanIgnore.map((p) => `    - ${JSON.stringify(p)}`));
    fs.writeFileSync(neon, lines.join('\n') + '\n');
    const r = await run.php(['-d', 'memory_limit=2G', phpstanBin, 'analyse', '--error-format=json', '--no-progress', '--no-interaction', '-c', neon, ...files], { timeoutMs: 20 * 60 * 1000, cwd: cfg._root });
    const json = parseJsonLoose(r.stdout);
    if (!json?.totals || r.timedOut) c.toolError('PHPStan', r, json?.totals ? 'timed out' : 'produced no JSON report');
    const crashed = (json.errors || []).filter((e) => /Internal error|Child process error|Allowed memory size|crashed/i.test(e));
    if (crashed.length) c.toolError('PHPStan', r, `crashed while analysing (${crashed.length} internal error(s))`);
    for (const e of json.errors || []) c.finding({ severity: 'low', tool: 'PHPStan', rule: 'phpstan.general', title: 'PHPStan configuration/analysis error', evidence: e });
    const pending = [];
    for (const [file, data] of Object.entries(json.files || {})) {
      for (const m of data.messages || []) {
        const symbol = notFoundSymbol(m.message);
        const sev = symbol ? 'low' : /undefined|does not exist|might not be defined|on null|non-object|expects .+ given|too few arguments|always (true|false)|unreachable/i.test(m.message) ? 'medium' : 'low';
        pending.push({
          symbol,
          f: {
            severity: sev, tool: 'PHPStan', rule: m.identifier || (symbol ? 'symbol.notFound' : 'phpstan'), title: m.message, file, line: m.line,
            message: m.tip ? `Tip: ${m.tip}` : null,
            recommendation: symbol ? 'Not defined in the scanned code or any installed plugin/theme: a real missing dependency, or code that needs a function_exists()/class_exists() guard.' : 'Fix the type/logic error or add a precise @var/@param annotation if PHPStan lacks context.',
            fingerprintExtra: m.message,
          },
        });
      }
    }
    // Symbols that exist in an installed third-party plugin/theme are not bugs: PHPStan just wasn't shown that code.
    const wanted = [...new Set(pending.map((p) => p.symbol?.name).filter(Boolean))];
    const providers = wanted.length ? locateSymbols(wanted, thirdPartyDirs(run)) : new Map();
    const suggest = new Map();
    for (const { symbol, f } of pending) {
      const prov = symbol && providers.get(symbol.name.toLowerCase());
      if (prov) {
        f.severity = 'info';
        f.aggregate = true;
        f.rule = 'symbol.thirdParty';
        f.title = 'Symbols from third-party plugins/themes not analysed by PHPStan';
        f.message = `${symbol.kind} ${symbol.name} is defined in ${prov.slug}`;
        f.recommendation = 'Add the providing plugin folder(s) to code.phpstanScanDirectories in wpqa.config.json so PHPStan can type-check these calls.';
        suggest.set(prov.slug, prov.dir);
      }
      c.finding(f);
    }
    if (suggest.size) c.note(`Third-party symbols come from: ${[...suggest.keys()].join(', ')}. To type-check calls into them, set code.phpstanScanDirectories to ${JSON.stringify([...suggest.values()].map((d) => rel(cfg._root, d)))}`);
    if (constants.length) c.note(`Bootstrapped ${constants.length} project constant(s): ${constants.slice(0, 8).join(', ')}${constants.length > 8 ? ' …' : ''}`);
    c.stats = { errors: json.totals.file_errors };
  });

  /* --------------------------- ESLint --------------------------- */
  await run.check({ id: 'code.eslint', title: 'JavaScript lint + DOM XSS sinks (ESLint)', category: CAT, tool: 'ESLint', requires: { customCode: true } }, async (c) => {
    if (!jsFiles.length) return c.notApplicable('no JavaScript source files in scope');
    c.scope(jsFiles);
    let ESLint;
    try { ({ ESLint } = await import('eslint')); } catch { return c.skip('ESLint not installed in toolkit', `Run "npm install" in ${TOOLKIT_ROOT}`); }
    const { eslintConfig } = await import('../config/eslint.config.mjs');
    const eslint = new ESLint({ cwd: commonRoot(cfg._root, jsFiles), overrideConfigFile: true, overrideConfig: await eslintConfig(), errorOnUnmatchedPattern: false, warnIgnored: false });
    const results = await eslint.lintFiles(jsFiles);
    for (const res of results) {
      for (const m of res.messages) {
        const map = classifyEslint(m);
        c.finding({ ...map, tool: 'ESLint', rule: m.ruleId || 'parse', title: map.title || m.message, message: map.title ? m.message : null, file: res.filePath, line: m.line, fingerprintExtra: map.aggregate ? '' : m.message });
      }
    }
    c.stats.files = jsFiles.length;
  });

  /* -------------------------- Stylelint ------------------------- */
  await run.check({ id: 'code.stylelint', title: 'CSS errors (Stylelint recommended)', category: CAT, tool: 'Stylelint', requires: { customCode: true } }, async (c) => {
    if (!cssFiles.length) return c.notApplicable('no CSS source files in scope');
    c.scope(cssFiles);
    let stylelint;
    try { stylelint = (await import('stylelint')).default; } catch { return c.skip('Stylelint not installed in toolkit', `Run "npm install" in ${TOOLKIT_ROOT}`); }
    const out = await stylelint.lint({ files: cssFiles.map((f) => f.split(path.sep).join('/')), config: { extends: ['stylelint-config-recommended'] }, configBasedir: TOOLKIT_ROOT, allowEmptyInput: true });
    for (const res of out.results) {
      for (const w of res.warnings || []) {
        const syntax = w.rule === 'CssSyntaxError';
        c.finding({ severity: syntax ? 'medium' : w.severity === 'error' ? 'low' : 'info', tool: 'Stylelint', rule: w.rule, title: syntax ? 'CSS syntax error' : `Stylelint: ${w.rule}`, message: w.text, file: res.source, line: w.line, aggregate: !syntax, recommendation: syntax ? 'Browsers drop the broken rule block; fix the syntax.' : 'Fix the CSS mistake (duplicate/invalid/unknown property or selector).' });
      }
    }
    c.stats.files = cssFiles.length;
  });
}

function commonRoot(root, files) {
  const outside = files.some((f) => rel(root, f).startsWith('..'));
  if (!outside) return root;
  let common = path.dirname(files[0]);
  for (const f of files) while (!f.startsWith(common + path.sep)) common = path.dirname(common);
  return common;
}

/** Names passed to define('NAME', …) in the project code. */
export function projectConstants(dirs, exclude) {
  const out = new Set();
  for (const d of dirs) {
    for (const f of walkFiles(d, { exts: ['.php'], exclude })) {
      const t = readText(f) || '';
      for (const m of t.matchAll(/\bdefine\s*\(\s*['"]([A-Za-z_][A-Za-z0-9_]*)['"]\s*,/g)) out.add(m[1]);
    }
  }
  return [...out].sort();
}

/** { kind, name } for PHPStan "X not found" / "unknown class X" messages. */
export function notFoundSymbol(msg) {
  let m = String(msg).match(/^(Function|Constant|Class|Interface|Trait) ([\\\w]+) not found/);
  if (m) return { kind: m[1].toLowerCase(), name: m[2].replace(/^\\/, '') };
  m = String(msg).match(/(?:unknown class|Instantiated class|Access to constant \w+ on an unknown class|Call to method \w+\(\) on an unknown class) ([\\\w]+)/i) || String(msg).match(/on an unknown class ([\\\w]+)/i);
  if (m) return { kind: 'class', name: m[1].replace(/^\\/, '').split('\\').pop() };
  return null;
}

function thirdPartyDirs(run) {
  const own = new Set(run.customDirs.map((d) => path.resolve(d.dir)));
  return [...(run.facts.plugins || []), ...(run.facts.themes || [])]
    .filter((x) => !x.single && x.path && !own.has(path.resolve(x.path)))
    .map((x) => ({ slug: x.slug, dir: x.path }));
}

/** Find where functions/classes/constants are defined in installed third-party code. Map(lowercase name → {slug, dir}). */
export function locateSymbols(names, dirs, { maxFiles = 30000 } = {}) {
  const want = new Set(names.map((n) => n.toLowerCase()));
  const found = new Map();
  const re = /\b(?:function\s+&?\s*([A-Za-z_]\w*)\s*\(|(?:class|interface|trait)\s+([A-Za-z_]\w*)\b|define\s*\(\s*['"]([A-Za-z_]\w*)['"])/g;
  let seen = 0;
  for (const { slug, dir } of dirs) {
    for (const f of walkFiles(dir, { exts: ['.php'], exclude: ['node_modules', '.git', 'tests', 'test'] })) {
      if (++seen > maxFiles || found.size === want.size) return found;
      const t = readText(f, 2 * 1024 * 1024);
      if (!t) continue;
      for (const m of t.matchAll(re)) {
        const n = (m[1] || m[2] || m[3]).toLowerCase();
        if (want.has(n) && !found.has(n)) found.set(n, { slug, dir });
      }
    }
  }
  return found;
}

/** A block template (block.json "render": "file:./render.php") runs inside a function: its variables are local. */
export function isBlockRenderTemplate(file) {
  return /^render\.php$/i.test(path.basename(String(file || ''))) && exists(path.join(path.dirname(file), 'block.json'));
}

export function classifyPhpcs(m, file) {
  const s = m.source || '';
  const err = m.type === 'ERROR';
  const group = s.split('.').slice(0, 3).join('.');
  if (s.startsWith('WordPress.Security.EscapeOutput')) return { severity: 'high', title: 'Unescaped output (possible XSS)', dedupeKey: 'xss', confidence: 'likely', recommendation: 'Escape late with esc_html(), esc_attr(), esc_url(), wp_kses_post() matching the output context.' };
  if (s.startsWith('WordPress.DB.PreparedSQLPlaceholders')) return { severity: 'medium', title: 'Incorrect $wpdb->prepare() placeholders', recommendation: 'Use %s/%d/%i placeholders matching the number of arguments.' };
  if (s.startsWith('WordPress.DB.PreparedSQL')) return { severity: 'high', title: 'SQL built with unprepared variables (possible SQL injection)', dedupeKey: 'sqli', confidence: 'likely', recommendation: 'Use $wpdb->prepare() with placeholders for every variable part of the query.' };
  if (s.startsWith('WordPress.Security.NonceVerification')) return { severity: 'medium', title: 'Form/request data processed without nonce verification (CSRF)', confidence: 'likely', recommendation: 'Verify with check_admin_referer()/wp_verify_nonce()/check_ajax_referer() before acting on $_POST/$_GET.' };
  if (s.startsWith('WordPress.Security.ValidatedSanitizedInput')) return { severity: 'medium', title: 'Request input not validated/sanitized', confidence: 'likely', recommendation: 'isset() check, wp_unslash(), then sanitize_text_field()/absint()/sanitize_email() etc.' };
  if (s.startsWith('WordPress.Security.SafeRedirect')) return { severity: 'medium', title: 'wp_redirect() with possibly untrusted URL (open redirect)', recommendation: 'Use wp_safe_redirect() and exit.' };
  if (s.startsWith('PHPCompatibility')) return { severity: err ? 'high' : 'medium', title: null, recommendation: 'Code is not compatible with the configured PHP version range (code.phpVersion).' };
  if (s.startsWith('WordPress.WP.DeprecatedFunctions') || s.startsWith('WordPress.WP.DeprecatedClasses') || s.startsWith('WordPress.WP.DeprecatedParameter')) return { severity: 'medium', title: null, recommendation: 'Replace the deprecated WordPress API.' };
  if (s.startsWith('WordPress.WP.GlobalVariablesOverride')) {
    if (isBlockRenderTemplate(file)) return { severity: 'info', aggregate: true, rule: `${group}.blockRender`, title: 'Variable named like a WordPress global in a block render template (local scope — not a global)', confidence: 'heuristic', recommendation: 'No functional problem: WordPress includes render.php inside a function. Rename ($post → $brand_post …) only if you want PHPCS quiet.' };
    return { severity: 'medium', title: 'Overrides a WordPress global variable', recommendation: 'Use a local/prefixed variable; overriding globals like $post breaks other code. (False positive if this file is only included inside a function.)' };
  }
  if (s.startsWith('WordPress.PHP.RestrictedPHPFunctions') || s.startsWith('WordPress.DB.RestrictedFunctions') || s.startsWith('WordPress.DB.RestrictedClasses')) return { severity: 'medium', title: null };
  if (s.startsWith('WordPress.WP.EnqueuedResources')) return { severity: 'medium', aggregate: true, rule: group, title: 'Scripts/styles hard-coded instead of enqueued', recommendation: 'Use wp_enqueue_script()/wp_enqueue_style() so caching, dependencies and plugins work.' };
  if (s.startsWith('WordPress.PHP.DevelopmentFunctions')) return { severity: 'low', aggregate: true, rule: group, title: 'Debug functions left in code (var_dump/print_r/error_log)', recommendation: 'Remove debug output before release.' };
  if (s.startsWith('WordPress.DB.DirectDatabaseQuery')) return { severity: 'low', aggregate: true, rule: group, title: 'Direct database queries without caching', recommendation: 'Prefer WP APIs or cache results (wp_cache_*/transients).' };
  if (s.startsWith('WordPress.WP.I18n')) return { severity: 'low', aggregate: true, rule: group, title: 'Internationalisation issues', recommendation: 'Use literal strings and the theme/plugin text domain in __()/_e().' };
  if (s.startsWith('WordPress.WP.AlternativeFunctions') || s.startsWith('WordPress.PHP.DiscouragedPHPFunctions')) return { severity: 'low', aggregate: true, rule: group, title: `Discouraged functions (${group})`, recommendation: 'Use the WordPress alternative (wp_remote_get, WP_Filesystem, wp_json_encode …).' };
  return { severity: err ? 'low' : 'info', aggregate: true, rule: group, title: `Coding standard: ${group}`, recommendation: m.fixable ? 'Auto-fixable with phpcbf.' : 'Follow WordPress Coding Standards.' };
}

function classifyEslint(m) {
  if (m.fatal || !m.ruleId) return { severity: 'high', title: 'JavaScript syntax error', recommendation: 'Fix the syntax; the script will not run.' };
  if (['no-eval', 'no-implied-eval', 'no-new-func'].includes(m.ruleId)) return { severity: 'high', title: 'Dynamic code execution (eval-like)', recommendation: 'Remove eval/new Function/string timers; they enable XSS-to-RCE in the browser.' };
  if (m.ruleId.startsWith('no-unsanitized')) return { severity: 'medium', title: 'Unsanitized HTML injection (innerHTML/insertAdjacentHTML)', dedupeKey: 'xss-js', confidence: 'likely', recommendation: 'Use textContent, or build DOM nodes; if HTML is required, sanitize (e.g. DOMPurify) and never insert URL/user data.' };
  if (m.ruleId === 'no-undef') return { severity: 'low', title: null, recommendation: 'If this is a wp_localize_script/global, declare it with /* global name */; otherwise it is a ReferenceError at runtime.' };
  if (m.severity === 2) return { severity: 'low', aggregate: true, title: `ESLint: ${m.ruleId}`, recommendation: 'Fix the reported problem.' };
  return { severity: 'info', aggregate: true, title: `ESLint: ${m.ruleId}`, recommendation: 'Clean up.' };
}
