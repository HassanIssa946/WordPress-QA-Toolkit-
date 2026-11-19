#!/usr/bin/env node
// WordPress QA Toolkit CLI — see `node bin/wpqa.mjs help`.
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import dns from 'node:dns/promises';
import { TOOLKIT_ROOT, run, which, exists, readJson, hasNodePackage, compareVersions } from '../lib/util.mjs';
import { CONFIG_FILE, DEFAULTS, findConfig, loadConfig, PLATFORM_HINTS } from '../lib/config.mjs';
import { discover, summarizeDiscovery } from '../lib/discover.mjs';
import { AuditRun } from '../lib/engine.mjs';
import { writeReport, EXIT_CODES } from '../lib/report.mjs';
import { MODES, AVAILABLE } from '../lib/modes.mjs';
import { localSiteDir, localSiteInfo, localWpTools } from '../lib/localwp.mjs';
import { seedPages } from '../lib/pages.mjs';

const VERSION = readJson(path.join(TOOLKIT_ROOT, 'package.json'))?.version || '0.0.0';

function parseArgs(argv) {
  const flags = { _: [] };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('--')) {
      const [k, v] = a.slice(2).split('=');
      const next = argv[i + 1];
      if (v !== undefined) flags[k] = v;
      else if (['config', 'url', 'env', 'public', 'only', 'skip', 'project', 'name', 'profile', 'scope'].includes(k) && next && !next.startsWith('--')) { flags[k] = next; i++; }
      else flags[k] = true;
    } else flags._.push(a);
  }
  for (const k of ['only', 'skip']) if (typeof flags[k] === 'string') flags[k] = flags[k].split(',').map((s) => s.trim()).filter(Boolean);
  return flags;
}

const HELP = `WordPress QA Toolkit v${VERSION}

Usage: node bin/wpqa.mjs <command> [options]

Setup
  init [--url <site url>] [--env local|staging|production] [--public <live url>]
                         Discover the WordPress project in the current folder and write ${CONFIG_FILE}
  doctor                 Check Node, PHP, WP-CLI, Composer tools, Semgrep, k6, Docker
  discover [--json]      Show what the toolkit detects (WP version, themes, plugins, blocks, stack)
  install-skill [--scope user|project]
                         Install the /wp-audit Claude Code skill (user: ~/.claude/skills, project: ./.claude/skills)

Audits
  run <mode> [options]   (or just: <mode>)
${Object.entries(MODES).map(([k, m]) => `    ${k.padEnd(15)} ${m.description}`).join('\n')}

  Options:
    --changed            Only analyse files changed in git (code/security checks)
    --only a,b           Only run checks whose id matches (e.g. security.wp-patterns, code.*)
    --skip a,b           Skip matching checks
    --approve            Allow approval-gated tests (load, active scans, write probes). Use only after the site owner agrees.
    --profile <p>        Load profile for scalability: smoke | load | stress (default: load)
    --config <path>      Use a specific ${CONFIG_FILE}
    --quiet              Less console output

Reports
  report                 Print the latest report path and verdict
  modes                  List audit modes

Exit codes: 0 = PASS, 1 = FAIL (findings at/above failOn), 2 = configuration/runtime error,
            3 = INCOMPLETE (no blocking findings, but a core check was skipped/errored or coverage < minCoverage).`;

async function main() {
  const flags = parseArgs(process.argv.slice(2));
  let [cmd, ...rest] = flags._;
  if (!cmd || cmd === 'help' || flags.help) { console.log(HELP); return 0; }
  if (MODES[cmd]) { rest = [cmd, ...rest]; cmd = 'run'; }
  switch (cmd) {
    case 'init': return cmdInit(flags);
    case 'doctor': return cmdDoctor(flags);
    case 'discover': return cmdDiscover(flags);
    case 'install-skill': return cmdInstallSkill(flags);
    case 'run': return cmdRun(rest[0], flags);
    case 'report': return cmdReport(flags);
    case 'modes': console.log(Object.entries(MODES).map(([k, m]) => `${k.padEnd(15)} ${m.description}`).join('\n')); return 0;
    case 'version': console.log(VERSION); return 0;
    default: console.error(`Unknown command: ${cmd}\n\n${HELP}`); return 2;
  }
}

function getConfig(flags) {
  const p = flags.config ? path.resolve(flags.config) : findConfig(process.cwd());
  if (!p || !fs.existsSync(p)) {
    console.error(`No ${CONFIG_FILE} found from ${process.cwd()}. Run "wpqa init" in your project folder first.`);
    return null;
  }
  const { cfg, problems } = loadConfig(p);
  if (problems.length) {
    console.error(`Config problems in ${p}:\n- ${problems.join('\n- ')}`);
    return null;
  }
  return cfg;
}

/* ------------------------------------------------------------------ */

async function cmdRun(mode, flags) {
  if (!MODES[mode]) { console.error(`Unknown mode "${mode}". Modes: ${Object.keys(MODES).join(', ')}`); return 2; }
  const cfg = getConfig(flags);
  if (!cfg) return 2;
  const audit = new AuditRun({ cfg, mode, flags, version: VERSION });
  audit.log(`WordPress QA Toolkit v${VERSION} — mode "${mode}" — ${cfg.site.url} (${cfg.site.environment})`);
  audit.log(`Custom code: ${audit.customDirs.map((d) => `${d.type}:${d.slug}`).join(', ') || '(none — set scan.themes / scan.plugins)'}`);
  if (flags.changed) {
    audit.changedFiles = await gitChangedFiles(audit.customDirs.map((d) => d.dir));
    audit.log(audit.changedFiles ? `--changed: ${audit.changedFiles.length} changed file(s)` : '--changed: no git repository found for the custom code, analysing all files');
  }
  if (flags.approve) audit.log('--approve given: approval-gated tests may run against allowed hosts.');
  audit.log('');
  for (const id of MODES[mode].modules) {
    if (!AVAILABLE.has(id)) {
      if (flags.only?.length && !audit.selected(`${id}.x`)) continue;
      audit.checks.push({ id: `${id}.*`, title: `${id} module`, category: id, status: 'skipped', planned: true, reason: 'module planned for phase 2 (not in this version)', howTo: 'Not tested yet — do not treat as passed.', notes: [], artifacts: [], stats: {}, findingCount: 0, durationMs: 0, scope: [] });
      audit.log(`[SKIP] ${(id + '.*').padEnd(34)} planned for phase 2 — not tested`);
      continue;
    }
    const mod = await import(`../modules/${id}.mjs`);
    try {
      await mod.default(audit);
    } catch (e) {
      audit.checks.push({ id: `${id}.module`, title: `${id} module`, category: id, status: 'error', reason: e.stack || String(e), notes: [], artifacts: [], stats: {}, findingCount: 0, durationMs: 0, scope: [] });
      audit.log(`[ERR ] ${id}.module ${e.message}`);
    }
  }
  audit.finalizeFindings();
  const { report, diff, mdPath, jsonPath } = writeReport(audit);
  const c = report.verdict.counts;
  audit.log('');
  audit.log(`Findings: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`);
  if (diff) audit.log(`Since ${diff.previousRunId}: ${diff.new.length} new, ${diff.resolved.length} resolved, ${diff.stillOpen.length} still open, ${diff.notRetested.length} not re-tested`);
  const skipped = report.checks.filter((x) => !x.planned && (x.status === 'skipped' || x.status === 'error')).length;
  const planned = report.checks.filter((x) => x.planned).length;
  if (skipped) audit.log(`${skipped} check(s) skipped/errored — NOT counted as passed (see report).`);
  if (planned) audit.log(`${planned} phase-2 area(s) not tested (not built yet).`);
  if (report.needsApproval.length) audit.log(`${report.needsApproval.length} test(s) waiting for approval (--approve).`);
  const v = report.verdict;
  audit.log(`Coverage: ${v.coveragePct ?? '—'}% of applicable checks executed (minimum ${v.minCoverage}%)`);
  for (const why of v.incomplete) audit.log(`  incomplete: ${why}`);
  audit.log(`Verdict: ${v.status} (failOn=${cfg.failOn})`);
  audit.log(`Report: ${mdPath}`);
  audit.log(`JSON:   ${jsonPath}`);
  return EXIT_CODES[v.status];
}

async function gitChangedFiles(dirs) {
  if (!which('git')) return null;
  const files = new Set();
  const tops = new Set();
  for (const d of dirs) {
    const r = await run('git', ['-C', d, 'rev-parse', '--show-toplevel']);
    if (r.code === 0) tops.add(r.stdout.trim());
  }
  if (!tops.size) return null;
  for (const top of tops) {
    for (const args of [['diff', '--name-only', 'HEAD'], ['diff', '--name-only', '--cached'], ['ls-files', '--others', '--exclude-standard']]) {
      const r = await run('git', ['-C', top, ...args]);
      if (r.code === 0) for (const f of r.stdout.split('\n').map((s) => s.trim()).filter(Boolean)) files.add(path.resolve(top, f));
    }
  }
  return [...files];
}

/* ------------------------------------------------------------------ */

async function cmdInit(flags) {
  const target = path.join(process.cwd(), CONFIG_FILE);
  if (exists(target) && !flags.force) {
    console.error(`${CONFIG_FILE} already exists here. Use --force to overwrite.`);
    return 2;
  }
  const d = discover(process.cwd());
  if (!d.wpRoot) {
    console.error('No WordPress installation found here (looked for wp-includes/version.php, incl. app/public). Run init from your site folder.');
    return 2;
  }
  console.log(summarizeDiscovery(d));
  const warnings = [];
  // LocalWP: the real domain is in Local's sites.json; PHP/WP-CLI/DB settings are in app/.envrc.
  const siteDir = d.localwp ? localSiteDir(d.wpRoot) : null;
  const local = siteDir ? localSiteInfo(siteDir) : null;
  const localTools = siteDir ? localWpTools(siteDir) : null;
  const localUrl = local?.domain ? `http://${local.domain}` : null;
  const guessUrl = flags.url || d.wpConfig?.WP_HOME || localUrl || (d.localSiteName ? `http://${d.localSiteName.toLowerCase().replace(/\s+/g, '-')}.local` : 'http://localhost');
  let host = '';
  try { host = new URL(guessUrl).hostname; } catch { console.error(`Invalid --url: ${guessUrl}`); return 2; }
  if (localUrl && host !== local.domain) warnings.push(`site.url host "${host}" differs from LocalWP's domain "${local.domain}" — check it (Local → site overview → Site domain).`);
  try { await dns.lookup(host); } catch (e) { warnings.push(`"${host}" does not resolve on this machine (${e.code || e.message}). Is the URL right and the site started?`); }
  if (d.localwp && !localTools) warnings.push('LocalWP site detected but app/.envrc is missing (start the site in Local, then run init --force) — WP-CLI/DB checks need Local\'s PHP environment.');
  const env = flags.env || 'local';
  // Seed pages from the core sitemap, an SEO plugin's sitemap or the REST API (if the site is up).
  const seeded = await seedPages(guessUrl);
  const pages = seeded.pages;
  const tools = { ...DEFAULTS.tools };
  if (localTools) Object.assign(tools, { php: localTools.php, wp: localTools.wp, composer: localTools.composer, env: localTools.env, pathPrepend: localTools.pathPrepend });
  const cfg = {
    $comment: 'WordPress QA Toolkit project config. Defaults: see DEFAULTS in lib/config.mjs. Keep secrets out of this file (use env vars).',
    project: { name: d.localSiteName || path.basename(process.cwd()), wpPath: path.relative(process.cwd(), d.wpRoot).split(path.sep).join('/') || '.' },
    site: { url: guessUrl.replace(/\/$/, ''), environment: env, pages },
    publicSite: { url: flags.public || null },
    scan: {
      themes: d.themes.filter((t) => t.likelyCustom).map((t) => t.slug),
      plugins: d.plugins.filter((p) => p.likelyCustom && !p.single).map((p) => p.slug),
      muPlugins: false,
      extraPaths: [],
    },
    tools,
    code: { phpVersion: `${(d.themes.find((t) => t.likelyCustom)?.requiresPhp || '8.1').replace(/^(\d+\.\d+).*$/, '$1')}-`, phpstanLevel: 5 },
    frontend: { viewports: ['desktop', 'mobile'], visualRegression: true },
    safety: { allowedHosts: [new URL(guessUrl).hostname], allowIntrusiveOnProduction: false },
    failOn: 'high',
  };
  fs.writeFileSync(target, JSON.stringify(cfg, null, 2) + '\n');
  const gi = await ensureGitignore(process.cwd());
  console.log(`\nWrote ${target}`);
  console.log(`- site.url = ${cfg.site.url} (${env}) — check this is right`);
  console.log(`- custom code to scan: themes [${cfg.scan.themes.join(', ')}], plugins [${cfg.scan.plugins.join(', ')}] — remove third-party items, add any missing`);
  console.log(`- pages (${seeded.source}): ${pages.join(', ')}`);
  if (localTools) console.log(`- tools: LocalWP PHP ${localTools.php}, WP-CLI and environment taken from app/.envrc`);
  console.log(`- .gitignore: ${gi}`);
  for (const w of warnings) console.log(`WARNING: ${w}`);
  console.log('Next: node bin/wpqa.mjs doctor, then run "quick" or "full".');
  return 0;
}

/** Make sure .wpqa/ is not committed. Leaves .gitignore alone when git already ignores the folder. */
async function ensureGitignore(dir) {
  const gi = path.join(dir, '.gitignore');
  const line = '.wpqa/';
  try {
    if (which('git')) {
      const r = await run('git', ['-C', dir, 'check-ignore', '-q', '--no-index', '.wpqa/reports/x']);
      if (r.code === 0) return '.wpqa/ already ignored by git — left unchanged';
    }
    const cur = exists(gi) ? fs.readFileSync(gi, 'utf8') : '';
    if (cur.split(/\r?\n/).includes(line)) return '.wpqa/ already listed';
    fs.writeFileSync(gi, cur + (cur && !cur.endsWith('\n') ? '\n' : '') + `# WordPress QA toolkit reports\n${line}\n`);
    return 'added .wpqa/';
  } catch { return 'not changed (could not read/write it)'; }
}

/* ------------------------------------------------------------------ */

async function cmdDiscover(flags) {
  const cfgPath = flags.config ? path.resolve(flags.config) : findConfig(process.cwd());
  let start = process.cwd();
  if (cfgPath) { const { cfg } = loadConfig(cfgPath); start = cfg._wpRoot; }
  const d = discover(start);
  if (flags.json) console.log(JSON.stringify(d, null, 2));
  else console.log(summarizeDiscovery(d));
  return d.wpRoot ? 0 : 2;
}

async function cmdDoctor(flags) {
  const lines = [];
  const ok = (b) => (b ? 'OK  ' : 'MISS');
  const nodeOk = compareVersions(process.versions.node, '22.22.0') >= 0;
  lines.push(`[${ok(nodeOk)}] Node ${process.version}${nodeOk ? '' : ' — need >= 22.22 (install current LTS from nodejs.org)'}`);
  const npmDeps = ['eslint', 'stylelint', 'globals', 'eslint-plugin-no-unsanitized'];
  const missingNpm = npmDeps.filter((p) => !hasNodePackage(p));
  lines.push(`[${ok(!missingNpm.length)}] Toolkit npm packages${missingNpm.length ? ` — missing ${missingNpm.join(', ')}: run "npm install" in ${TOOLKIT_ROOT}` : ''}`);
  const vendor = exists(path.join(TOOLKIT_ROOT, 'vendor', 'squizlabs', 'php_codesniffer'));
  lines.push(`[${ok(vendor)}] PHPCS/WPCS/PHPStan (composer vendor)${vendor ? '' : ` — run "composer install" in ${TOOLKIT_ROOT}`}`);

  const cfgPath = flags.config ? path.resolve(flags.config) : findConfig(process.cwd());
  let cfg = null;
  if (cfgPath) {
    const loaded = loadConfig(cfgPath);
    cfg = loaded.cfg;
    lines.push(`[${ok(!loaded.problems.length)}] Config ${cfgPath}${loaded.problems.length ? ' — ' + loaded.problems.join('; ') : ''}`);
  } else lines.push(`[MISS] ${CONFIG_FILE} — run "wpqa init" in your WordPress project`);

  const audit = cfg ? new AuditRun({ cfg, mode: 'doctor', flags: { quiet: true }, version: VERSION }) : null;
  const tools = cfg?.tools || DEFAULTS.tools;
  for (const name of ['php', 'composer', 'wp', 'semgrep', 'k6', 'docker']) {
    let res;
    if (audit) res = await audit.tool(name);
    else {
      const has = which(Array.isArray(tools[name]) ? tools[name][0] : tools[name]);
      res = { ok: Boolean(has), version: has ? 'found' : null };
    }
    const why = { php: 'php -l, PHPCS, PHPStan', composer: 'installing PHPCS/PHPStan into the toolkit; composer audit is phase 2', wp: 'wpcli.* checks: core/plugin integrity, updates, settings', semgrep: 'security.semgrep (optional)', k6: 'load testing (phase 2, optional)', docker: 'OWASP ZAP scans (phase 2, optional)' }[name];
    lines.push(`[${ok(res.ok)}] ${name.padEnd(8)} ${res.ok ? res.version : `— ${PLATFORM_HINTS[name] || ''}`}  (${why})`);
    if (res.startupWarnings?.length) {
      lines.push(`[WARN] ${name} prints PHP startup warnings (kept out of results, but fix the environment): ${res.startupWarnings[0].slice(0, 160)}`);
      lines.push('       LocalWP: re-run "init --force", or add Local\'s php …/ImageMagick folder to tools.pathPrepend.');
    }
  }
  if (audit) {
    const w = await audit.wpCli();
    if (w.ok) lines.push(`[${ok(w.db)}] WP-CLI database connection${w.db ? ` (${w.siteurl})` : ` — ${w.dbError || ''} → ${PLATFORM_HINTS.wp}`}`);
    if (w.db) {
      // site.url must be the site WP-CLI talks to, otherwise HTTP checks test something else.
      let same = true;
      try { same = new URL(w.siteurl).host === new URL(cfg.site.url).host; } catch { /* ignore */ }
      if (!same) lines.push(`[MISS] site.url ${cfg.site.url} does not match WordPress siteurl ${w.siteurl} — set site.url to ${w.siteurl.replace(/\/$/, '')} (and safety.allowedHosts)`);
      for (const [slug, check, type] of [['plugin-check', 'wpcli.plugin-check', 'plugin'], ['theme-check', 'wpcli.theme-check', 'theme']]) {
        if (!audit.customDirs.some((d) => d.type === type)) continue;
        const active = (await audit.wp(['plugin', 'is-active', slug])).code === 0;
        lines.push(`[${ok(active)}] ${slug} plugin${active ? '' : ` — ${check} will be skipped (optional; local/staging: wp plugin install ${slug} --activate)`}`);
      }
    }
    const reach = await audit.siteReachable();
    lines.push(`[${ok(reach.ok)}] Site reachable: ${cfg.site.url}${reach.ok ? ` (HTTP ${reach.status})` : ` — ${reach.error}`}`);
    lines.push(`[INFO] Custom code: ${audit.customDirs.map((d) => `${d.type}:${d.slug}`).join(', ') || 'none configured'}`);
    fs.rmSync(audit.outDir, { recursive: true, force: true });
  }
  console.log(`WordPress QA Toolkit v${VERSION} — doctor (${TOOLKIT_ROOT})\n`);
  console.log(lines.join('\n'));
  console.log('\nMissing optional tools only skip their checks; they are reported as "not tested", never as passed.');
  return 0;
}

/* ------------------------------------------------------------------ */

async function cmdInstallSkill(flags) {
  const scope = flags.scope || 'user';
  const base = scope === 'project' ? path.join(process.cwd(), '.claude', 'skills') : path.join(os.homedir(), '.claude', 'skills');
  const dest = path.join(base, 'wp-audit');
  const src = path.join(TOOLKIT_ROOT, 'skill', 'wp-audit');
  fs.mkdirSync(dest, { recursive: true });
  const home = TOOLKIT_ROOT.split(path.sep).join('/');
  for (const f of fs.readdirSync(src)) {
    const text = fs.readFileSync(path.join(src, f), 'utf8').replaceAll('{{WPQA_HOME}}', home);
    fs.writeFileSync(path.join(dest, f), text);
  }
  console.log(`Installed /wp-audit skill to ${dest}`);
  console.log(`It runs: node "${home}/bin/wpqa.mjs" <mode>`);
  console.log('Restart Claude Code (or open a new session), then type /wp-audit quick in your WordPress project.');
  return 0;
}

async function cmdReport(flags) {
  const cfg = getConfig(flags);
  if (!cfg) return 2;
  const latest = readJson(path.join(cfg._outRoot, 'latest.json'));
  if (!latest) { console.log('No reports yet. Run an audit first.'); return 0; }
  console.log(`Latest: ${latest.runId} (${latest.mode}) — ${latest.verdict.status || (latest.verdict.pass ? 'PASS' : 'FAIL')}`);
  for (const why of latest.verdict.incomplete || []) console.log(`  incomplete: ${why}`);
  console.log(`Counts: ${Object.entries(latest.verdict.counts).map(([k, v]) => `${k}=${v}`).join(', ')}`);
  console.log(`Markdown: ${path.join(cfg._root, latest.report)}`);
  console.log(`JSON:     ${path.join(cfg._root, latest.json)}`);
  return 0;
}

// Exit by setting exitCode and letting the event loop drain: calling process.exit() right after fetch() to a
// *.local host (resolves to ::1 and 127.0.0.1) aborts Node on Windows with a libuv assertion and exit code 127.
// The unref'd timer only forces the exit if some handle keeps the process alive.
function finish(code) {
  process.exitCode = code;
  setTimeout(() => process.exit(code), 5000).unref();
}
main().then((code) => finish(code ?? 0)).catch((e) => { console.error(e.stack || e); finish(2); });
