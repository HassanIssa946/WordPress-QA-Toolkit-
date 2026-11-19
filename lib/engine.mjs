// Audit engine: run context, checks, findings, tool detection, safety gates.
import path from 'node:path';
import fs from 'node:fs';
import dns from 'node:dns/promises';
import { run, runTool, hash, rel, truncate, which, toolCommand, isLocalHost, toolEnv } from './util.mjs';
import { customCodeDirs, siteHost, PLATFORM_HINTS } from './config.mjs';
import { discover } from './discover.mjs';

/** Thrown when a scanner crashed or its output could not be parsed. The check becomes "error", never "passed". */
export class ToolError extends Error {
  constructor(message, artifact) { super(message); this.name = 'ToolError'; this.artifact = artifact || null; }
}

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const SEV_RANK = Object.fromEntries(SEVERITIES.map((s, i) => [s, i]));

export const CATEGORIES = {
  code: 'Code Quality',
  security: 'Security',
  dependencies: 'Dependencies & Vulnerabilities',
  wordpress: 'WordPress (themes, plugins, blocks)',
  frontend: 'Frontend & Accessibility',
  backend: 'Backend, APIs & Database',
  performance: 'Performance & Caching',
  seo: 'SEO',
  infrastructure: 'Network, DNS, TLS & HTTP',
  scalability: 'Scalability (load)',
  dast: 'Dynamic security scan',
};

class CheckContext {
  constructor(runCtx, meta) {
    this.run = runCtx;
    this.meta = meta;
    this.findings = [];
    this.notes = [];
    this.artifacts = [];
    this.status = null;
    this.reason = null;
    this.howTo = null;
    this.stats = {};
    this._scope = null;
  }
  /**
   * Record what this check examined (absolute files/dirs or URLs). Used to decide whether a finding from a
   * previous run was really re-tested. A check that never calls scope() is treated as covering its whole subject.
   */
  scope(items) {
    this._scope ||= new Set();
    for (const it of [].concat(items || [])) {
      if (!it) continue;
      const s = String(it);
      this._scope.add(/^[a-z]+:\/\//i.test(s) ? s : path.isAbsolute(s) ? rel(this.run.cfg._root, s) : s.split(path.sep).join('/'));
    }
  }
  /**
   * The scanner failed or produced output we cannot parse: save the raw output as an artifact and stop the
   * check with status "error". r = result of run()/runTool().
   */
  toolError(what, r, detail) {
    const dir = this.run.artifactDir(this.meta.id);
    const file = path.join(dir, what.replace(/[^\w.-]+/g, '-').toLowerCase() + '-raw.txt');
    const body = [
      '$ ' + (r?.command || '(unknown command)'),
      'exit code: ' + r?.code + (r?.timedOut ? ' (timed out)' : ''),
      detail ? 'problem: ' + detail : null,
      '', '--- stdout ---', r?.rawStdout ?? r?.stdout ?? '', '', '--- stderr ---', r?.stderr ?? '', '',
    ].filter((x) => x !== null).join('\n');
    fs.writeFileSync(file, body);
    this.artifact(file, what + ' raw output');
    const first = String((r?.stderr || r?.stdout || '').trim().split('\n')[0] || '').slice(0, 200);
    throw new ToolError(`${what} ${detail || 'output could not be parsed'} (exit ${r?.code}${r?.timedOut ? ', timed out' : ''})${first ? ': ' + first : ''} — raw output saved to artifacts`, file);
  }
  /** Record a finding. severity: critical|high|medium|low|info. */
  finding(f) {
    const cfg = this.run.cfg;
    const file = f.file ? (path.isAbsolute(f.file) ? rel(cfg._root, f.file) : f.file) : null;
    const item = {
      severity: SEVERITIES.includes(f.severity) ? f.severity : 'medium',
      title: f.title,
      message: f.message || null,
      category: this.meta.category,
      check: this.meta.id,
      tool: f.tool || this.meta.tool || 'wpqa',
      rule: f.rule || null,
      file,
      line: f.line || null,
      url: f.url || null,
      evidence: f.evidence ? truncate(f.evidence, 1200) : null,
      recommendation: f.recommendation || null,
      confidence: f.confidence || 'confirmed',
      references: f.references || [],
      aggregate: Boolean(f.aggregate),
      dedupeKey: f.dedupeKey || null,
    };
    item.id = hash(item.check, item.rule || item.title, item.file || item.url || '', f.fingerprintExtra ?? item.line ?? '');
    this.findings.push(item);
    return item;
  }
  note(text) { this.notes.push(text); }
  artifact(p, label) { this.artifacts.push({ path: rel(this.run.cfg._root, p), label: label || path.basename(p) }); }
  skip(reason, howTo) { this.status = 'skipped'; this.reason = reason; this.howTo = howTo || null; }
  notApplicable(reason) { this.status = 'not_applicable'; this.reason = reason; }
  /** Approval gate for intrusive actions. Returns true when allowed; otherwise marks the check skipped. */
  requireApproval(kind, targetUrl) {
    const { cfg, flags } = this.run;
    let host;
    try { host = new URL(targetUrl).hostname; } catch { this.skip(`invalid target URL ${targetUrl}`); return false; }
    const publicHost = cfg.publicSite?.url ? new URL(cfg.publicSite.url).hostname : null;
    // The public site is always treated as production.
    const isProd = (host === siteHost(cfg) && cfg.site.environment === 'production') || (publicHost !== null && host === publicHost);
    const allowed = new Set((cfg.safety.allowedHosts || []).map((h) => h.toLowerCase()));
    if (cfg.site.environment === 'local' && isLocalHost(siteHost(cfg))) allowed.add(siteHost(cfg));
    if (!allowed.has(host.toLowerCase())) {
      this.skip(`${kind} blocked: host "${host}" is not in safety.allowedHosts`, `Add "${host}" to safety.allowedHosts in wpqa.config.json (only for environments you own and may stress), then re-run with --approve.`);
      return false;
    }
    if (isProd && !cfg.safety.allowIntrusiveOnProduction) {
      this.skip(`${kind} blocked: ${host} is production`, 'Run against staging/local. Production requires safety.allowIntrusiveOnProduction=true AND --approve, after the site owner agrees.');
      return false;
    }
    if (!flags.approve) {
      this.skip(`${kind} needs explicit approval`, `Confirm with the site owner, then re-run with --approve (target: ${targetUrl}).`);
      this.run.needsApproval.push({ check: this.meta.id, kind, target: targetUrl });
      return false;
    }
    return true;
  }
}

const PHP_TOOLS = new Set(['php', 'wp', 'composer']);

/** Local-time run stamp, e.g. 20261118-140857 (report folders sort by time). */
export function runStamp(d = new Date()) {
  const p = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${p(d.getMonth() + 1)}${p(d.getDate())}-${p(d.getHours())}${p(d.getMinutes())}${p(d.getSeconds())}`;
}

export class AuditRun {
  constructor({ cfg, mode, flags, version }) {
    this.cfg = cfg;
    this.mode = mode;
    this.flags = flags;
    this.version = version;
    this.started = new Date();
    this.checks = [];
    this.findings = [];
    this.toolCache = new Map();
    this.needsApproval = [];
    this.facts = discover(cfg._wpRoot);
    this.customDirs = customCodeDirs(cfg);
    this.runId = `${runStamp(this.started)}-${mode}`;
    this.outDir = path.join(cfg._outRoot, 'reports', this.runId);
    fs.mkdirSync(this.outDir, { recursive: true });
    this.changedFiles = null;
  }

  log(line) { if (!this.flags.quiet) process.stdout.write(line + '\n'); }

  artifactDir(name) {
    const d = path.join(this.outDir, 'artifacts', name);
    fs.mkdirSync(d, { recursive: true });
    return d;
  }

  /* ------------------------------ tools ------------------------------ */

  /** Detect a tool from config.tools; returns { ok, cmd, version, hint }. */
  async tool(name) {
    if (this.toolCache.has(name)) return this.toolCache.get(name);
    const t = this.cfg.tools;
    const setting = t[name];
    const cmd = toolCommand(setting, t.php);
    let res = { ok: false, name, cmd, version: null, hint: PLATFORM_HINTS[name] || null };
    const env = { SEMGREP_SEND_METRICS: 'off', ...toolEnv(t) };
    const envPath = env[Object.keys(env).find((k) => k.toUpperCase() === 'PATH')];
    if (cmd && (which(cmd[0], envPath) || fs.existsSync(cmd[0]))) {
      const versionArgs = { php: ['-r', 'echo PHP_VERSION;'], wp: ['--version'], composer: ['--version', '--no-ansi'], semgrep: ['--version', '--disable-version-check'], docker: ['version', '--format', '{{.Server.Version}}'], k6: ['version'], npm: ['--version'] }[name] || ['--version'];
      const r = await runTool(setting, versionArgs, { php: t.php, timeoutMs: 60000, env, cleanPhp: PHP_TOOLS.has(name) });
      const out = (r.stdout.trim() || r.stderr.trim()).split('\n')[0].replace(/\x1b\[[0-9;]*m/g, '').slice(0, 80);
      if (r.code === 0 && out) res = { ...res, ok: true, version: out };
      else res.error = truncate(r.stderr || r.stdout, 300);
      if (r.phpDiagnostics?.length) res.startupWarnings = r.phpDiagnostics;
    }
    this.toolCache.set(name, res);
    return res;
  }

  /** WP-CLI availability including DB connectivity. */
  async wpCli() {
    if (this.toolCache.has('wp:db')) return this.toolCache.get('wp:db');
    const base = await this.tool('wp');
    let res = { ...base, db: false };
    if (base.ok) {
      const r = await this.wp(['option', 'get', 'siteurl']);
      const siteurl = r.stdout.trim().split('\n').pop().trim();
      if (r.code === 0 && /^https?:\/\//.test(siteurl)) res = { ...res, db: true, siteurl };
      else res.dbError = truncate((r.stderr || r.stdout).replace(/\s+/g, ' '), 300);
    }
    this.toolCache.set('wp:db', res);
    return res;
  }

  wp(args, opts = {}) {
    return runTool(this.cfg.tools.wp, [...args, `--path=${this.cfg._wpRoot}`, '--no-color'], { php: this.cfg.tools.php, env: toolEnv(this.cfg.tools), timeoutMs: opts.timeoutMs || 5 * 60 * 1000, cwd: this.cfg._wpRoot, cleanPhp: true });
  }

  php(args, opts = {}) {
    return runTool(this.cfg.tools.php, args, { env: toolEnv(this.cfg.tools), cleanPhp: true, ...opts });
  }

  /** Environment for other tool processes (Semgrep …). */
  toolEnv() { return toolEnv(this.cfg.tools); }

  /* ------------------------------ checks ----------------------------- */

  selected(id) {
    const { only, skip } = this.flags;
    const match = (pattern) => {
      const re = new RegExp('^' + pattern.split('*').map((s) => s.replace(/[.+?^${}()|[\]\\]/g, '\\$&')).join('.*') + '$');
      return re.test(id) || id.startsWith(pattern + '.');
    };
    if (only?.length && !only.some(match)) return false;
    if (skip?.length && skip.some(match)) return false;
    return true;
  }

  /**
   * Run one check.
   * meta: { id, title, category, tool, requires: { tools:[], wpcli:'db'|'bin', url:true, customCode:true } }
   */
  async check(meta, fn) {
    if (!this.selected(meta.id)) return null;
    const c = new CheckContext(this, meta);
    const started = Date.now();
    try {
      const req = meta.requires || {};
      if (req.customCode && !this.customDirs.length) {
        c.notApplicable('no custom themes/plugins configured in scan.themes / scan.plugins');
      }
      for (const t of req.tools || []) {
        if (c.status) break;
        const tool = await this.tool(t);
        if (!tool.ok) c.skip(`tool not available: ${t}${tool.error ? ` (${tool.error})` : ''}`, tool.hint);
      }
      if (!c.status && req.wpcli) {
        const w = await this.wpCli();
        if (!w.ok) c.skip('WP-CLI not available', PLATFORM_HINTS.wp);
        else if (req.wpcli === 'db' && !w.db) c.skip(`WP-CLI cannot reach the database${w.dbError ? `: ${w.dbError}` : ''}`, PLATFORM_HINTS.wp);
      }
      if (!c.status && req.url) {
        const reach = await this.siteReachable();
        if (!reach.ok) c.skip(`site not reachable at ${this.cfg.site.url} (${reach.error})`, 'Start the site (LocalWP: Start site) or fix site.url in wpqa.config.json.');
      }
      if (!c.status) await fn(c);
    } catch (e) {
      c.status = 'error';
      c.reason = e instanceof ToolError ? e.message : truncate(e.stack || String(e), 1500);
    }
    if (!c.status) {
      const failing = c.findings.filter((f) => f.severity !== 'info');
      c.status = failing.length ? 'failed' : 'passed';
    }
    const record = {
      id: meta.id,
      title: meta.title,
      category: meta.category,
      tool: meta.tool || null,
      status: c.status,
      reason: c.reason,
      howTo: c.howTo,
      notes: c.notes,
      artifacts: c.artifacts,
      stats: c.stats,
      findingCount: c.findings.length,
      durationMs: Date.now() - started,
      // What was examined: ['*'] = the check's whole subject (site-wide checks), otherwise files/dirs/URLs.
      scope: c._scope ? [...c._scope].sort() : ['*'],
    };
    this.checks.push(record);
    this.findings.push(...c.findings);
    const tag = { passed: '[PASS]', failed: '[FAIL]', skipped: '[SKIP]', not_applicable: '[N/A ]', error: '[ERR ]' }[c.status];
    const extra = c.status === 'failed' ? `${c.findings.length} finding(s)` : c.reason ? truncate(c.reason.split('\n')[0], 140) : c.findings.length ? `${c.findings.length} info` : '';
    this.log(`${tag} ${meta.id.padEnd(34)} ${extra} (${((Date.now() - started) / 1000).toFixed(1)}s)`);
    return record;
  }

  async siteReachable() {
    if (this._reach) return this._reach;
    const { httpFetch } = await import('./util.mjs');
    let host = '';
    try { host = new URL(this.cfg.site.url).hostname; } catch { /* validated in config */ }
    try {
      await dns.lookup(host);
    } catch (e) {
      this._reach = { ok: false, error: `cannot resolve host "${host}" (${e.code || e.message}) — check site.url` };
      return this._reach;
    }
    const r = await httpFetch(this.cfg.site.url, { timeoutMs: 15000, readBody: false, redirect: 'follow' });
    this._reach = r.ok ? { ok: true, status: r.status } : { ok: false, error: r.error };
    return this._reach;
  }

  /** Custom code directories, optionally limited to changed files (--changed). */
  customFiles(walk) {
    const files = [];
    for (const d of this.customDirs) files.push(...walk(d.dir));
    if (this.changedFiles) {
      const set = new Set(this.changedFiles.map((f) => path.resolve(f)));
      return files.filter((f) => set.has(path.resolve(f)));
    }
    return files;
  }

  /** Apply per-rule caps and aggregation so reports stay readable. */
  finalizeFindings() {
    // Merge exact duplicates (same check/rule/location), keeping all distinct messages.
    const byId = new Map();
    for (const f of this.findings) {
      const prev = byId.get(f.id);
      if (!prev) { byId.set(f.id, f); continue; }
      if (f.message && prev.message !== f.message && !prev.message?.includes(f.message)) prev.message = [prev.message, f.message].filter(Boolean).join(' · ');
    }
    this.findings = [...byId.values()];
    const cap = this.cfg.code.maxFindingsPerRule || 25;
    const groups = new Map();
    for (const f of this.findings) {
      const key = `${f.check}|${f.rule || f.title}|${f.aggregate ? 'agg' : 'ind'}`;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(f);
    }
    const out = [];
    for (const [, list] of groups) {
      const first = list[0];
      if (first.aggregate) {
        const sevOrder = [...list].sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity]);
        out.push({
          ...first,
          severity: sevOrder[0].severity,
          id: hash(first.check, first.rule || first.title, 'aggregate'),
          title: `${first.title} (${list.length} occurrence${list.length > 1 ? 's' : ''})`,
          count: list.length,
          locations: list.slice(0, 15).map((f) => (f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : f.url)).filter(Boolean),
          file: null,
          line: null,
        });
      } else if (list.length > cap) {
        out.push(...list.slice(0, cap));
        out.push({
          ...first,
          id: hash(first.check, first.rule || first.title, 'overflow'),
          severity: first.severity,
          title: `${first.rule || first.title}: ${list.length - cap} more occurrence(s) not listed individually`,
          count: list.length - cap,
          locations: list.slice(cap, cap + 30).map((f) => (f.file ? `${f.file}${f.line ? ':' + f.line : ''}` : f.url)).filter(Boolean),
          file: null,
          line: null,
          evidence: null,
        });
      } else out.push(...list);
    }
    // Deduplicate identical findings reported by multiple tools (same file/line/severity class).
    const seen = new Map();
    const deduped = [];
    for (const f of out.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity])) {
      // Same problem found by two tools/checks (PHPCS + scanner on one line; wordpress.org + WP-CLI "update available").
      if (f.dedupeKey && (f.file || f.url)) {
        const k = `${f.file || f.url}:${f.line || ''}:${f.dedupeKey}`;
        if (seen.has(k)) { seen.get(k).alsoReportedBy = [...(seen.get(k).alsoReportedBy || []), f.tool]; continue; }
        seen.set(k, f);
      }
      deduped.push(f);
    }
    this.findings = deduped;
  }
}

export { run, runTool };
