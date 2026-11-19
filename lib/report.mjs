// Report generation: JSON + Markdown, coverage, and comparison with the previous run.
import fs from 'node:fs';
import path from 'node:path';
import { SEVERITIES, SEV_RANK, CATEGORIES } from './engine.mjs';
import { summarizeDiscovery } from './discover.mjs';
import { MODES } from './modes.mjs';

/** Last report.json of the same mode (runs of other modes test other things and would show as "not re-tested"). */
export function findPreviousReport(outRoot, currentRunId, mode) {
  const dir = path.join(outRoot, 'reports');
  let runs = [];
  try { runs = fs.readdirSync(dir).filter((d) => d !== currentRunId).sort(); } catch { return null; }
  for (let i = runs.length - 1; i >= 0; i--) {
    if (mode && !runs[i].endsWith(`-${mode}`)) continue;
    const p = path.join(dir, runs[i], 'report.json');
    if (!fs.existsSync(p)) continue;
    try {
      const r = JSON.parse(fs.readFileSync(p, 'utf8'));
      if (!mode || r.mode === mode) return r;
    } catch { /* ignore broken report */ }
  }
  return null;
}

/** Is a location (relative file path or URL) covered by a check's recorded scope? '*' = whole subject. */
export function inScope(scope, loc) {
  if (!scope?.length) return false;
  if (scope.includes('*')) return true;
  return scope.some((e) => e === loc || loc.startsWith(e.replace(/\/$/, '') + '/'));
}

/** Files/URLs a finding is about ([] = site-wide finding such as "no SPF record"). */
export function findingLocations(f) {
  if (f.file) return [f.file];
  if (f.url) return [f.url];
  if (f.locations?.length) return f.locations.map((l) => (/^[a-z]+:\/\//i.test(l) ? l : l.replace(/:\d+$/, '')));
  return [];
}

/**
 * Compare with the previous run of the same mode.
 * A previous finding that is gone counts as resolved only when the same check ran again (passed/failed) AND
 * scanned the finding's file/URL again. Otherwise it is "not re-tested" (check skipped/errored/not selected,
 * or --changed left the file out).
 */
export function diffRuns(prev, current) {
  if (!prev) return null;
  const prevSchema = prev.schemaVersion || 1;
  if (prevSchema !== (current.schemaVersion || SCHEMA_VERSION)) {
    // Finding IDs are computed differently across schema versions: comparing them would invent new/resolved items.
    return {
      previousRunId: prev.runId, previousMode: prev.mode, baselineReset: true,
      reason: `previous report uses report schema v${prevSchema}, this run v${current.schemaVersion || SCHEMA_VERSION}; finding IDs are not comparable, so this run starts a new comparison baseline`,
      new: [], stillOpen: [], resolved: [], notRetested: [],
    };
  }
  // Open items of the previous run = its findings + what it carried as "not re-tested" (those stay open until a
  // run actually re-tests them; without this they would silently vanish after one more incomplete run).
  const carried = (prev.diff?.notRetested || []).filter((f) => f?.id && !prev.findings.some((p) => p.id === f.id));
  const open = [...prev.findings, ...carried];
  const curIds = new Set(current.findings.map((f) => f.id));
  const prevIds = new Set(open.map((f) => f.id));
  const scopes = new Map(current.checks.filter((c) => c.status === 'passed' || c.status === 'failed').map((c) => [c.id, c.scope || ['*']]));
  const resolved = [];
  const notRetested = [];
  for (const f of open) {
    if (curIds.has(f.id)) continue;
    const scope = scopes.get(f.check);
    if (!scope) { notRetested.push({ ...f, why: `check ${f.check} did not run this time` }); continue; }
    const locs = findingLocations(f);
    const missing = locs.filter((l) => !inScope(scope, l));
    if (missing.length) notRetested.push({ ...f, why: `not scanned again: ${missing.slice(0, 3).join(', ')}` });
    else resolved.push(f);
  }
  return {
    previousRunId: prev.runId,
    previousMode: prev.mode,
    new: current.findings.filter((f) => !prevIds.has(f.id)).map((f) => f.id),
    stillOpen: current.findings.filter((f) => prevIds.has(f.id)).map((f) => f.id),
    resolved: resolved.map((f) => ({ id: f.id, severity: f.severity, title: f.title, check: f.check, file: f.file, url: f.url })),
    // Keep the locations so a later run can tell whether it re-scanned them.
    notRetested: notRetested.map((f) => ({ id: f.id, severity: f.severity, title: f.title, check: f.check, rule: f.rule, file: f.file ?? null, url: f.url ?? null, locations: f.locations, firstSeen: f.firstSeen, why: f.why })),
  };
}

/** Per-area coverage. Phase-2 placeholders (planned: true) are not counted — they do not exist in this version. */
export function coverage(checks) {
  const by = {};
  for (const c of checks) {
    if (c.planned) continue;
    const k = c.category;
    by[k] ||= { category: k, label: CATEGORIES[k] || k, total: 0, passed: 0, failed: 0, skipped: 0, not_applicable: 0, error: 0 };
    by[k].total++;
    by[k][c.status]++;
  }
  for (const v of Object.values(by)) {
    const applicable = v.total - v.not_applicable;
    v.executed = v.passed + v.failed;
    v.coveragePct = applicable ? Math.round((v.executed / applicable) * 100) : null;
  }
  return Object.values(by);
}

const isUrl = (s) => /^[a-z][a-z0-9+.-]*:\/\//i.test(s);

/**
 * Overall execution totals (phase-2 placeholders excluded from all but `planned`) and what was inspected:
 * distinct files/folders and URLs from the scopes of checks that executed. Site-wide checks ('*') add nothing.
 */
export function coverageSummary(checks) {
  const s = { total: 0, applicable: 0, executed: 0, passed: 0, failed: 0, skipped: 0, errored: 0, notApplicable: 0, planned: 0, coveragePct: null, filesInspected: 0, urlsInspected: 0 };
  const files = new Set();
  const urls = new Set();
  for (const c of checks) {
    if (c.planned) { s.planned++; continue; }
    s.total++;
    if (c.status === 'passed') s.passed++;
    else if (c.status === 'failed') s.failed++;
    else if (c.status === 'skipped') s.skipped++;
    else if (c.status === 'error') s.errored++;
    else if (c.status === 'not_applicable') s.notApplicable++;
    if (c.status === 'passed' || c.status === 'failed') {
      for (const e of c.scope || []) if (e !== '*') (isUrl(e) ? urls : files).add(e);
    }
  }
  s.applicable = s.total - s.notApplicable;
  s.executed = s.passed + s.failed;
  s.coveragePct = s.applicable ? Math.floor((s.executed / s.applicable) * 100) : null;
  s.filesInspected = files.size;
  s.urlsInspected = urls.size;
  return s;
}

export const SCHEMA_VERSION = 2;
export const EXIT_CODES = { PASS: 0, FAIL: 1, ERROR: 2, INCOMPLETE: 3 };

/**
 * Verdict:
 * - FAIL       findings at/above failOn exist (they are real regardless of what else was skipped);
 * - INCOMPLETE no blocking findings, but a core check of the mode was skipped/errored, coverage is below
 *              minCoverage, or nothing was tested — a PASS cannot be claimed;
 * - PASS       otherwise.
 * `incomplete` lists the reasons and is filled even when the status is FAIL.
 */
export function verdict(findings, failOn, { checks = [], core = [], minCoverage = 80 } = {}) {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
  for (const f of findings) counts[f.severity]++;
  const blocking = failOn === 'none' ? 0 : findings.filter((f) => SEV_RANK[f.severity] <= SEV_RANK[failOn]).length;
  const counted = checks.filter((c) => !c.planned);
  const applicable = counted.filter((c) => c.status !== 'not_applicable');
  const executed = applicable.filter((c) => c.status === 'passed' || c.status === 'failed');
  const ratio = applicable.length ? (executed.length / applicable.length) * 100 : null;
  const incomplete = [];
  for (const c of counted) {
    if (core.includes(c.id) && (c.status === 'skipped' || c.status === 'error')) {
      incomplete.push(`core check ${c.id} ${c.status === 'error' ? 'errored' : 'was skipped'}: ${String(c.reason || '').split('\n')[0].slice(0, 160)}`);
    }
  }
  if (!executed.length) incomplete.push('no check was executed');
  else if (ratio < minCoverage) incomplete.push(`coverage ${Math.floor(ratio)}% (${executed.length}/${applicable.length} applicable checks executed) is below minCoverage ${minCoverage}%`);
  const status = blocking ? 'FAIL' : incomplete.length ? 'INCOMPLETE' : 'PASS';
  return { status, pass: status === 'PASS', blocking, counts, coveragePct: ratio == null ? null : Math.floor(ratio), minCoverage, incomplete };
}

export function buildReport(runCtx) {
  const { cfg, mode, flags, checks, findings, facts } = runCtx;
  const finished = new Date();
  findings.sort((a, b) => SEV_RANK[a.severity] - SEV_RANK[b.severity] || (a.category || '').localeCompare(b.category || ''));
  // Stable short references (C1, H2 ...) for discussion with Claude/humans.
  const counters = {};
  for (const f of findings) {
    const p = f.severity[0].toUpperCase();
    counters[p] = (counters[p] || 0) + 1;
    f.ref = `${p}${counters[p]}`;
  }
  const report = {
    tool: 'wordpress-qa-toolkit',
    schemaVersion: SCHEMA_VERSION,
    version: runCtx.version,
    runId: runCtx.runId,
    mode,
    flags: { approve: !!flags.approve, changed: !!flags.changed, only: flags.only || null, skip: flags.skip || null },
    project: cfg.project.name,
    target: { url: cfg.site.url, environment: cfg.site.environment, publicUrl: cfg.publicSite?.url || null },
    startedAt: runCtx.started.toISOString(),
    finishedAt: finished.toISOString(),
    durationSec: Math.round((finished - runCtx.started) / 1000),
    verdict: verdict(findings, cfg.failOn, { checks, core: MODES[mode]?.core || [], minCoverage: cfg.minCoverage ?? 80 }),
    failOn: cfg.failOn,
    coverage: coverage(checks),
    coverageSummary: coverageSummary(checks),
    planned: checks.filter((c) => c.planned).map((c) => c.id),
    checks,
    findings,
    needsApproval: runCtx.needsApproval,
    approvals: runCtx.approvals || [],
    sections: (runCtx.sections || []).map(({ id, title, lines, data }) => ({ id, title, lines, data })),
    environment: {
      discovery: summarizeDiscovery(facts),
      wpVersion: facts.wpVersion,
      tools: Object.fromEntries([...runCtx.toolCache.entries()].filter(([k]) => !k.includes(':')).map(([k, v]) => [k, v.ok ? v.version : 'unavailable'])),
      node: process.version,
      platform: process.platform,
      customCode: runCtx.customDirs.map((d) => `${d.type}:${d.slug}`),
    },
  };
  return report;
}

const esc = (s) => String(s ?? '').replace(/\|/g, '\\|').replace(/\r?\n/g, ' ');

export function renderMarkdown(r, diff) {
  const L = [];
  const v = r.verdict;
  L.push(`# WordPress QA Report — ${r.project}`);
  L.push('');
  L.push(`**Mode:** \`${r.mode}\` · **Target:** ${r.target.url} (${r.target.environment})${r.target.publicUrl ? ` · **Public:** ${r.target.publicUrl}` : ''}  `);
  L.push(`**Run:** ${r.runId} · **Duration:** ${r.durationSec}s · **Toolkit:** v${r.version}`);
  L.push('');
  const status = v.status || (v.pass ? 'PASS' : 'FAIL');
  const verdictLine = {
    PASS: `✅ **PASS** — no findings at or above \`${r.failOn}\`, coverage ${v.coveragePct ?? '—'}%`,
    FAIL: `❌ **FAIL** — ${v.blocking} finding(s) at or above \`${r.failOn}\``,
    INCOMPLETE: `⚠️ **INCOMPLETE** — no findings at or above \`${r.failOn}\`, but this run cannot be called a pass`,
  }[status];
  L.push(`## Verdict\n\n${verdictLine}`);
  if (v.incomplete?.length) {
    L.push('');
    L.push(status === 'INCOMPLETE' ? 'Why incomplete:' : 'Also incomplete:');
    for (const why of v.incomplete) L.push(`- ${why}`);
  }
  const skipped = r.checks.filter((c) => c.status === 'skipped' || c.status === 'error');
  if (skipped.length) L.push(`\n> ⚠️ ${skipped.length} check(s) were skipped or errored and are **not** counted as passed — see "Not tested" below.`);
  L.push('');
  L.push('| Critical | High | Medium | Low | Info |');
  L.push('|---:|---:|---:|---:|---:|');
  L.push(`| ${v.counts.critical} | ${v.counts.high} | ${v.counts.medium} | ${v.counts.low} | ${v.counts.info} |`);
  L.push('');

  L.push('## Coverage');
  L.push('');
  L.push('Coverage = executed checks ÷ applicable checks. It measures how much was tested, not how good the site is.');
  L.push('');
  L.push('| Area | Passed | Failed | Skipped | Errors | N/A | Coverage |');
  L.push('|---|---:|---:|---:|---:|---:|---:|');
  for (const c of r.coverage) L.push(`| ${c.label} | ${c.passed} | ${c.failed} | ${c.skipped} | ${c.error} | ${c.not_applicable} | ${c.coveragePct == null ? '—' : c.coveragePct + '%'} |`);
  L.push('');
  L.push(`Overall: **${v.coveragePct ?? '—'}%** (minimum ${v.minCoverage ?? 80}%).`);
  const cs = r.coverageSummary;
  if (cs) {
    L.push('');
    L.push('| Applicable | Executed | Passed | Failed | Skipped | Errored | N/A | Files/folders inspected | URLs inspected |');
    L.push('|---:|---:|---:|---:|---:|---:|---:|---:|---:|');
    L.push(`| ${cs.applicable} | ${cs.executed} | ${cs.passed} | ${cs.failed} | ${cs.skipped} | ${cs.errored} | ${cs.notApplicable} | ${cs.filesInspected} | ${cs.urlsInspected} |`);
  }
  if (r.planned?.length) L.push(`Not in this version (phase 2, not counted, **not tested**): ${r.planned.map((p) => '`' + p + '`').join(', ')}.`);
  L.push('');

  if (diff?.baselineReset) {
    L.push(`## Changes since previous run (\`${diff.previousRunId}\`)`);
    L.push('');
    L.push(`Not compared: ${diff.reason}.`);
    L.push('');
  } else if (diff) {
    L.push(`## Changes since previous run (\`${diff.previousRunId}\`)`);
    L.push('');
    L.push(`- 🆕 New: **${diff.new.length}** · 🔁 Still open: **${diff.stillOpen.length}** · ✅ Resolved: **${diff.resolved.length}** · ❔ Not re-tested this run: **${diff.notRetested.length}**`);
    if (diff.resolved.length) {
      L.push('');
      L.push('Resolved:');
      for (const f of diff.resolved.slice(0, 30)) L.push(`- ~~${f.severity.toUpperCase()} — ${f.title}~~ ${f.file || f.url || ''}`);
    }
    const nr = diff.notRetested.filter((f) => ['critical', 'high', 'medium'].includes(f.severity));
    if (nr.length) {
      L.push('');
      L.push('Not re-tested (assume still open):');
      for (const f of nr.slice(0, 30)) L.push(`- ${f.severity.toUpperCase()} — ${f.title} (${f.why})`);
    }
    L.push('');
  }

  if (r.needsApproval?.length) {
    L.push('## Waiting for approval');
    L.push('');
    L.push('These tests can affect availability or data and were **not** run. Re-run with `--approve` only after the site owner agrees:');
    L.push('');
    for (const a of r.needsApproval) L.push(`- \`${a.check}\` — ${a.kind} against ${a.target}`);
    L.push('');
  }
  const refused = (r.approvals || []).filter((a) => !a.allowed && !(a.reasons.length === 1 && a.reasons[0].startsWith('needs explicit approval')));
  const ran = (r.approvals || []).filter((a) => a.allowed);
  if (refused.length || ran.length) {
    L.push('## Safety gate');
    L.push('');
    for (const a of ran) L.push(`- ✅ \`${a.check}\` — ${a.kind} against ${a.target}: allowed (--approve, allowlisted, non-production)`);
    for (const a of refused) L.push(`- ⛔ \`${a.check}\` — ${a.kind} against ${a.target}: refused — ${a.reasons.join('; ')}`);
    L.push('');
  }

  for (const sec of r.sections || []) {
    L.push(`## ${sec.title}`);
    L.push('');
    L.push(...sec.lines);
    L.push('');
  }

  L.push('## Findings');
  L.push('');
  if (!r.findings.length) L.push('_No findings._');
  const newIds = new Set(diff?.new || []);
  for (const sev of ['critical', 'high', 'medium']) {
    const list = r.findings.filter((f) => f.severity === sev);
    if (!list.length) continue;
    L.push(`### ${sev[0].toUpperCase() + sev.slice(1)} (${list.length})`);
    L.push('');
    for (const f of list) {
      L.push(`#### [${f.ref}] ${f.title}${newIds.has(f.id) && diff ? ' 🆕' : ''}`);
      const where = f.file ? `\`${f.file}${f.line ? ':' + f.line : ''}\`` : f.url ? f.url : null;
      if (where) L.push(`- **Where:** ${where}`);
      if (f.locations?.length) L.push(`- **Locations:** ${f.locations.slice(0, 10).map((l) => '`' + l + '`').join(', ')}${f.count > 10 ? ' …' : ''}`);
      L.push(`- **Check:** \`${f.check}\` · **Tool:** ${f.tool}${f.rule ? ` · **Rule:** \`${f.rule}\`` : ''} · **Confidence:** ${f.confidence}${f.alsoReportedBy ? ` · also: ${f.alsoReportedBy.join(', ')}` : ''}`);
      if (f.message) L.push(`- **Details:** ${f.message}`);
      if (f.evidence) L.push('- **Evidence:**\n\n  ```\n  ' + f.evidence.replace(/\n/g, '\n  ') + '\n  ```');
      if (f.recommendation) L.push(`- **Fix:** ${f.recommendation}`);
      L.push('');
    }
  }
  const minor = r.findings.filter((f) => f.severity === 'low' || f.severity === 'info');
  if (minor.length) {
    L.push(`### Low & info (${minor.length})`);
    L.push('');
    L.push('| Ref | Sev | Finding | Where | Fix |');
    L.push('|---|---|---|---|---|');
    for (const f of minor) {
      const where = f.file ? `\`${f.file}${f.line ? ':' + f.line : ''}\`` : f.locations?.length ? `\`${f.locations[0]}\`${f.count > 1 ? ` +${f.count - 1}` : ''}` : f.url || '';
      L.push(`| ${f.ref} | ${f.severity} | ${esc(f.title)} | ${esc(where)} | ${esc(f.recommendation || '')} |`);
    }
    L.push('');
  }

  L.push('## Checks');
  L.push('');
  L.push('| Check | Area | Status | Findings | Notes |');
  L.push('|---|---|---|---:|---|');
  const icon = { passed: '✅ passed', failed: '❌ failed', skipped: '⏭️ skipped', not_applicable: '➖ n/a', error: '💥 error' };
  for (const c of r.checks) L.push(`| \`${c.id}\` | ${c.category} | ${icon[c.status]} | ${c.findingCount} | ${esc((c.reason || c.notes.join('; ')).split('\n')[0]).slice(0, 160)} |`);
  L.push('');

  if (skipped.length) {
    L.push('## Not tested (skipped or errored)');
    L.push('');
    L.push('| Check | Reason | How to enable |');
    L.push('|---|---|---|');
    for (const c of skipped) L.push(`| \`${c.id}\` | ${esc((c.reason || '').split('\n')[0]).slice(0, 200)} | ${esc(c.howTo || '')} |`);
    L.push('');
  }

  const arts = r.checks.flatMap((c) => c.artifacts.map((a) => ({ ...a, check: c.id })));
  if (arts.length) {
    L.push('## Artifacts');
    L.push('');
    for (const a of arts) L.push(`- \`${a.check}\`: [${a.label}](${path.posix.relative(`.wpqa/reports/${r.runId}`, a.path)})`);
    L.push('');
  }

  L.push('## Environment');
  L.push('');
  L.push('```');
  L.push(r.environment.discovery);
  L.push(`Custom code scanned: ${r.environment.customCode.join(', ') || '(none configured)'}`);
  L.push(`Tools: ${Object.entries(r.environment.tools).map(([k, v]) => `${k}=${v}`).join(', ')}`);
  L.push(`Node ${r.environment.node} on ${r.environment.platform}`);
  L.push('```');
  L.push('');
  return L.join('\n');
}

export function writeReport(runCtx) {
  const report = buildReport(runCtx);
  const prev = findPreviousReport(runCtx.cfg._outRoot, runCtx.runId, runCtx.mode);
  const diff = diffRuns(prev, report);
  report.diff = diff;
  // Per-finding retest status and first sighting (carried over from the previous comparable report).
  const prevById = new Map(diff && !diff.baselineReset ? prev.findings.map((f) => [f.id, f]) : []);
  for (const f of report.findings) {
    const p = prevById.get(f.id);
    f.retest = !diff || diff.baselineReset ? null : p ? 'still-open' : 'new';
    f.firstSeen = p ? p.firstSeen || prev.runId : report.runId;
  }
  const jsonPath = path.join(runCtx.outDir, 'report.json');
  const mdPath = path.join(runCtx.outDir, 'report.md');
  fs.writeFileSync(jsonPath, JSON.stringify(report, null, 2));
  fs.writeFileSync(mdPath, renderMarkdown(report, diff));
  const latest = { runId: report.runId, mode: report.mode, report: path.relative(runCtx.cfg._root, mdPath).split(path.sep).join('/'), json: path.relative(runCtx.cfg._root, jsonPath).split(path.sep).join('/'), verdict: report.verdict, finishedAt: report.finishedAt };
  fs.writeFileSync(path.join(runCtx.cfg._outRoot, 'latest.json'), JSON.stringify(latest, null, 2));
  return { report, diff, jsonPath, mdPath };
}
