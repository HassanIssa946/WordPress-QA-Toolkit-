// OWASP ZAP via Docker (pinned image): baseline (passive) scan, and the full (active) scan only with dast.active.
// Approval-gated, never production. Without Docker the checks are reported as not run — never as passed.
import fs from 'node:fs';
import path from 'node:path';
import { run as runCmd } from '../lib/util.mjs';

const CAT = 'dast';
const RISK = { 3: 'high', 2: 'medium', 1: 'low', 0: 'info' };

/** A pinned image tag (x.y.z or a sha256 digest); "stable", "latest", "weekly" are refused. */
export function pinnedImage(img) {
  const s = String(img || '');
  return /@sha256:[a-f0-9]{64}$/.test(s) || /:\d+\.\d+\.\d+$/.test(s);
}

/** ZAP rules that describe the scanner itself, not the target (10116 = "ZAP is Out of Date"). */
export const ZAP_SELF_ALERTS = new Set(['10116']);

/**
 * ZAP JSON report → { alerts: [{ key, risk, name, count, urls, cwe, solution }], urls, self }.
 * `key` is ZAP's alertRef (one plugin can raise several distinct alerts, e.g. 10055-4 / 10055-5 for CSP).
 * `urls` = every URL ZAP reported on; `self` = alerts about ZAP itself (kept out of the findings).
 */
export function parseZapReport(j) {
  const alerts = [], self = [], urls = new Set();
  for (const site of [].concat(j?.site || [])) {
    for (const a of site.alerts || []) {
      const all = (a.instances || []).map((i) => i.uri).filter(Boolean);
      const item = { key: a.alertRef || `${a.pluginid}:${a.name || a.alert}`, risk: RISK[a.riskcode] || 'info', name: a.name || a.alert, pluginId: a.pluginid, count: Number(a.count || a.instances?.length || 1), urls: all.slice(0, 5), cwe: a.cweid, solution: String(a.solution || '').replace(/<[^>]+>/g, '').slice(0, 300) };
      if (ZAP_SELF_ALERTS.has(String(a.pluginid))) { self.push(item); continue; }
      all.forEach((u) => urls.add(u));
      alerts.push(item);
    }
  }
  return { alerts, urls: [...urls], self };
}

export default async function dast(run) {
  const { cfg } = run;
  const base = cfg.site.url.replace(/\/$/, '');
  const exec = run.exec || ((cmd, args, opts) => runCmd(cmd, args, opts));

  const scan = async (c, { kind, script, minutes }) => {
    if (!(await c.requireApproval(kind, base))) return;
    if (!pinnedImage(cfg.dast.zapImage)) return c.skip(`dast.zapImage "${cfg.dast.zapImage}" is not pinned to a version`, 'Use an exact version, e.g. ghcr.io/zaproxy/zaproxy:2.16.1, so results are reproducible.');
    const docker = await run.tool('docker');
    if (!docker.ok) return c.skip('Docker not available — ZAP did not run', 'ZAP needs Docker Desktop (not installed; waiting for approval). This check is NOT tested until then.');
    const dir = run.artifactDir(c.meta.id);
    const host = new URL(base).hostname;
    const addHost = /\.(local|test|localhost)$|^localhost$|^127\./.test(host) ? ['--add-host', `${host}:host-gateway`] : [];
    const r = await exec(cfg.tools.docker, ['run', '--rm', ...addHost, '-v', `${dir}:/zap/wrk:rw`, cfg.dast.zapImage, script, '-t', base, '-J', 'zap.json', '-m', String(minutes), '-I'], { timeoutMs: (minutes + 10) * 60000 });
    let j = null;
    try { j = JSON.parse(fs.readFileSync(path.join(dir, 'zap.json'), 'utf8')); } catch { /* none */ }
    if (!j) return c.toolError(`zap ${script}`, r, 'no ZAP JSON report produced');
    c.artifact(path.join(dir, 'zap.json'), 'ZAP report');
    const parsed = parseZapReport(j);
    c.scope([base, ...parsed.urls]);
    for (const s of parsed.self) c.note(`ZAP about itself (not a site finding): ${s.name} — the pinned image ${cfg.dast.zapImage} is kept for reproducible results; update dast.zapImage deliberately.`);
    c.stats = { alerts: parsed.alerts.length, urls: parsed.urls.length, image: cfg.dast.zapImage };
    c.note(`ZAP ${j['@version'] || ''} baseline: ${parsed.alerts.length} alert type(s) on ${parsed.urls.length} URL(s)`.replace('  ', ' '));
    for (const a of parsed.alerts) c.finding({ severity: a.risk, rule: `zap.${a.pluginId}`, title: `${a.name} (${a.count} instance${a.count > 1 ? 's' : ''})`, url: a.urls[0] || base, fingerprintExtra: String(a.key), message: a.urls.join(' · ') || null, references: a.cwe ? [`https://cwe.mitre.org/data/definitions/${a.cwe}.html`] : [], recommendation: a.solution || null, tool: 'OWASP ZAP' });
  };

  await run.check({ id: 'dast.zap-baseline', title: 'OWASP ZAP baseline (passive) scan', category: CAT, tool: 'OWASP ZAP (Docker)', requires: { url: true } }, (c) => scan(c, { kind: 'zap', script: 'zap-baseline.py', minutes: cfg.dast.maxMinutes }));
  await run.check({ id: 'dast.zap-full', title: 'OWASP ZAP full (active) scan', category: CAT, tool: 'OWASP ZAP (Docker)', requires: { url: true } }, async (c) => {
    if (cfg.dast.active !== true) return c.notApplicable('dast.active is false (active scans attack the site; enable only for a disposable sandbox)');
    return scan(c, { kind: 'zap-active', script: 'zap-full-scan.py', minutes: cfg.dast.maxMinutes });
  });
}
