// Dependency audits of YOUR code: `composer audit` (composer.lock) and `npm audit` (package-lock.json).
// Read-only: lock files are audited as they are; nothing is installed, updated or fixed.
import path from 'node:path';
import { exists, runTool, parseJsonLoose } from '../lib/util.mjs';

const CAT = 'dependencies';
const NPM_SEV = { critical: 'critical', high: 'high', moderate: 'medium', low: 'low', info: 'info' };
const LOWER = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };

/** Folders with a lock file: each custom theme/plugin and the project root. */
export function lockDirs(run, lockName) {
  const dirs = [...run.customDirs.map((d) => ({ dir: d.dir, label: `${d.type} ${d.slug}` })), { dir: run.cfg._root, label: 'project root' }];
  const seen = new Set();
  return dirs.filter((d) => {
    const key = path.resolve(d.dir);
    if (seen.has(key) || !exists(path.join(d.dir, lockName))) return false;
    seen.add(key);
    return true;
  });
}

/** composer audit --format=json → [{ pkg, id, title, cve, link, severity, affected }], abandoned → [{ pkg, replacement }]. */
export function parseComposerAudit(j) {
  const out = [];
  const adv = j?.advisories && !Array.isArray(j.advisories) ? j.advisories : {};
  for (const [pkg, list] of Object.entries(adv)) {
    for (const a of [].concat(list || [])) out.push({ pkg, id: a.advisoryId || a.cve || a.title, title: a.title || 'security advisory', cve: a.cve || null, link: a.link || null, severity: ['critical', 'high', 'medium', 'low'].includes(a.severity) ? a.severity : 'high', affected: a.affectedVersions || null });
  }
  const abandoned = Object.entries(j?.abandoned || {}).map(([pkg, replacement]) => ({ pkg, replacement: replacement || null }));
  return { advisories: out, abandoned };
}

/** npm audit --json (v2 report) → [{ pkg, severity, title, url, range, direct, fix }]. */
export function parseNpmAudit(j) {
  const out = [];
  for (const [name, v] of Object.entries(j?.vulnerabilities || {})) {
    const advisories = (v.via || []).filter((x) => typeof x === 'object');
    // Packages vulnerable only through another package ("via": ["other"]) are reported at the source.
    if (!advisories.length) continue;
    for (const a of advisories) out.push({ pkg: name, id: a.source ?? a.url ?? a.title, severity: NPM_SEV[a.severity] || NPM_SEV[v.severity] || 'high', title: a.title || 'advisory', url: a.url || null, range: a.range || v.range || null, direct: !!v.isDirect, fix: v.fixAvailable === false ? 'no fix available' : v.fixAvailable === true ? 'fix available (npm audit fix)' : v.fixAvailable?.name ? `fix: ${v.fixAvailable.name}@${v.fixAvailable.version}${v.fixAvailable.isSemVerMajor ? ' (major version)' : ''}` : null });
  }
  return out;
}

export default async function dependencies(run) {
  const { cfg } = run;
  const exec = run.exec || ((tool, args, opts) => runTool(cfg.tools[tool], args, { php: cfg.tools.php, env: run.toolEnv(), timeoutMs: 180000, ...opts }));

  await run.check({ id: 'dependencies.composer-audit', title: 'Composer packages with known vulnerabilities (composer audit)', category: CAT, tool: 'composer audit', requires: { tools: ['composer'] } }, async (c) => {
    const dirs = lockDirs(run, 'composer.lock');
    if (!dirs.length) return c.notApplicable('no composer.lock in your themes/plugins or the project root');
    c.scope(dirs.map((d) => path.join(d.dir, 'composer.lock')));
    for (const d of dirs) {
      const r = await exec('composer', ['audit', '--locked', '--format=json', '--no-interaction', '--no-ansi'], { cwd: d.dir, cleanPhp: true });
      const j = parseJsonLoose(r.stdout);
      if (!j || typeof j !== 'object') return c.toolError(`composer audit (${d.label})`, r, 'returned no JSON');
      const { advisories, abandoned } = parseComposerAudit(j);
      for (const a of advisories) c.finding({ severity: a.severity, rule: 'composer.advisory', title: `${d.label}: ${a.pkg} — ${a.title}`, file: path.join(d.dir, 'composer.lock'), fingerprintExtra: `${a.pkg}:${a.id}`, message: [a.cve, a.affected && `affected ${a.affected}`].filter(Boolean).join(' · ') || null, references: a.link ? [a.link] : [], recommendation: `Update ${a.pkg} (composer update ${a.pkg} --with-dependencies) on a branch, run the tests, then deploy.` });
      for (const a of abandoned) c.finding({ severity: 'low', rule: 'composer.abandoned', title: `${d.label}: ${a.pkg} is abandoned${a.replacement ? ` (use ${a.replacement})` : ''}`, file: path.join(d.dir, 'composer.lock'), fingerprintExtra: `abandoned:${a.pkg}`, recommendation: 'Abandoned packages get no security fixes. Plan a replacement.' });
    }
  });

  await run.check({ id: 'dependencies.npm-audit', title: 'npm packages with known vulnerabilities (npm audit)', category: CAT, tool: 'npm audit', requires: { tools: ['npm'] } }, async (c) => {
    const dirs = lockDirs(run, 'package-lock.json');
    if (!dirs.length) return c.notApplicable('no package-lock.json in your themes/plugins or the project root');
    c.scope(dirs.map((d) => path.join(d.dir, 'package-lock.json')));
    for (const d of dirs) {
      // Runtime dependencies (shipped in your build) at their severity; dev-only ones (build tools) one level lower.
      const prodR = await exec('npm', ['audit', '--json', '--package-lock-only', '--omit=dev'], { cwd: d.dir });
      const allR = await exec('npm', ['audit', '--json', '--package-lock-only'], { cwd: d.dir });
      const prodJ = parseJsonLoose(prodR.stdout), allJ = parseJsonLoose(allR.stdout);
      if (!allJ || allJ.error || !prodJ || prodJ.error) return c.toolError(`npm audit (${d.label})`, allJ?.error ? allR : prodR, (allJ?.error || prodJ?.error)?.summary || 'returned no JSON');
      const prod = parseNpmAudit(prodJ);
      const prodKeys = new Set(prod.map((a) => `${a.pkg}:${a.id}`));
      for (const a of prod) c.finding({ severity: a.severity, rule: 'npm.advisory', title: `${d.label}: ${a.pkg} — ${a.title}`, file: path.join(d.dir, 'package-lock.json'), fingerprintExtra: `${a.pkg}:${a.id}`, message: [a.range && `vulnerable ${a.range}`, a.fix].filter(Boolean).join(' · ') || null, references: a.url ? [a.url] : [], recommendation: 'Runtime dependency (ends up in your build). Update it, rebuild, and test.' });
      const devOnly = parseNpmAudit(allJ).filter((a) => !prodKeys.has(`${a.pkg}:${a.id}`));
      if (devOnly.length) {
        const rank = ['critical', 'high', 'medium', 'low', 'info'];
        const counts = rank.map((s) => [s, devOnly.filter((a) => a.severity === s).length]).filter(([, n]) => n);
        const worst = counts[0][0];
        const pkgs = [...new Set(devOnly.map((a) => a.pkg))];
        c.finding({ severity: LOWER[worst], rule: 'npm.advisory-dev', title: `${d.label}: ${devOnly.length} advisories in build-only npm packages (${counts.map(([s, n]) => `${n} ${s}`).join(', ')})`, file: path.join(d.dir, 'package-lock.json'), fingerprintExtra: `dev:${d.dir}`, message: `Packages: ${pkgs.slice(0, 12).join(', ')}${pkgs.length > 12 ? ` … +${pkgs.length - 12}` : ''}. Worst: ${devOnly.find((a) => a.severity === worst).pkg} — ${devOnly.find((a) => a.severity === worst).title}`, references: devOnly.map((a) => a.url).filter(Boolean).slice(0, 3), recommendation: 'These run on your machine/CI during the build, not on the site (one level lower than npm rates them). Update when convenient (bump @wordpress/scripts, then npm update), rebuild and test.' });
      }
    }
  });
}
