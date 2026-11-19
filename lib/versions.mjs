// Version helpers for the stack mode: release-cycle matching, end-of-life status and version constraints
// (Composer / npm / WordPress "Requires" headers). Pure functions — no network.
import { compareVersions } from './util.mjs';

export const STATUS = {
  CURRENT: 'CURRENT',
  UPDATE: 'UPDATE AVAILABLE',
  SECURITY: 'SECURITY UPDATE REQUIRED',
  EOL: 'END OF LIFE',
  INCOMPATIBLE: 'INCOMPATIBLE',
  UNKNOWN: 'UNKNOWN',
};

/** "8.2.29-1ubuntu" → "8.2.29"; "v24.18.0" → "24.18.0"; null when no number. */
export function cleanVersion(v) {
  const m = String(v ?? '').match(/(\d+(?:\.\d+)*)/);
  return m ? m[1] : null;
}

/** The endoflife.date cycle a version belongs to (longest matching prefix: "8.4.0" → "8.4", "24.1.0" → "24"). */
export function cycleFor(version, cycles) {
  const v = cleanVersion(version);
  if (!v || !Array.isArray(cycles)) return null;
  let best = null;
  for (const c of cycles) {
    const cy = String(c.cycle);
    if ((v === cy || v.startsWith(cy + '.')) && (!best || cy.length > String(best.cycle).length)) best = c;
  }
  return best;
}

/** endoflife.date dates are a date string, true/false. Returns { ended, date } relative to `now`. */
export function eolInfo(cycle, now = new Date()) {
  if (!cycle) return { ended: null, date: null };
  const e = cycle.eol;
  if (e === true) return { ended: true, date: null };
  if (e === false || e == null) return { ended: false, date: null };
  const d = new Date(e + 'T00:00:00Z');
  if (isNaN(d)) return { ended: null, date: null };
  return { ended: d <= now, date: e, daysLeft: Math.ceil((d - now) / 864e5) };
}

/** Does a WPVulnerability "operator" range include version? (min/max with lt/le/gt/ge/eq). */
export function inVulnRange(op, version) {
  if (!op) return true;
  const cmp = (o, v) => {
    const r = compareVersions(version, v);
    return { lt: r < 0, le: r <= 0, gt: r > 0, ge: r >= 0, eq: r === 0 }[o] ?? true;
  };
  if (op.min_version && op.min_operator && !cmp(op.min_operator, op.min_version)) return false;
  if (op.max_version && op.max_operator && !cmp(op.max_operator, op.max_version)) return false;
  return true;
}

/** Human title of a WPVulnerability record (core records are named only by version; the title is in source[].name). */
export function vulnTitle(v) {
  const name = String(v?.name || '').trim();
  if (name && !/^[\d.]+$/.test(name)) return name;
  return (v?.source || []).map((s) => s.name).find(Boolean) || name || 'known vulnerability';
}

/**
 * Stable advisory ID. WPVulnerability can give many records the same uuid (all 19 WordPress 7.1.4 core records share
 * one), so the source's own ID (Wordfence/CVE) comes first.
 */
export function advisoryId(v) {
  const s = (v?.source || []).find((x) => x?.id);
  return s ? String(s.id) : v?.uuid || v?.name || null;
}

/** Vulnerabilities from a WPVulnerability response that affect `version`. */
export function affectingVulns(data, version) {
  return (data?.vulnerability || []).filter((v) => inVulnRange(v.operator, version)).map((v) => ({
    id: advisoryId(v),
    name: vulnTitle(v),
    severityRated: !!v.impact?.cvss?.severity, // false = the source gives no CVSS; severity is the toolkit default (high)
    severity: { c: 'critical', h: 'high', m: 'medium', l: 'low' }[v.impact?.cvss?.severity] || 'high',
    fixedIn: v.operator?.max_version && /lt/.test(v.operator?.max_operator || '') ? v.operator.max_version : null,
    cves: (v.source || []).map((s) => s.id).filter((id) => /^CVE-\d{4}-\d+$/i.test(id || '')).slice(0, 5),
    links: (v.source || []).map((s) => s.link).filter(Boolean).slice(0, 3),
  }));
}

/* ------------------------- version constraints ------------------------- */

const parts = (v) => String(v).split('.').map((x) => (/^\d+$/.test(x) ? Number(x) : x));

/** "^8.1" etc. → list of [op, version] comparators (AND). null when the syntax is not understood. */
function expand(term, flavor) {
  term = term.trim().replace(/^v/i, '');
  if (!term || term === '*' || /^x$/i.test(term)) return [];
  let m;
  if ((m = term.match(/^(\d+(?:\.\d+)*)\s+-\s+(\d+(?:\.\d+)*)$/))) return [['>=', m[1]], ['<=', m[2]]];
  if ((m = term.match(/^(>=|<=|>|<|=|==|!=)\s*v?(\d+(?:\.\d+)*)(?:[-@][\w.]+)?$/))) return [[m[1] === '==' ? '=' : m[1], m[2]]];
  if ((m = term.match(/^\^v?(\d+(?:\.\d+)*)(?:[-@][\w.]+)?$/))) {
    const p = parts(m[1]);
    const i = p.findIndex((x) => x !== 0);
    const idx = i === -1 ? p.length - 1 : i; // ^0.3 → <0.4; ^0.0.3 → <0.0.4
    const up = p.slice(0, idx + 1);
    up[idx] = Number(up[idx]) + 1;
    return [['>=', m[1]], ['<', up.join('.')]];
  }
  if ((m = term.match(/^~v?(\d+(?:\.\d+)*)(?:[-@][\w.]+)?$/))) {
    const p = parts(m[1]);
    // Composer: ~1.2 → <2.0, ~1.2.3 → <1.3. npm: ~1.2 → <1.3, ~1 → <2.
    const keep = flavor === 'composer' ? Math.max(1, p.length - 1) : (p.length === 1 ? 1 : 2);
    const up = p.slice(0, keep);
    up[keep - 1] = Number(up[keep - 1]) + 1;
    return [['>=', m[1]], ['<', up.join('.')]];
  }
  if ((m = term.match(/^(\d+(?:\.\d+)*)(?:\.[*x])+$/i)) || (m = term.match(/^(\d+(?:\.\d+)*)$/))) {
    if (/[*x]$/i.test(term) || flavor === 'npm') {
      const p = parts(m[1]);
      const up = [...p];
      up[up.length - 1] = Number(up[up.length - 1]) + 1;
      return [['>=', m[1]], ['<', up.join('.')]];
    }
    return [['=', m[1]]];
  }
  return null;
}

/**
 * Does `version` satisfy a Composer/npm constraint? true / false / null (constraint not understood).
 * flavor: 'composer' | 'npm'.
 */
export function satisfies(version, constraint, flavor = 'npm') {
  const v = cleanVersion(version);
  if (!v || typeof constraint !== 'string') return null;
  const alternatives = constraint.split(/\s*\|\|?\s*/);
  let understood = true;
  for (const alt of alternatives) {
    // AND: commas (Composer) or whitespace not part of a hyphen range. ">= 8.1" → ">=8.1" first.
    const terms = alt.replace(/(>=|<=|!=|==|>|<|=)\s+/g, '$1').replace(/\s+-\s+/g, '\u0000').split(/\s*,\s*|\s+/).map((t) => t.replace('\u0000', ' - ')).filter(Boolean);
    let ok = true;
    for (const t of terms) {
      const comps = expand(t, flavor);
      if (comps === null) { understood = false; ok = false; break; }
      for (const [op, target] of comps) {
        const r = compareVersions(v, target);
        const pass = { '>=': r >= 0, '<=': r <= 0, '>': r > 0, '<': r < 0, '=': r === 0, '!=': r !== 0 }[op];
        if (!pass) { ok = false; break; }
      }
      if (!ok) break;
    }
    if (ok) return true;
  }
  return understood ? false : null;
}

/** "Requires PHP: 8.1" style header: installed >= required. null when either is missing. */
export function meetsMinimum(installed, required) {
  const a = cleanVersion(installed), b = cleanVersion(required);
  if (!a || !b) return null;
  return compareVersions(a, b) >= 0;
}
