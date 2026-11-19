// The one gate for intrusive actions: editor drafts, write probes, load tests, ZAP scans.
// Every rule must pass; any failing rule refuses the action, and the reasons are reported.
// There is no production override: `safety.allowIntrusiveOnProduction` is ignored (config warning).
import dns from 'node:dns/promises';

export const INTRUSIVE_KINDS = ['editor-drafts', 'write-probe', 'load', 'zap', 'zap-active'];

/** Absolute ceilings. Config can lower them (safety.limits), never raise them. */
export const HARD_LIMITS = { maxVus: 50, maxDurationSec: 600 };

const lc = (s) => String(s || '').trim().toLowerCase().replace(/\.$/, '');
const hostOf = (u) => { try { return lc(new URL(u).hostname).replace(/^\[|\]$/g, ''); } catch { return null; } };

/** host plus its www./apex variant. */
export function hostVariants(host) {
  const h = lc(host);
  if (!h) return [];
  return h.startsWith('www.') ? [h, h.slice(4)] : [h, `www.${h}`];
}

/** Default resolver: every A/AAAA address of a host ([] when it does not resolve). */
export async function resolveAll(host) {
  try {
    return (await dns.lookup(host, { all: true })).map((a) => a.address.toLowerCase());
  } catch { return []; }
}

/** Effective limits: the lower of HARD_LIMITS and safety.limits. */
export function effectiveLimits(cfg) {
  const l = cfg?.safety?.limits || {};
  const pick = (k) => (Number.isFinite(l[k]) && l[k] > 0 ? Math.min(l[k], HARD_LIMITS[k]) : HARD_LIMITS[k]);
  return { maxVus: pick('maxVus'), maxDurationSec: pick('maxDurationSec') };
}

/**
 * Decide whether an intrusive action may run.
 * @param {object} o
 * @param {string} o.kind          one of INTRUSIVE_KINDS
 * @param {string} o.targetUrl     URL the action will hit
 * @param {object} o.cfg           loaded config (may lack a safety section → deny)
 * @param {object} o.flags         parsed CLI flags; approval only when flags.approve === true
 * @param {Function} [o.resolve]   host → Promise<string[]> (injected in tests)
 * @param {string|null} [o.wpEnvironment]  explicitly configured WP_ENVIRONMENT_TYPE of the target, if known
 * @param {object} [o.request]     { vus, durationSec, stress } for load tests
 * @returns {Promise<{allowed: boolean, reasons: string[], host: string|null, kind: string, target: string}>}
 */
export async function evaluateIntrusive({ kind, targetUrl, cfg, flags = {}, resolve = resolveAll, wpEnvironment = null, request = null }) {
  const reasons = [];
  const host = hostOf(targetUrl);
  const out = (extra = {}) => ({ allowed: reasons.length === 0, reasons, host, kind, target: String(targetUrl), ...extra });
  if (!INTRUSIVE_KINDS.includes(kind)) reasons.push(`unknown intrusive kind "${kind}"`);
  let protocol = null;
  try { protocol = new URL(targetUrl).protocol; } catch { /* invalid */ }
  if (protocol && !/^https?:$/.test(protocol)) { reasons.push(`only http(s) targets are allowed (got ${protocol})`); return out(); }
  if (!host) { reasons.push(`invalid target URL "${targetUrl}"`); return out(); }

  // 1. Explicit approval: exactly boolean true (the CLI rejects --approve=<value>).
  if (flags?.approve !== true) reasons.push('needs explicit approval (--approve)');

  // 2. Host listed in safety.allowedHosts — nothing is allowed automatically.
  const allowed = new Set((Array.isArray(cfg?.safety?.allowedHosts) ? cfg.safety.allowedHosts : []).map(lc));
  if (!allowed.has(host)) reasons.push(`host "${host}" is not in safety.allowedHosts`);

  // 3. Never production.
  if (!cfg?.site || cfg.site.environment !== 'local' && cfg.site.environment !== 'staging') {
    reasons.push(`site.environment is "${cfg?.site?.environment ?? 'missing'}" — intrusive tests only run on local or staging`);
  }
  const publicHost = cfg?.publicSite?.url ? hostOf(cfg.publicSite.url) : null;
  const prodHosts = publicHost ? hostVariants(publicHost) : [];
  if (prodHosts.includes(host)) reasons.push(`host "${host}" is the production site (publicSite.url ${publicHost}) — production is never a target`);
  if (wpEnvironment && lc(wpEnvironment) === 'production') reasons.push(`the target WordPress reports WP_ENVIRONMENT_TYPE = production`);

  // 4. Same machine as production? Compare resolved addresses.
  const targetIps = await resolve(host);
  if (!targetIps.length) reasons.push(`host "${host}" does not resolve`);
  if (prodHosts.length && targetIps.length && !prodHosts.includes(host)) {
    const prodIps = new Set((await Promise.all(prodHosts.map((h) => resolve(h)))).flat());
    const shared = targetIps.filter((ip) => prodIps.has(ip));
    if (shared.length) reasons.push(`host "${host}" resolves to production's address (${shared.join(', ')})`);
  }

  // 5. Load-test limits.
  if (kind === 'load' && request) {
    const lim = effectiveLimits(cfg);
    if (!(request.vus > 0) || request.vus > lim.maxVus) reasons.push(`requested ${request.vus} VUs exceeds the limit of ${lim.maxVus}`);
    if (!(request.durationSec > 0) || request.durationSec > lim.maxDurationSec) reasons.push(`requested duration ${request.durationSec}s exceeds the limit of ${lim.maxDurationSec}s`);
    if (request.stress && cfg?.safety?.allowStress !== true) reasons.push('stress profile needs safety.allowStress = true');
  }
  if (kind === 'zap-active' && cfg?.dast?.active !== true) reasons.push('active ZAP scan needs dast.active = true');
  return out();
}
