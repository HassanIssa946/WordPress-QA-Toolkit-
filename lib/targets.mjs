// Targets for passive page checks (SEO, caching, cached nonces): the audited site and, when configured, the public
// production site (GET only). Pages = site.pages plus pages found in the sitemap, fetched once per run.
import { joinUrl } from './util.mjs';
import { seedPages } from './pages.mjs';

/** Fetch a page once per run (GET, follow redirects, compressed). */
export async function getPage(run, url) {
  run._pageCache ||= new Map();
  if (!run._pageCache.has(url)) {
    run._pageCache.set(url, run.http(url, { timeoutMs: 30000, redirect: 'follow', headers: { 'accept-encoding': 'gzip, deflate, br', accept: 'text/html,application/xhtml+xml' } }));
  }
  return run._pageCache.get(url);
}

/**
 * [{ base, env, label, production, pages: [paths] }]. The audited site always comes first; production is added for
 * passive checks when publicSite.url is set and differs. `max` caps pages per target.
 */
export async function pageTargets(run, { max = run.cfg.seo?.maxPages || 20 } = {}) {
  if (run._targets) return run._targets;
  const { cfg } = run;
  const list = [{ base: cfg.site.url.replace(/\/$/, ''), env: cfg.site.environment, label: cfg.site.environment === 'production' ? 'production' : `${cfg.site.environment} site`, production: cfg.site.environment === 'production' }];
  const pub = cfg.publicSite?.url?.replace(/\/$/, '');
  if (pub && cfg.site.environment !== 'production' && new URL(pub).host !== new URL(list[0].base).host) list.push({ base: pub, env: 'production', label: 'production (public site, read-only GET)', production: true });
  for (const t of list) {
    const seeded = await seedPages(t.base, { fetch: run.http, max }).catch(() => ({ pages: ['/'] }));
    const pages = [...new Set([...(cfg.site.pages || ['/']), ...seeded.pages])].slice(0, max);
    t.pages = pages;
    t.pageSource = seeded.source || 'none';
  }
  run._targets = list;
  return list;
}

export const pageUrl = (t, p) => joinUrl(t.base + '/', p.replace(/^\//, ''));

/**
 * Targets that can be checked now. When the audited site itself is down, passive checks still look at production
 * (GET only) but the check is marked skipped afterwards, so the verdict stays INCOMPLETE — never a partial PASS.
 * Returns { targets, finish(c) }; call finish(c) at the end of the check.
 */
export async function reachableTargets(run) {
  const reach = await run.siteReachable();
  const all = await pageTargets(run);
  const targets = reach.ok ? all : all.slice(1);
  return {
    targets,
    finish(c) {
      if (!reach.ok) c.skip(`site not reachable at ${run.cfg.site.url} (${reach.error})${targets.length ? ' — only the public production site was checked' : ''}`, 'Start the site (LocalWP: Start site) and rerun for a complete result.');
    },
  };
}
