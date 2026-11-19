// Seed site.pages for init: core sitemap, then SEO-plugin sitemaps (Yoast/Rank Math disable the core one),
// then the REST API. Read-only GET requests against the local site.
import { httpFetch, joinUrl } from './util.mjs';

/** <loc> values of a sitemap or sitemap index. */
export function extractLocs(xml) {
  return [...String(xml || '').matchAll(/<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]+)\s*(?:\]\]>)?\s*<\/loc>/g)].map((m) => m[1].replace(/&amp;/g, '&'));
}

/** Same-host paths from a list of URLs, '/' first, at most max. */
export function pagePaths(urls, baseUrl, max = 12) {
  const base = new URL(baseUrl);
  const pages = ['/'];
  for (const u of urls) {
    try {
      const x = new URL(u, base);
      if (x.hostname === base.hostname && !pages.includes(x.pathname)) pages.push(x.pathname);
    } catch { /* skip */ }
    if (pages.length >= max) break;
  }
  return pages;
}

/** Returns { pages, source } — source says where the list came from ('none' = only '/'). */
export async function seedPages(baseUrl, { fetch = httpFetch, max = 12 } = {}) {
  const get = async (p) => {
    const r = await fetch(joinUrl(baseUrl, p), { timeoutMs: 8000, redirect: 'follow' });
    return r.ok && r.status === 200 ? r.text : null;
  };
  // 1. WordPress core sitemap.
  const core = await get('wp-sitemap-pages-1.xml');
  if (core && extractLocs(core).length) return { pages: pagePaths(extractLocs(core), baseUrl, max), source: 'wp-sitemap-pages-1.xml' };
  // 2. Yoast / Rank Math / SEOPress / AIOSEO index → the pages sub-sitemap.
  for (const idx of ['sitemap_index.xml', 'sitemap.xml']) {
    const xml = await get(idx);
    if (!xml) continue;
    const locs = extractLocs(xml);
    if (!locs.length) continue;
    const isIndex = /<sitemapindex[\s>]/i.test(xml);
    if (!isIndex) return { pages: pagePaths(locs, baseUrl, max), source: idx }; // a plain <urlset>
    const sub = locs.find((l) => /page-sitemap|sitemap-pages|pages?[-_]sitemap/i.test(l));
    if (sub) {
      const pagesXml = await get(sub);
      if (pagesXml && extractLocs(pagesXml).length) return { pages: pagePaths(extractLocs(pagesXml), baseUrl, max), source: sub };
    }
  }
  // 3. REST API.
  const json = await get('wp-json/wp/v2/pages?per_page=20&_fields=link&orderby=menu_order&order=asc');
  if (json) {
    try {
      const links = JSON.parse(json).map((p) => p.link).filter(Boolean);
      if (links.length) return { pages: pagePaths(links, baseUrl, max), source: 'REST /wp/v2/pages' };
    } catch { /* not JSON */ }
  }
  return { pages: ['/'], source: 'none' };
}
