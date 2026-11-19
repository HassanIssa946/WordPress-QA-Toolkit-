// SEO: robots.txt, sitemaps (core / Yoast / Rank Math), and per page: title, description, canonical, one H1, lang,
// noindex (an error only on production), hreflang (Polylang/WPML), JSON-LD. Read-only GET requests.
import { reachableTargets, getPage, pageUrl } from '../lib/targets.mjs';
import { pageFacts } from '../lib/html.mjs';
import { extractLocs } from '../lib/pages.mjs';
import { joinUrl } from '../lib/util.mjs';

const CAT = 'seo';
const LANG_RE = /^(x-default|[a-z]{2,3}(-[A-Za-z0-9]{2,8})*)$/i;

/** robots.txt → { blocksAll, sitemaps } for "User-agent: *". */
export function parseRobots(text) {
  const lines = String(text || '').split(/\r?\n/).map((l) => l.replace(/#.*/, '').trim()).filter(Boolean);
  let star = false, blocksAll = false, inGroup = false;
  const sitemaps = [];
  for (const l of lines) {
    const [k, ...rest] = l.split(':');
    const key = k.trim().toLowerCase(), val = rest.join(':').trim();
    if (key === 'sitemap') { sitemaps.push(val); continue; }
    if (key === 'user-agent') { if (!inGroup) star = false; inGroup = true; if (val === '*') star = true; continue; }
    inGroup = false;
    if (star && key === 'disallow' && val === '/') blocksAll = true;
  }
  return { blocksAll, sitemaps };
}

export default async function seo(run) {
  const { cfg, facts } = run;
  const multilingual = facts.plugins.some((p) => /^(polylang|polylang-pro|sitepress-multilingual-cms|translatepress-multilingual)$/.test(p.slug));
  const prodSev = (t, onProd, otherwise = 'info') => (t.production ? onProd : otherwise);

  await run.check({ id: 'seo.robots', title: 'robots.txt', category: CAT }, async (c) => {
    const { targets, finish } = await reachableTargets(run);
    if (!targets.length) return finish(c);
    for (const t of targets) {
      const url = joinUrl(t.base, 'robots.txt');
      const r = await run.http(url, { timeoutMs: 20000, redirect: 'follow' });
      if (!r.ok) { if (!t.production) return c.skip(`robots.txt not fetched: ${r.error}`); c.note(`${t.label}: robots.txt not fetched (${r.error})`); continue; }
      c.scope([url]);
      if (r.status === 404) { c.finding({ severity: prodSev(t, 'low', 'info'), rule: 'seo.robots-missing', title: `${t.label}: robots.txt returns 404`, url, recommendation: 'WordPress serves a virtual robots.txt; a 404 usually means a server rule or a static file is in the way.' }); continue; }
      if (r.status >= 400) { c.note(`${t.label}: robots.txt HTTP ${r.status}`); continue; }
      const rb = parseRobots(r.text);
      t.robots = rb;
      if (rb.blocksAll) c.finding({ severity: prodSev(t, 'critical'), rule: 'seo.robots-blocks-all', title: `${t.label}: robots.txt disallows the whole site`, url, recommendation: t.production ? 'Remove "Disallow: /" (Settings → Reading → "Discourage search engines" may be on).' : 'Expected on a non-production copy; make sure it is not deployed to production.' });
      if (!rb.sitemaps.length) c.finding({ severity: prodSev(t, 'low', 'info'), rule: 'seo.robots-no-sitemap', title: `${t.label}: robots.txt does not reference a sitemap`, url, recommendation: 'Add a "Sitemap: https://…/sitemap_index.xml" line (SEO plugins and core do this when sitemaps are on).' });
    }
    finish(c);
  });

  await run.check({ id: 'seo.sitemap', title: 'XML sitemap (core, Yoast, Rank Math)', category: CAT }, async (c) => {
    const { targets, finish } = await reachableTargets(run);
    if (!targets.length) return finish(c);
    for (const t of targets) {
      const candidates = [...new Set([...(t.robots?.sitemaps || []), joinUrl(t.base, 'sitemap_index.xml'), joinUrl(t.base, 'wp-sitemap.xml')])];
      let found = null;
      for (const u of candidates) {
        const r = await run.http(u, { timeoutMs: 20000, redirect: 'follow' });
        if (r.ok && r.status === 200 && /<(urlset|sitemapindex)[\s>]/i.test(r.text)) { found = { url: r.url || u, xml: r.text }; break; }
      }
      if (!found) { c.finding({ severity: prodSev(t, 'medium', 'low'), rule: 'seo.sitemap-missing', title: `${t.label}: no XML sitemap found`, url: t.base, message: `Tried: ${candidates.join(', ')}`, recommendation: 'Enable the core sitemap or your SEO plugin\'s sitemap.' }); continue; }
      c.scope([found.url]);
      const isIndex = /<sitemapindex[\s>]/i.test(found.xml);
      const locs = extractLocs(found.xml);
      let urls = isIndex ? [] : locs;
      if (isIndex) for (const sub of locs.slice(0, 5)) { const r = await run.http(sub, { timeoutMs: 20000, redirect: 'follow' }); if (r.ok && r.status === 200) urls.push(...extractLocs(r.text)); else c.finding({ severity: prodSev(t, 'medium', 'low'), rule: 'seo.sitemap-broken', title: `${t.label}: sub-sitemap returns ${r.ok ? `HTTP ${r.status}` : r.error}`, url: sub }); }
      const host = new URL(t.base).host;
      const foreign = urls.filter((u) => { try { return new URL(u).host !== host; } catch { return true; } });
      if (foreign.length) c.finding({ severity: prodSev(t, 'medium', 'low'), rule: 'seo.sitemap-host', title: `${t.label}: ${foreign.length} sitemap URL(s) point to another host`, url: found.url, message: foreign.slice(0, 5).join(', '), recommendation: 'Sitemap URLs must use the site\'s own domain (check siteurl/home and the SEO plugin settings).' });
      for (const u of urls.filter((x) => !foreign.includes(x)).slice(0, 5)) {
        const r = await run.http(u, { timeoutMs: 20000, redirect: 'manual', readBody: false });
        c.scope([u]);
        if (!r.ok || r.status !== 200) c.finding({ severity: prodSev(t, 'medium', 'low'), rule: 'seo.sitemap-url', title: `${t.label}: sitemap lists a URL that returns ${r.ok ? `HTTP ${r.status}` : r.error}`, url: u, recommendation: 'Sitemaps should list only final, indexable 200 URLs (no redirects or errors).' });
      }
      c.note(`${t.label}: ${found.url} (${isIndex ? 'index' : 'urlset'}, ${urls.length} URL(s) read)`);
    }
    finish(c);
  });

  await run.check({ id: 'seo.pages', title: 'Titles, descriptions, canonical, H1, lang, noindex, hreflang, JSON-LD', category: CAT }, async (c) => {
    const { targets, finish } = await reachableTargets(run);
    if (!targets.length) return finish(c);
    let checked = 0;
    for (const t of targets) {
      const titles = new Map();
      for (const p of t.pages) {
        const url = pageUrl(t, p);
        const r = await getPage(run, url);
        if (!r.ok || r.status >= 400 || !/html/i.test(r.headers['content-type'] || 'text/html')) { c.note(`${t.label}: ${url} → ${r.ok ? `HTTP ${r.status}` : r.error}`); continue; }
        checked++;
        c.scope([url]);
        const f = pageFacts(r.text, r.headers);
        const where = (rule, severity, title, extra = {}) => c.finding({ severity, rule, title: `${t.label}: ${title}`, url, fingerprintExtra: rule, ...extra });
        if (f.noindex) where('seo.noindex', prodSev(t, 'high'), `page is noindex (${f.robots})`, { recommendation: t.production ? 'Remove noindex unless this page must stay out of search results.' : 'Normal on a non-production copy — make sure production does not inherit it.' });
        if (!f.title) where('seo.title-missing', 'medium', 'no <title>', { recommendation: "add_theme_support( 'title-tag' ) or an SEO plugin." });
        else { if (f.title.length > 65) where('seo.title-length', 'info', `title is ${f.title.length} characters (search results show ~60)`); titles.set(f.title, [...(titles.get(f.title) || []), url]); }
        if (!f.description) where('seo.description-missing', 'low', 'no meta description', { recommendation: 'Write a unique description (SEO plugin field).' });
        if (!f.canonical) where('seo.canonical-missing', 'low', 'no canonical link');
        else {
          try {
            const cu = new URL(f.canonical, url);
            if (cu.host !== new URL(url).host) where('seo.canonical-host', t.production ? 'high' : 'medium', `canonical points to another host (${cu.host})`, { recommendation: 'Canonical must use the page\'s own domain; check home/siteurl and the SEO plugin.' });
          } catch { where('seo.canonical-invalid', 'medium', `canonical is not a valid URL (${f.canonical.slice(0, 80)})`); }
        }
        if (f.h1 !== 1) where('seo.h1', 'low', f.h1 === 0 ? 'no <h1>' : `${f.h1} <h1> elements`, { recommendation: 'Use exactly one H1 with the page topic.' });
        if (!f.lang) where('seo.lang', 'medium', '<html> has no lang attribute', { recommendation: 'Call language_attributes() on the <html> tag.' });
        const bad = f.hreflang.filter((h) => !LANG_RE.test(h.lang) || !/^https?:\/\//.test(h.href));
        if (bad.length) where('seo.hreflang-invalid', 'medium', `invalid hreflang entries: ${bad.map((h) => h.lang).join(', ')}`, { recommendation: 'hreflang needs a valid language code and an absolute URL.' });
        if (f.hreflang.length) {
          const self = f.hreflang.some((h) => { try { return new URL(h.href).pathname === new URL(r.url || url).pathname; } catch { return false; } });
          if (!self) where('seo.hreflang-self', 'low', 'hreflang set does not include this page itself');
        } else if (multilingual) where('seo.hreflang-missing', 'low', 'multilingual plugin active but no hreflang links', { recommendation: 'Polylang/WPML add hreflang automatically for translated pages; check that translations are linked.' });
        const invalidLd = f.jsonLd.filter((x) => !x.ok);
        if (invalidLd.length) where('seo.jsonld-invalid', 'medium', `${invalidLd.length} JSON-LD block(s) are not valid JSON`, { message: invalidLd[0].error });
        if (!f.jsonLd.length) where('seo.jsonld-missing', 'info', 'no JSON-LD structured data');
      }
      for (const [title, urls] of titles) if (urls.length > 1) c.finding({ severity: 'low', rule: 'seo.title-duplicate', title: `${t.label}: ${urls.length} pages share the title "${title.slice(0, 60)}"`, url: urls[0], fingerprintExtra: `dup:${t.base}:${title}`, message: urls.join(', ') });
      c.note(`${t.label}: ${t.pages.length} page(s) (site.pages + sitemap: ${t.pageSource})`);
    }
    if (!checked) return c.skip('no page could be fetched');
    finish(c);
  });
}
