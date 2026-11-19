// Small, dependency-free HTML helpers for SEO and caching checks (regex based; good enough for server-rendered WP).
// Nonce helpers return WHERE a nonce is, never its value.

const attr = (tag, name) => {
  const m = tag.match(new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[2] ?? m[3] ?? m[4] ?? '') : null;
};
const decode = (s) => String(s ?? '').replace(/&amp;/g, '&').replace(/&quot;/g, '"').replace(/&#0?39;|&#8217;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&#8211;/g, '–').replace(/&#8212;/g, '—').trim();
const tags = (html, name) => [...String(html || '').matchAll(new RegExp(`<${name}\\b[^>]*>`, 'gi'))].map((m) => m[0]);

/** SEO-relevant facts of one HTML page. */
export function pageFacts(html, headers = {}) {
  const h = String(html || '');
  const head = h.split(/<\/head>/i)[0];
  const title = (head.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1];
  const metas = tags(head, 'meta');
  const meta = (n) => { const t = metas.find((x) => (attr(x, 'name') || attr(x, 'property') || '').toLowerCase() === n); return t ? decode(attr(t, 'content')) : null; };
  const links = tags(head, 'link');
  const canonicalTag = links.find((x) => (attr(x, 'rel') || '').toLowerCase().split(/\s+/).includes('canonical'));
  const hreflang = links.filter((x) => attr(x, 'hreflang') && /alternate/i.test(attr(x, 'rel') || '')).map((x) => ({ lang: attr(x, 'hreflang'), href: decode(attr(x, 'href')) }));
  const robots = [meta('robots'), meta('googlebot'), headers['x-robots-tag']].filter(Boolean).join(', ');
  const jsonLd = [...h.matchAll(/<script[^>]+type=["']application\/ld\+json["'][^>]*>([\s\S]*?)<\/script>/gi)].map((m) => {
    try { return { ok: true, data: JSON.parse(m[1]) }; } catch (e) { return { ok: false, error: e.message.slice(0, 120) }; }
  });
  const htmlTag = tags(h, 'html')[0] || '';
  return {
    title: title != null ? decode(title.replace(/<[^>]+>/g, '')) : null,
    description: meta('description'),
    canonical: canonicalTag ? decode(attr(canonicalTag, 'href')) : null,
    h1: (h.match(/<h1\b/gi) || []).length,
    lang: attr(htmlTag, 'lang'),
    robots,
    noindex: /\bnoindex\b/i.test(robots),
    hreflang,
    jsonLd,
    generator: meta('generator'),
  };
}

/** Where public HTML carries a WordPress nonce (field/attribute/key names only — never values). */
export function nonceMarkers(html) {
  const h = String(html || '');
  const out = new Set();
  for (const m of h.matchAll(/<input\b[^>]*>/gi)) {
    const name = attr(m[0], 'name') || '';
    if (/nonce/i.test(name) && /^[a-f0-9]{10}$/i.test(attr(m[0], 'value') || '')) out.add(`hidden field "${name}"`);
  }
  for (const m of h.matchAll(/\s(data-[a-z0-9_-]*nonce)\s*=\s*["']([a-f0-9]{10})["']/gi)) out.add(`attribute ${m[1]}`);
  for (const m of h.matchAll(/["']?([A-Za-z0-9_]*nonce[A-Za-z0-9_]*)["']?\s*:\s*["']([a-f0-9]{10})["']/gi)) out.add(`script value "${m[1]}"`);
  return [...out];
}

/** Same-origin CSS/JS/image URLs referenced by a page (for asset caching checks). */
export function assetUrls(html, baseUrl, max = 6) {
  const base = new URL(baseUrl);
  const out = [];
  const add = (u, type) => {
    try {
      const x = new URL(decode(u), base);
      if (x.host === base.host && !out.some((o) => o.url === x.href)) out.push({ url: x.href, type });
    } catch { /* skip */ }
  };
  for (const t of tags(html, 'link')) if (/stylesheet/i.test(attr(t, 'rel') || '') && attr(t, 'href')) add(attr(t, 'href'), 'css');
  for (const t of tags(html, 'script')) if (attr(t, 'src')) add(attr(t, 'src'), 'js');
  for (const t of tags(html, 'img')) if (attr(t, 'src') && !/^data:/.test(attr(t, 'src'))) add(attr(t, 'src'), 'image');
  const pick = [];
  for (const type of ['css', 'js', 'image']) pick.push(...out.filter((o) => o.type === type).slice(0, 2));
  return pick.slice(0, max);
}

/** Cache evidence from response headers: which layers answered and how old the copy is. */
export function cacheEvidence(h = {}, now = Date.now()) {
  const layers = [];
  const hit = (v) => /^(hit|stale|updating|revalidated)/i.test(String(v || ''));
  if (h['x-litespeed-cache']) layers.push({ layer: 'LiteSpeed', status: h['x-litespeed-cache'], hit: hit(h['x-litespeed-cache']) });
  if (h['x-hcdn-cache-status']) layers.push({ layer: 'Hostinger CDN', status: h['x-hcdn-cache-status'], hit: hit(h['x-hcdn-cache-status']) });
  if (h['cf-cache-status']) layers.push({ layer: 'Cloudflare', status: h['cf-cache-status'], hit: hit(h['cf-cache-status']) });
  if (h['x-cache']) layers.push({ layer: 'proxy (x-cache)', status: h['x-cache'], hit: /hit/i.test(h['x-cache']) });
  if (h['x-proxy-cache']) layers.push({ layer: 'nginx proxy cache', status: h['x-proxy-cache'], hit: hit(h['x-proxy-cache']) });
  if (h['x-nginx-cache']) layers.push({ layer: 'nginx cache', status: h['x-nginx-cache'], hit: hit(h['x-nginx-cache']) });
  if (h['x-varnish'] && /\d+\s+\d+/.test(h['x-varnish'])) layers.push({ layer: 'Varnish', status: 'hit', hit: true });
  if (h['x-wp-super-cache'] || h['wp-super-cache']) layers.push({ layer: 'WP Super Cache', status: h['x-wp-super-cache'] || h['wp-super-cache'], hit: true });
  const cc = String(h['cache-control'] || '').toLowerCase();
  const num = (k) => { const m = cc.match(new RegExp(`${k}=(\\d+)`)); return m ? Number(m[1]) : null; };
  const ages = [];
  if (h.age && /^\d+$/.test(String(h.age).trim())) ages.push({ sec: Number(h.age), from: `Age: ${h.age}` });
  // LiteSpeed's ETag is "<id>-<unix time the cached copy was generated>;<encoding>".
  const et = String(h.etag || '').match(/^"?\d+-(\d{10})(?:;[a-z]+)?"?$/i);
  if (et && layers.some((l) => l.layer === 'LiteSpeed' && l.hit)) ages.push({ sec: Math.max(0, Math.round(now / 1000 - Number(et[1]))), from: 'LiteSpeed ETag timestamp' });
  const oldest = ages.sort((a, b) => b.sec - a.sec)[0] || null;
  return {
    layers,
    anyHit: layers.some((l) => l.hit),
    noStore: /no-store|private/.test(cc),
    maxAge: num('s-maxage') ?? num('max-age'),
    expires: h.expires || null,
    ageSec: oldest?.sec ?? null,
    ageFrom: oldest?.from ?? null,
    cacheControl: h['cache-control'] || null,
  };
}
