// Network, DNS, TLS and HTTP checks. All passive/read-only (a few GET requests), safe on production.
import dnsReal from 'node:dns/promises';
import tls from 'node:tls';
import https from 'node:https';
import http from 'node:http';
import { httpFetch, followRedirects, joinUrl, isLocalHost, median } from '../lib/util.mjs';

const CAT = 'infrastructure';

/** DNS answer: records, [] when the name has no such record (ENODATA / NXDOMAIN), null when the lookup failed. */
async function resolve(fn, name) {
  try { return await fn(name); } catch (e) { return e.code === 'ENODATA' || e.code === 'ENOTFOUND' ? [] : null; }
}

/** Errors that mean "this machine could not resolve the name", not "the server has no HTTPS". */
export const DNS_ERRORS = new Set(['EAI_AGAIN', 'ENOTFOUND', 'EAI_FAIL', 'EAI_NODATA', 'EAI_NONAME', 'ESERVFAIL', 'ETIMEOUT']);

function tlsProbeReal(host, opts = {}) {
  return new Promise((res) => {
    const sock = tls.connect({ host, port: 443, servername: host, rejectUnauthorized: false, timeout: 15000, ...opts }, () => {
      const cert = sock.getPeerCertificate(true);
      res({ ok: true, authorized: sock.authorized, authError: sock.authorizationError, protocol: sock.getProtocol(), alpn: sock.alpnProtocol, cert });
      sock.end();
    });
    sock.on('error', (e) => res({ ok: false, error: e.code || e.message }));
    sock.on('timeout', () => { sock.destroy(); res({ ok: false, error: 'timeout' }); });
  });
}

function timing(url) {
  return new Promise((res) => {
    const u = new URL(url);
    const lib = u.protocol === 'https:' ? https : http;
    const t0 = performance.now();
    const t = {};
    const req = lib.get(u, { headers: { 'user-agent': 'wpqa-toolkit/2.0' }, timeout: 20000 }, (r) => {
      r.once('data', () => { t.ttfb = performance.now() - t0; });
      r.on('end', () => { t.total = performance.now() - t0; res({ ok: true, ...t }); });
      r.resume();
    });
    req.on('socket', (s) => {
      s.on('lookup', () => { t.dns = performance.now() - t0; });
      s.on('connect', () => { t.connect = performance.now() - t0; });
      s.on('secureConnect', () => { t.tls = performance.now() - t0; });
    });
    req.on('error', (e) => res({ ok: false, error: e.code || e.message }));
    req.on('timeout', () => { req.destroy(); res({ ok: false, error: 'timeout' }); });
  });
}

export default async function infrastructure(run) {
  const { cfg } = run;
  const dns = run.dns || dnsReal; // injectable for tests
  const tlsProbe = run.tlsProbe || tlsProbeReal;
  const publicUrl = cfg.publicSite?.url || (!isLocalHost(new URL(cfg.site.url).hostname) ? cfg.site.url : null);
  const pub = publicUrl ? new URL(publicUrl) : null;
  const apex = pub ? pub.hostname.replace(/^www\./, '') : null;
  const needPublic = (c) => { if (!pub) { c.notApplicable('no public domain (set publicSite.url in wpqa.config.json)'); return false; } return true; };

  await run.check({ id: 'infra.dns', title: 'DNS records (A/AAAA/CNAME/NS/CAA)', category: CAT, tool: 'node:dns' }, async (c) => {
    if (!needPublic(c)) return;
    const hosts = [...new Set([apex, `www.${apex}`])];
    c.scope(hosts.map((h) => `https://${h}`));
    const rec = {};
    for (const h of hosts) rec[h] = { A: await resolve(dns.resolve4, h), AAAA: await resolve(dns.resolve6, h), CNAME: await resolve(dns.resolveCname, h) };
    if (rec[apex].A === null) return c.skip('DNS lookups failing from this machine', 'Check your internet/DNS connection');
    for (const h of hosts) {
      const r = rec[h];
      if (!r.A?.length && !r.AAAA?.length && !r.CNAME?.length) c.finding({ severity: h === pub.hostname ? 'critical' : 'medium', rule: 'dns.no-address', title: `${h} does not resolve`, url: `https://${h}`, recommendation: h.startsWith('www.') ? `Add a CNAME www → ${apex} (and redirect it).` : 'Add an A record pointing to the server.' });
    }
    const ns = await resolve(dns.resolveNs, apex);
    if (ns && ns.length === 1) c.finding({ severity: 'medium', rule: 'dns.ns', title: 'Only 1 nameserver', recommendation: 'Use at least two nameservers.' });
    const caa = await resolve(dns.resolveCaa, apex);
    if (caa && !caa.length) c.finding({ severity: 'low', rule: 'dns.caa', title: 'No CAA record', recommendation: `Restrict which CAs may issue certificates, e.g. ${apex}. CAA 0 issue "letsencrypt.org".` });
    if (!rec[apex].AAAA?.length) c.finding({ severity: 'info', rule: 'dns.ipv6', title: 'No IPv6 (AAAA) record' });
    c.stats = { records: rec, ns };
    c.note(`A ${apex}: ${(rec[apex].A || []).join(', ') || '-'}; NS: ${(ns || []).join(', ')}`);
  });

  await run.check({ id: 'infra.email-dns', title: 'Email authentication DNS (MX, SPF, DMARC)', category: CAT, tool: 'node:dns' }, async (c) => {
    if (!needPublic(c)) return;
    // "No SPF/DMARC" is only a finding when DNS demonstrably works: the domain resolves and every lookup answered.
    const apexA = await resolve(dns.resolve4, apex), apexAAAA = await resolve(dns.resolve6, apex);
    if (!apexA?.length && !apexAAAA?.length) return c.skip(`DNS lookups failing from this machine (${apex} did not resolve) — SPF/DMARC not tested`, 'Check your internet/DNS connection and rerun.');
    const mx = await resolve(dns.resolveMx, apex);
    const txtApex = await resolve(dns.resolveTxt, apex);
    const txtDmarc = await resolve(dns.resolveTxt, `_dmarc.${apex}`);
    if (mx === null || txtApex === null || txtDmarc === null) return c.skip('DNS lookups failed part-way (no answer for MX/TXT) — SPF/DMARC not tested', 'Check your internet/DNS connection and rerun.');
    const spf = txtApex.map((t) => t.join('')).filter((t) => /^v=spf1/i.test(t));
    const dmarc = txtDmarc.map((t) => t.join('')).filter((t) => /^v=DMARC1/i.test(t));
    if (!mx?.length) c.finding({ severity: 'info', rule: 'email.mx', title: 'No MX record (domain receives no email)', recommendation: 'If the contact form sends "from" this domain, still publish SPF/DMARC.' });
    if (!spf.length) c.finding({ severity: 'medium', rule: 'email.spf', title: 'No SPF record', recommendation: `Contact-form emails may land in spam and the domain can be spoofed. Add TXT "v=spf1 include:<your mail provider> -all" (or "v=spf1 -all" if the domain never sends).` });
    if (spf.length > 1) c.finding({ severity: 'high', rule: 'email.spf-multiple', title: 'Multiple SPF records (SPF fails permanently)', evidence: spf.join('\n'), recommendation: 'Merge into one record.' });
    if (spf.some((s) => /\+all\b/.test(s))) c.finding({ severity: 'high', rule: 'email.spf-all', title: 'SPF ends with +all (anyone may send as you)', evidence: spf.join('\n') });
    if (!dmarc.length) c.finding({ severity: 'medium', rule: 'email.dmarc', title: 'No DMARC record', recommendation: `Add TXT _dmarc.${apex} "v=DMARC1; p=quarantine; rua=mailto:dmarc@${apex}" (start with p=none to monitor).` });
    else if (/p=none/i.test(dmarc[0])) c.finding({ severity: 'low', rule: 'email.dmarc-none', title: 'DMARC policy is p=none (monitor only)', evidence: dmarc[0] });
  });

  await run.check({ id: 'infra.tls', title: 'TLS certificate, chain and protocols', category: CAT, tool: 'node:tls' }, async (c) => {
    if (!needPublic(c)) return;
    const hosts = [...new Set([pub.hostname, apex, `www.${apex}`])];
    c.scope(hosts.map((h) => `https://${h}`));
    for (const h of hosts) {
      const p = await tlsProbe(h, { ALPNProtocols: ['h2', 'http/1.1'] });
      // A name this machine cannot resolve says nothing about HTTPS (missing www records are infra.dns's job).
      if (!p.ok && DNS_ERRORS.has(p.error)) {
        if (h === pub.hostname) return c.skip(`could not resolve ${h} from this machine (${p.error}) — TLS not tested`, 'Check your internet/DNS connection and rerun.');
        c.note(`${h}: not resolvable from this machine (${p.error}) — TLS not tested for this host`);
        continue;
      }
      if (!p.ok) { c.finding({ severity: h === pub.hostname ? 'critical' : 'medium', rule: 'tls.connect', title: `HTTPS not available on ${h} (${p.error})`, url: `https://${h}` }); continue; }
      if (!p.authorized) c.finding({ severity: 'critical', rule: 'tls.invalid', title: `Certificate not trusted for ${h}: ${p.authError}`, url: `https://${h}`, recommendation: 'Install a valid certificate covering this hostname with the full intermediate chain.' });
      const days = Math.floor((new Date(p.cert.valid_to) - Date.now()) / 864e5);
      if (days < 0) c.finding({ severity: 'critical', rule: 'tls.expired', title: `Certificate for ${h} expired ${-days} day(s) ago`, url: `https://${h}` });
      else if (days < 14) c.finding({ severity: 'high', rule: 'tls.expiring', title: `Certificate for ${h} expires in ${days} day(s)`, url: `https://${h}`, recommendation: 'Check auto-renewal (certbot/hosting panel).' });
      else if (days < 30) c.finding({ severity: 'medium', rule: 'tls.expiring', title: `Certificate for ${h} expires in ${days} days`, url: `https://${h}` });
      if (/TLSv1(\.1)?$/.test(p.protocol || '')) c.finding({ severity: 'high', rule: 'tls.old-negotiated', title: `${h} negotiated ${p.protocol}`, url: `https://${h}` });
      if (h === pub.hostname && p.alpn !== 'h2') c.finding({ severity: 'low', rule: 'tls.http2', title: 'HTTP/2 not offered', url: `https://${h}`, recommendation: 'Enable HTTP/2 (or HTTP/3) on the server/CDN for faster asset loading.' });
      if (h === pub.hostname) {
        c.note(`${h}: ${p.protocol}, issuer ${p.cert.issuer?.O || p.cert.issuer?.CN}, expires ${p.cert.valid_to} (${days}d), ALPN ${p.alpn || 'none'}`);
        for (const v of ['TLSv1', 'TLSv1.1']) {
          const old = await tlsProbe(h, { minVersion: v, maxVersion: v, ciphers: 'DEFAULT@SECLEVEL=0' });
          if (old.ok) c.finding({ severity: 'medium', rule: 'tls.legacy', title: `Server still accepts ${v}`, url: `https://${h}`, recommendation: 'Disable TLS 1.0/1.1; allow only TLS 1.2 and 1.3.' });
        }
      }
    }
  });

  await run.check({ id: 'infra.redirects', title: 'HTTP→HTTPS and www/non-www canonical redirects', category: CAT, tool: 'fetch' }, async (c) => {
    if (!needPublic(c)) return;
    const canonical = `${pub.protocol}//${pub.hostname}/`;
    const variants = [`http://${apex}/`, `http://www.${apex}/`, `https://${apex}/`, `https://www.${apex}/`];
    c.scope(variants);
    for (const v of variants) {
      const r = await followRedirects(v);
      const final = r.chain[r.chain.length - 1];
      if (final.error) { c.note(`${v}: ${final.error}`); continue; }
      const hops = r.chain.length - 1;
      if (v.startsWith('http://') && !r.finalUrl.startsWith('https://')) c.finding({ severity: 'high', rule: 'http.no-https-redirect', title: `${v} is served without redirecting to HTTPS`, url: v, recommendation: 'Redirect all HTTP traffic to HTTPS with a 301.' });
      else if (r.finalUrl !== canonical && final.status < 400) c.finding({ severity: 'medium', rule: 'http.canonical-host', title: `${v} ends at ${r.finalUrl} instead of ${canonical}`, url: v, recommendation: 'Pick one host (www or apex) and 301-redirect every variant to it — avoids duplicate content.' });
      if (hops > 2) c.finding({ severity: 'low', rule: 'http.redirect-chain', title: `${v} takes ${hops} redirects`, url: v, evidence: r.chain.map((x) => `${x.status} ${x.url}`).join('\n'), recommendation: 'Redirect straight to the final URL in one hop.' });
      if (r.chain.some((x) => x.status === 302 || x.status === 307) && v !== canonical) c.finding({ severity: 'low', rule: 'http.temp-redirect', title: `${v} uses a temporary (302/307) redirect`, url: v, recommendation: 'Use 301 for permanent host/protocol redirects.' });
    }
  });

  const target = publicUrl || cfg.site.url;
  await run.check({ id: 'infra.headers', title: 'Security headers and server information leakage', category: CAT, tool: 'fetch', requires: publicUrl ? {} : { url: true } }, async (c) => {
    const r = await httpFetch(target, { redirect: 'follow', timeoutMs: 20000 });
    if (!r.ok) return c.skip(`could not fetch ${target}: ${r.error}`);
    c.scope([...new Set([target, r.url])]);
    const h = r.headers;
    const https = r.url.startsWith('https://');
    const hsts = h['strict-transport-security'];
    if (https && !hsts) c.finding({ severity: 'medium', rule: 'hdr.hsts', title: 'Strict-Transport-Security header missing', url: r.url, recommendation: 'Strict-Transport-Security: max-age=31536000; includeSubDomains (after confirming all subdomains have HTTPS).' });
    else if (hsts && Number((hsts.match(/max-age=(\d+)/) || [])[1] || 0) < 15552000) c.finding({ severity: 'low', rule: 'hdr.hsts-short', title: `HSTS max-age is short (${hsts})`, url: r.url });
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(h['content-security-policy'] || '')) c.finding({ severity: 'medium', rule: 'hdr.clickjacking', title: 'No clickjacking protection (X-Frame-Options / CSP frame-ancestors)', url: r.url, recommendation: 'X-Frame-Options: SAMEORIGIN (or CSP frame-ancestors \'self\').' });
    if ((h['x-content-type-options'] || '').toLowerCase() !== 'nosniff') c.finding({ severity: 'low', rule: 'hdr.nosniff', title: 'X-Content-Type-Options: nosniff missing', url: r.url });
    if (!h['referrer-policy']) c.finding({ severity: 'low', rule: 'hdr.referrer', title: 'Referrer-Policy missing', url: r.url, recommendation: 'Referrer-Policy: strict-origin-when-cross-origin' });
    if (!h['content-security-policy']) c.finding({ severity: 'low', rule: 'hdr.csp', title: 'No Content-Security-Policy', url: r.url, recommendation: 'Start with a report-only CSP; at minimum "upgrade-insecure-requests; frame-ancestors \'self\'".' });
    if (!h['permissions-policy']) c.finding({ severity: 'info', rule: 'hdr.permissions', title: 'No Permissions-Policy header', url: r.url });
    if (/\d/.test(h.server || '')) c.finding({ severity: 'low', rule: 'hdr.server-version', title: `Server version disclosed: "${h.server}"`, url: r.url, recommendation: 'Hide versions (Apache: ServerTokens Prod; nginx: server_tokens off).' });
    if (h['x-powered-by']) c.finding({ severity: 'low', rule: 'hdr.powered-by', title: `X-Powered-By disclosed: "${h['x-powered-by']}"`, url: r.url, recommendation: 'php.ini: expose_php = Off.' });
    const gen = r.text.match(/<meta[^>]+name=["']generator["'][^>]+content=["']WordPress ([\d.]+)/i);
    if (gen) c.finding({ severity: 'low', rule: 'wp.version-disclosed', title: `WordPress version ${gen[1]} in meta generator`, url: r.url, recommendation: "remove_action( 'wp_head', 'wp_generator' );" });
    if (https) {
      const mixed = [...new Set([...r.text.matchAll(/(?:src|href)=["'](http:\/\/[^"']+)["']/gi)].map((m) => m[1]).filter((u) => !/^http:\/\/(www\.)?w3\.org|gmpg\.org/.test(u)))];
      if (mixed.length) c.finding({ severity: 'medium', rule: 'http.mixed-content', title: `${mixed.length} http:// resource(s) on an HTTPS page (mixed content)`, url: r.url, evidence: mixed.slice(0, 10).join('\n'), recommendation: 'Search-replace http:// → https:// in the database (wp search-replace) and theme.' });
    }
    c.stats.headers = h;
  });

  await run.check({ id: 'infra.exposure', title: 'Exposed files and WordPress information leaks', category: CAT, tool: 'fetch', requires: publicUrl ? {} : { url: true } }, async (c) => {
    const base = target.endsWith('/') ? target : target + '/';
    const probes = [
      ['wp-content/debug.log', 'high', (r) => r.status === 200 && /PHP (Fatal|Warning|Notice|Deprecated)|\[\d{2}-\w{3}-\d{4}/.test(r.text), 'Public debug.log (leaks paths, queries, sometimes credentials)', 'Delete it and set WP_DEBUG_LOG to a path outside the web root, or block *.log.'],
      ['.env', 'critical', (r) => r.status === 200 && /^[A-Z_]+=/m.test(r.text), 'Public .env file', 'Remove from the web root and rotate all secrets in it.'],
      ['.git/HEAD', 'high', (r) => r.status === 200 && /^ref:/m.test(r.text), 'Public .git folder (source code download)', 'Block access to /.git (or deploy without it).'],
      ['wp-config.php.bak', 'critical', (r) => r.status === 200 && /DB_PASSWORD/.test(r.text), 'Backup of wp-config.php is downloadable', 'Delete it and change the DB password and salts.'],
      ['wp-config.php~', 'critical', (r) => r.status === 200 && /DB_PASSWORD/.test(r.text), 'Editor backup of wp-config.php is downloadable', 'Delete it and change the DB password and salts.'],
      ['wp-config.old', 'critical', (r) => r.status === 200 && /DB_PASSWORD/.test(r.text), 'Old wp-config is downloadable', 'Delete it and change the DB password and salts.'],
      ['wp-content/uploads/', 'medium', (r) => r.status === 200 && /<title>Index of/i.test(r.text), 'Directory listing enabled on uploads', 'Disable indexes (Options -Indexes / autoindex off).'],
      ['wp-json/wp/v2/users', 'medium', (r) => r.status === 200 && /"slug"\s*:/.test(r.text), 'REST API exposes user list (usernames for brute force)', 'Restrict the users endpoint to logged-in users (security plugin or a rest_endpoints filter).'],
      ['xmlrpc.php', 'medium', (r) => r.status === 405 || /XML-RPC server accepts POST/i.test(r.text), 'xmlrpc.php enabled (brute-force amplification)', "Block it at the server or add_filter( 'xmlrpc_enabled', '__return_false' ) if you don't use Jetpack/apps."],
      ['readme.html', 'low', (r) => r.status === 200 && /WordPress/i.test(r.text), 'readme.html accessible (version fingerprinting)', 'Delete or block it.'],
    ];
    c.scope([...probes.map(([p]) => joinUrl(base, p)), joinUrl(base, '?author=1')]);
    for (const [p, severity, test, title, recommendation] of probes) {
      const url = joinUrl(base, p);
      const r = await httpFetch(url, { timeoutMs: 15000, maxBody: 64 * 1024 });
      if (r.ok && test(r)) c.finding({ severity: cfg.site.environment === 'local' && !publicUrl && severity !== 'critical' ? 'low' : severity, rule: 'exposure.' + p.replace(/\W+/g, '-'), title, url, recommendation });
    }
    const author = await httpFetch(joinUrl(base, '?author=1'), { timeoutMs: 15000, readBody: false });
    if (author.ok && /\/author\/[^/]+/.test(author.headers.location || '')) c.finding({ severity: 'low', rule: 'exposure.author-enum', title: 'Usernames enumerable via ?author=1 redirect', url: joinUrl(base, '?author=1'), evidence: author.headers.location });
  });

  await run.check({ id: 'infra.timing', title: 'Network timing (DNS, connect, TLS, TTFB)', category: CAT, tool: 'node:https', requires: publicUrl ? {} : { url: true } }, async (c) => {
    c.scope([target]);
    const samples = [];
    for (let i = 0; i < 5; i++) { const t = await timing(target); if (t.ok) samples.push(t); }
    if (!samples.length) return c.skip(`could not connect to ${target}`);
    const m = (k) => Math.round(median(samples.map((s) => s[k]).filter((x) => x != null)));
    const ttfb = m('ttfb');
    c.note(`median of ${samples.length}: dns ${m('dns')}ms, connect ${m('connect')}ms, tls ${m('tls') || '-'}ms, TTFB ${ttfb}ms, total ${m('total')}ms`);
    c.stats = { dns: m('dns'), connect: m('connect'), tls: m('tls'), ttfb, total: m('total') };
    const limit = cfg.performance.ttfbMs;
    if (ttfb > limit * 2) c.finding({ severity: 'high', rule: 'net.ttfb', title: `Slow server response: TTFB ${ttfb} ms (target < ${limit} ms)`, url: target, recommendation: 'Add full-page caching (server/CDN or a cache plugin), an object cache, and check slow plugins/queries.' });
    else if (ttfb > limit) c.finding({ severity: 'medium', rule: 'net.ttfb', title: `TTFB ${ttfb} ms above target ${limit} ms`, url: target, recommendation: 'Enable page caching; check hosting resources.' });
  });
}
