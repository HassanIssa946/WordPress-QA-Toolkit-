// DNS / TLS failures on the auditing machine must make checks "skipped" (not tested), never findings like
// "No SPF record" or "HTTPS not available". Real problems on a working network must still be reported.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import infrastructure from '../modules/infrastructure.mjs';
import { makeRun } from './helpers.mjs';

const APEX = 'shop.example';
const err = (code) => Object.assign(new Error(`queryX ${code}`), { code });

/** Fake node:dns/promises. `zone` maps "type name" → records, or an error code string to throw. */
function fakeDns(zone) {
  const q = (type) => async (name) => {
    const v = zone[`${type} ${name}`];
    if (typeof v === 'string') throw err(v);
    if (v === undefined) throw err('ENODATA');
    return v;
  };
  return { resolve4: q('A'), resolve6: q('AAAA'), resolveCname: q('CNAME'), resolveMx: q('MX'), resolveTxt: q('TXT'), resolveNs: q('NS'), resolveCaa: q('CAA') };
}
const OUTAGE = new Proxy({}, { get: () => async () => { throw err('ECONNREFUSED'); } });

const future = new Date(Date.now() + 90 * 864e5).toUTCString();
const tlsOk = { ok: true, authorized: true, protocol: 'TLSv1.3', alpn: 'h2', cert: { valid_to: future, issuer: { O: 'Fixture CA' } } };
const fakeTls = (byHost) => async (host, opts = {}) => (opts.minVersion ? { ok: false, error: 'EPROTO' } : byHost[host] ?? tlsOk);

async function infraRun({ dns, tls, only }) {
  const run = makeRun({ config: { site: { url: 'http://fixture.local', environment: 'local' }, publicSite: { url: `https://${APEX}` } }, mode: 'infrastructure', flags: { only } });
  run.dns = dns;
  run.tlsProbe = tls || fakeTls({});
  await infrastructure(run);
  run.finalizeFindings();
  return run;
}
const check = (run, id) => run.checks.find((c) => c.id === id);
const rules = (run) => run.findings.map((f) => f.rule);

describe('email DNS (SPF / DMARC)', () => {
  const EMAIL = ['infra.email-dns'];
  test('DNS outage (resolver refuses) → skipped, no SPF/DMARC findings', async () => {
    const run = await infraRun({ dns: OUTAGE, only: EMAIL });
    assert.equal(check(run, 'infra.email-dns').status, 'skipped');
    assert.match(check(run, 'infra.email-dns').reason, /DNS lookups failing/);
    assert.deepEqual(rules(run), []);
  });
  test('domain does not resolve from this machine (ENOTFOUND, as in the Al-Hadbaa run) → skipped', async () => {
    const run = await infraRun({ dns: fakeDns({ [`A ${APEX}`]: 'ENOTFOUND', [`AAAA ${APEX}`]: 'ENOTFOUND', [`TXT ${APEX}`]: 'ENOTFOUND', [`TXT _dmarc.${APEX}`]: 'ENOTFOUND' }), only: EMAIL });
    assert.equal(check(run, 'infra.email-dns').status, 'skipped');
    assert.deepEqual(rules(run), []);
  });
  test('lookups fail part-way (TXT times out) → skipped', async () => {
    const run = await infraRun({ dns: fakeDns({ [`A ${APEX}`]: ['192.0.2.1'], [`MX ${APEX}`]: [{ exchange: 'mx', priority: 1 }], [`TXT ${APEX}`]: 'ETIMEOUT' }), only: EMAIL });
    assert.equal(check(run, 'infra.email-dns').status, 'skipped');
    assert.match(check(run, 'infra.email-dns').reason, /part-way/);
    assert.deepEqual(rules(run), []);
  });
  test('must detect: DNS works and the domain really has no SPF and no DMARC', async () => {
    const run = await infraRun({ dns: fakeDns({ [`A ${APEX}`]: ['192.0.2.1'], [`MX ${APEX}`]: [{ exchange: 'mx', priority: 1 }], [`TXT ${APEX}`]: [['google-site-verification=x']], [`TXT _dmarc.${APEX}`]: 'ENOTFOUND' }), only: EMAIL });
    assert.equal(check(run, 'infra.email-dns').status, 'failed');
    assert.deepEqual(rules(run).sort(), ['email.dmarc', 'email.spf']);
  });
  test('clean: SPF + DMARC p=reject → zero findings', async () => {
    const run = await infraRun({ dns: fakeDns({ [`A ${APEX}`]: ['192.0.2.1'], [`MX ${APEX}`]: [{ exchange: 'mx', priority: 1 }], [`TXT ${APEX}`]: [['v=spf1 include:_spf.mail.example -all']], [`TXT _dmarc.${APEX}`]: [['v=DMARC1; p=reject']] }), only: EMAIL });
    assert.equal(check(run, 'infra.email-dns').status, 'passed');
    assert.deepEqual(rules(run), []);
  });
});

describe('TLS', () => {
  const TLS = ['infra.tls'];
  const dns = fakeDns({});
  test('main host not resolvable (EAI_AGAIN, as in the Al-Hadbaa run) → skipped, not "HTTPS not available"', async () => {
    const run = await infraRun({ dns, tls: fakeTls({ [APEX]: { ok: false, error: 'EAI_AGAIN' } }), only: TLS });
    assert.equal(check(run, 'infra.tls').status, 'skipped');
    assert.match(check(run, 'infra.tls').reason, /could not resolve shop\.example .*EAI_AGAIN.*TLS not tested/);
    assert.deepEqual(rules(run), []);
  });
  test('www not resolvable → a note, not a TLS finding (missing www records belong to infra.dns)', async () => {
    const run = await infraRun({ dns, tls: fakeTls({ [`www.${APEX}`]: { ok: false, error: 'ENOTFOUND' } }), only: TLS });
    assert.equal(check(run, 'infra.tls').status, 'passed');
    assert.match(check(run, 'infra.tls').notes.join(' '), /www\.shop\.example: not resolvable/);
    assert.deepEqual(rules(run), []);
  });
  test('must detect: name resolves but port 443 refuses → critical tls.connect', async () => {
    const run = await infraRun({ dns, tls: fakeTls({ [APEX]: { ok: false, error: 'ECONNREFUSED' } }), only: TLS });
    const f = run.findings.find((x) => x.rule === 'tls.connect');
    assert.equal(f.severity, 'critical');
    assert.match(f.title, /HTTPS not available on shop\.example \(ECONNREFUSED\)/);
  });
  test('clean: valid certificate, TLS 1.3, h2, no legacy protocols → zero findings', async () => {
    const run = await infraRun({ dns, only: TLS });
    assert.equal(check(run, 'infra.tls').status, 'passed');
    assert.deepEqual(rules(run), []);
  });
});

describe('DNS records check during an outage', () => {
  test('resolver failing → skipped (unchanged behaviour)', async () => {
    const run = await infraRun({ dns: OUTAGE, only: ['infra.dns'] });
    assert.equal(check(run, 'infra.dns').status, 'skipped');
    assert.deepEqual(rules(run), []);
  });
});
