// The safety gate for intrusive tests (lib/safety.mjs): every refusal reason, alone, plus the engine wiring.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { evaluateIntrusive, hostVariants, effectiveLimits, HARD_LIMITS } from '../lib/safety.mjs';
import { configWarnings } from '../lib/config.mjs';
import { makeRun } from './helpers.mjs';

// Fake DNS: sandbox and staging are local/private, production is public, "twin" shares production's address.
const DNS = {
  'wpqa-sandbox.local': ['127.0.0.1', '::1'],
  'staging.example.com': ['10.0.0.5'],
  'example.com': ['203.0.113.10'],
  'www.example.com': ['203.0.113.10'],
  'twin.example.net': ['203.0.113.10'],
};
const resolve = async (h) => DNS[h] || [];

/** A config that allows the sandbox; each test breaks exactly one rule. */
const goodCfg = (over = {}) => ({
  site: { url: 'http://wpqa-sandbox.local', environment: 'local' },
  publicSite: { url: 'https://www.example.com' },
  safety: { allowedHosts: ['wpqa-sandbox.local'], limits: { maxVus: 50, maxDurationSec: 600 }, allowStress: false },
  dast: { active: false },
  ...over,
});
const ok = { approve: true };
const evalGate = (o) => evaluateIntrusive({ kind: 'load', targetUrl: 'http://wpqa-sandbox.local/', cfg: goodCfg(), flags: ok, resolve, ...o });

describe('safety gate: allowed case', () => {
  test('approved, allowlisted, local, resolvable, not production → allowed', async () => {
    const d = await evalGate({});
    assert.deepEqual(d.reasons, []);
    assert.equal(d.allowed, true);
  });
  test('staging host that is allowlisted is allowed', async () => {
    const cfg = goodCfg({ site: { url: 'https://staging.example.com', environment: 'staging' }, safety: { allowedHosts: ['staging.example.com'] } });
    assert.equal((await evalGate({ cfg, targetUrl: 'https://staging.example.com/' })).allowed, true);
  });
});

describe('safety gate: each refusal reason on its own', () => {
  const refused = async (o, pattern) => {
    const d = await evalGate(o);
    assert.equal(d.allowed, false, `expected refusal for ${pattern}`);
    assert.ok(d.reasons.some((r) => pattern.test(r)), `reasons ${JSON.stringify(d.reasons)} should match ${pattern}`);
    return d;
  };
  test('no --approve', async () => {
    const d = await refused({ flags: {} }, /needs explicit approval/);
    assert.equal(d.reasons.length, 1);
  });
  test('--approve with a value ("false", "yes", "1") is not approval', async () => {
    for (const v of ['false', 'yes', '1', 1, 'true']) await refused({ flags: { approve: v } }, /needs explicit approval/);
  });
  test('host not in safety.allowedHosts', () => refused({ cfg: goodCfg({ safety: { allowedHosts: ['other.local'] } }) }, /not in safety\.allowedHosts/));
  test('the local site host is NOT allowed automatically', () => refused({ cfg: goodCfg({ safety: { allowedHosts: [] } }) }, /not in safety\.allowedHosts/));
  test('site.environment = production', () => refused({ cfg: goodCfg({ site: { url: 'http://wpqa-sandbox.local', environment: 'production' } }) }, /environment is "production"/));
  test('production public host, even when allowlisted', async () => {
    const cfg = goodCfg({ safety: { allowedHosts: ['www.example.com'] } });
    await refused({ cfg, targetUrl: 'https://www.example.com/' }, /production site/);
  });
  test('www/apex variant of the production host', async () => {
    const cfg = goodCfg({ safety: { allowedHosts: ['example.com'] } });
    await refused({ cfg, targetUrl: 'https://example.com/' }, /production site/);
  });
  test('a different name resolving to production\'s address', async () => {
    const cfg = goodCfg({ site: { url: 'https://twin.example.net', environment: 'staging' }, safety: { allowedHosts: ['twin.example.net'] } });
    await refused({ cfg, targetUrl: 'https://twin.example.net/' }, /resolves to production's address \(203\.0\.113\.10\)/);
  });
  test('WordPress itself says WP_ENVIRONMENT_TYPE = production', () => refused({ wpEnvironment: 'production' }, /WP_ENVIRONMENT_TYPE = production/));
  test('target does not resolve', async () => {
    const cfg = goodCfg({ safety: { allowedHosts: ['ghost.local'] } });
    await refused({ cfg, targetUrl: 'http://ghost.local/' }, /does not resolve/);
  });
  test('invalid or non-http target', async () => {
    await refused({ targetUrl: 'not a url' }, /invalid target URL/);
    await refused({ targetUrl: 'file:///etc/passwd' }, /only http\(s\)/);
  });
  test('unknown intrusive kind', () => refused({ kind: 'rm-rf' }, /unknown intrusive kind/));
  test('missing config sections deny (no safety, no site)', async () => {
    const d = await evaluateIntrusive({ kind: 'load', targetUrl: 'http://wpqa-sandbox.local/', cfg: {}, flags: ok, resolve });
    assert.equal(d.allowed, false);
    assert.ok(d.reasons.some((r) => /not in safety\.allowedHosts/.test(r)));
    assert.ok(d.reasons.some((r) => /environment is "missing"/.test(r)));
  });
  test('load above the VU or duration limit', async () => {
    await refused({ request: { vus: 51, durationSec: 60 } }, /exceeds the limit of 50/);
    await refused({ request: { vus: 10, durationSec: 601 } }, /exceeds the limit of 600s/);
    await refused({ request: { vus: 10, durationSec: 60 }, cfg: goodCfg({ safety: { allowedHosts: ['wpqa-sandbox.local'], limits: { maxVus: 5 } } }) }, /exceeds the limit of 5/);
  });
  test('stress profile without safety.allowStress', () => refused({ request: { vus: 10, durationSec: 60, stress: true } }, /allowStress/));
  test('active ZAP without dast.active', () => refused({ kind: 'zap-active' }, /dast\.active/));
});

describe('safety helpers', () => {
  test('www/apex variants', () => {
    assert.deepEqual(hostVariants('www.Example.com'), ['www.example.com', 'example.com']);
    assert.deepEqual(hostVariants('example.com'), ['example.com', 'www.example.com']);
  });
  test('config can lower but never raise the hard limits', () => {
    assert.deepEqual(effectiveLimits({ safety: { limits: { maxVus: 500, maxDurationSec: 99999 } } }), HARD_LIMITS);
    assert.deepEqual(effectiveLimits({ safety: { limits: { maxVus: 5, maxDurationSec: 30 } } }), { maxVus: 5, maxDurationSec: 30 });
  });
  test('allowIntrusiveOnProduction: true only produces a warning, it unlocks nothing', async () => {
    assert.match(configWarnings({ safety: { allowIntrusiveOnProduction: true } })[0], /ignored/);
    const cfg = goodCfg({ site: { url: 'https://www.example.com', environment: 'production' }, safety: { allowedHosts: ['www.example.com'], allowIntrusiveOnProduction: true } });
    const d = await evaluateIntrusive({ kind: 'load', targetUrl: 'https://www.example.com/', cfg, flags: ok, resolve });
    assert.equal(d.allowed, false);
  });
});

describe('engine wiring (CheckContext.requireApproval)', () => {
  async function gate({ config = {}, flags = {}, target = 'http://fixture.local/' }) {
    const run = makeRun({ config, flags });
    run.resolve = async (h) => (h === 'fixture.local' ? ['127.0.0.1'] : []);
    let allowed = null;
    const record = await run.check({ id: 'dast.probe', title: 'probe', category: 'dast' }, async (c) => { allowed = await c.requireApproval('zap', target); });
    return { allowed, record, run };
  }
  const listed = { safety: { allowedHosts: ['fixture.local'] } };

  test('only approval missing: skipped and listed as waiting for approval', async () => {
    const { allowed, record, run } = await gate({ config: listed });
    assert.equal(allowed, false);
    assert.equal(record.status, 'skipped');
    assert.match(record.reason, /needs explicit approval/);
    assert.deepEqual(run.needsApproval, [{ check: 'dast.probe', kind: 'zap', target: 'http://fixture.local/' }]);
  });
  test('all rules met: allowed, and the decision is recorded', async () => {
    const { allowed, record, run } = await gate({ config: listed, flags: { approve: true } });
    assert.equal(allowed, true);
    assert.equal(record.status, 'passed');
    assert.equal(run.approvals[0].allowed, true);
  });
  test('local site not listed: blocked (no automatic allow), not "waiting for approval"', async () => {
    const { allowed, record, run } = await gate({ flags: { approve: true } });
    assert.equal(allowed, false);
    assert.match(record.reason, /blocked: .*not in safety\.allowedHosts/);
    assert.equal(run.needsApproval.length, 0);
    assert.equal(run.approvals[0].allowed, false);
  });
});
