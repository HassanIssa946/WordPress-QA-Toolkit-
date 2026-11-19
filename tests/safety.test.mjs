// The --approve safety gate for intrusive tests (load, active scans, write probes).
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { makeRun } from './helpers.mjs';

/** Run one check that asks for approval; returns { allowed, record, run }. */
async function gate({ config = {}, flags = {}, target }) {
  const run = makeRun({ config, flags });
  let allowed = null;
  const record = await run.check({ id: 'dast.probe', title: 'probe', category: 'dast' }, async (c) => {
    allowed = c.requireApproval('active scan', target);
  });
  return { allowed, record, run };
}

describe('--approve safety gate', () => {
  test('local site without --approve: skipped and listed as waiting for approval', async () => {
    const { allowed, record, run } = await gate({ target: 'http://fixture.local/' });
    assert.equal(allowed, false);
    assert.equal(record.status, 'skipped');
    assert.match(record.reason, /needs explicit approval/);
    assert.deepEqual(run.needsApproval, [{ check: 'dast.probe', kind: 'active scan', target: 'http://fixture.local/' }]);
  });

  test('local site with --approve: allowed', async () => {
    const { allowed, record } = await gate({ flags: { approve: true }, target: 'http://fixture.local/' });
    assert.equal(allowed, true);
    assert.equal(record.status, 'passed');
  });

  test('host not in safety.allowedHosts is refused even with --approve', async () => {
    const { allowed, record, run } = await gate({ flags: { approve: true }, target: 'https://staging.example.com/' });
    assert.equal(allowed, false);
    assert.match(record.reason, /not in safety\.allowedHosts/);
    assert.equal(run.needsApproval.length, 0);
  });

  test('public (production) domain is refused even when allowed and approved', async () => {
    const { allowed, record } = await gate({
      config: { publicSite: { url: 'https://www.example.com' }, safety: { allowedHosts: ['www.example.com'] } },
      flags: { approve: true }, target: 'https://www.example.com/',
    });
    assert.equal(allowed, false);
    assert.match(record.reason, /is production/);
  });

  test('production site.url is refused unless allowIntrusiveOnProduction is true', async () => {
    const config = { site: { url: 'https://shop.example.com', environment: 'production' }, safety: { allowedHosts: ['shop.example.com'] } };
    const refused = await gate({ config, flags: { approve: true }, target: 'https://shop.example.com/' });
    assert.equal(refused.allowed, false);
    const ok = await gate({ config: { ...config, safety: { ...config.safety, allowIntrusiveOnProduction: true } }, flags: { approve: true }, target: 'https://shop.example.com/' });
    assert.equal(ok.allowed, true);
  });

  test('production with allowIntrusiveOnProduction but without --approve is still refused', async () => {
    const { allowed, record } = await gate({
      config: { site: { url: 'https://shop.example.com', environment: 'production' }, safety: { allowedHosts: ['shop.example.com'], allowIntrusiveOnProduction: true } },
      target: 'https://shop.example.com/',
    });
    assert.equal(allowed, false);
    assert.match(record.reason, /needs explicit approval/);
  });

  test('invalid target URL is refused', async () => {
    const { allowed, record } = await gate({ flags: { approve: true }, target: 'not a url' });
    assert.equal(allowed, false);
    assert.equal(record.status, 'skipped');
  });
});
