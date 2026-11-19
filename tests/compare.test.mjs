// Run comparison: same-mode previous run; "resolved" only when the same check re-scanned the same file/URL.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { diffRuns, findPreviousReport, inScope, findingLocations } from '../lib/report.mjs';
import { chk, fnd, tempDir } from './helpers.mjs';

const report = (runId, mode, checks, findings) => ({ runId, mode, checks, findings });

describe('diffRuns', () => {
  const prev = report('20260101-100000-quick', 'quick', [], [
    fnd('sqli', 'security.wp-patterns', 'high', { file: 'wp-content/plugins/p/a.php', line: 5 }),
    fnd('xss', 'security.wp-patterns', 'high', { file: 'wp-content/plugins/p/b.php', line: 9 }),
    fnd('hdr', 'infra.headers', 'medium', { url: 'https://example.com/' }),
    fnd('spf', 'infra.email-dns', 'medium'),
    fnd('agg', 'code.phpcs', 'low', { locations: ['wp-content/plugins/p/a.php:3', 'wp-content/plugins/p/c.php:7'] }),
    fnd('still', 'security.wp-patterns', 'high', { file: 'wp-content/plugins/p/a.php', line: 20 }),
  ]);

  test('resolved only when the same check scanned the file again', () => {
    const cur = report('20260102-100000-quick', 'quick', [chk('security.wp-patterns', 'passed', { scope: ['wp-content/plugins/p/a.php'] })], [
      fnd('still', 'security.wp-patterns', 'high', { file: 'wp-content/plugins/p/a.php', line: 20 }),
    ]);
    const d = diffRuns(prev, cur);
    assert.deepEqual(d.resolved.map((f) => f.id), ['sqli']); // a.php was re-scanned
    const nr = Object.fromEntries(d.notRetested.map((f) => [f.id, f.why]));
    assert.match(nr.xss, /not scanned again: wp-content\/plugins\/p\/b\.php/); // --changed left b.php out
    assert.match(nr.hdr, /check infra\.headers did not run/);
    assert.match(nr.spf, /check infra\.email-dns did not run/);
    assert.deepEqual(d.stillOpen, ['still']);
  });

  test('a skipped or errored check never resolves anything', () => {
    for (const status of ['skipped', 'error', 'not_applicable']) {
      const cur = report('x', 'quick', [chk('security.wp-patterns', status)], []);
      const d = diffRuns(prev, cur);
      assert.equal(d.resolved.filter((f) => f.check === 'security.wp-patterns').length, 0, status);
    }
  });

  test('whole-subject checks (scope *) resolve site-wide and URL findings', () => {
    const cur = report('x', 'quick', [chk('infra.headers', 'passed'), chk('infra.email-dns', 'failed')], []);
    const d = diffRuns(prev, cur);
    assert.ok(d.resolved.some((f) => f.id === 'hdr'));
    assert.ok(d.resolved.some((f) => f.id === 'spf'));
  });

  test('aggregated findings need every location re-scanned', () => {
    const partial = diffRuns(prev, report('x', 'quick', [chk('code.phpcs', 'passed', { scope: ['wp-content/plugins/p/a.php'] })], []));
    assert.ok(partial.notRetested.some((f) => f.id === 'agg'));
    const full = diffRuns(prev, report('x', 'quick', [chk('code.phpcs', 'passed', { scope: ['wp-content/plugins/p'] })], []));
    assert.ok(full.resolved.some((f) => f.id === 'agg'));
  });

  test('new findings are listed', () => {
    const d = diffRuns(prev, report('x', 'quick', [], [fnd('fresh', 'code.phpcs', 'low')]));
    assert.deepEqual(d.new, ['fresh']);
  });

  test('no previous run → no diff', () => {
    assert.equal(diffRuns(null, report('x', 'quick', [], [])), null);
  });
});

describe('scope helpers', () => {
  test('inScope: exact file, parent directory, wildcard', () => {
    assert.ok(inScope(['*'], 'anything'));
    assert.ok(inScope(['wp-content/themes/t'], 'wp-content/themes/t/functions.php'));
    assert.ok(inScope(['wp-content/themes/t/a.php'], 'wp-content/themes/t/a.php'));
    assert.ok(!inScope(['wp-content/themes/t'], 'wp-content/themes/t2/a.php'));
    assert.ok(!inScope([], 'x'));
  });
  test('findingLocations strips line numbers from aggregated locations but keeps URLs', () => {
    assert.deepEqual(findingLocations({ locations: ['a/b.php:12', 'https://x.test:8443/p'] }), ['a/b.php', 'https://x.test:8443/p']);
  });
});

describe('findPreviousReport', () => {
  test('returns the latest run of the same mode, ignoring other modes and broken reports', () => {
    const root = tempDir();
    const write = (id, mode, broken = false) => {
      fs.mkdirSync(path.join(root, 'reports', id), { recursive: true });
      fs.writeFileSync(path.join(root, 'reports', id, 'report.json'), broken ? '{nope' : JSON.stringify({ runId: id, mode, checks: [], findings: [] }));
    };
    write('20260101-090000-quick', 'quick');
    write('20260101-100000-security', 'security');
    write('20260101-110000-quick', 'quick');
    write('20260101-120000-security', 'security');
    write('20260101-130000-quick', 'quick', true);
    assert.equal(findPreviousReport(root, '20260101-140000-quick', 'quick').runId, '20260101-110000-quick');
    assert.equal(findPreviousReport(root, '20260101-140000-security', 'security').runId, '20260101-120000-security');
    assert.equal(findPreviousReport(root, 'x', 'infrastructure'), null);
  });
});
