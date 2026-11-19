// Engine: scanner errors become "error" with raw output saved; scope recording; cross-check dedupe.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { runStamp } from '../lib/engine.mjs';
import { writeReport } from '../lib/report.mjs';
import { makeRun } from './helpers.mjs';

describe('scanner failures', () => {
  test('toolError: status "error", reason mentions the tool, raw stdout/stderr saved as artifact', async () => {
    const run = makeRun();
    const record = await run.check({ id: 'code.phpcs', title: 'PHPCS', category: 'code' }, async (c) => {
      c.finding({ severity: 'low', title: 'found before the crash' });
      c.toolError('PHPCS', { command: 'php phpcs …', code: 255, stdout: 'PHP Fatal error: Allowed memory size exhausted', stderr: 'boom' }, 'produced no JSON report');
      c.finding({ severity: 'high', title: 'never reached' });
    });
    assert.equal(record.status, 'error');
    assert.match(record.reason, /^PHPCS produced no JSON report \(exit 255\)/);
    assert.equal(record.artifacts.length, 1);
    const raw = fs.readFileSync(path.join(run.cfg._root, record.artifacts[0].path), 'utf8');
    assert.match(raw, /exit code: 255/);
    assert.match(raw, /--- stdout ---\nPHP Fatal error: Allowed memory size exhausted/);
    assert.match(raw, /--- stderr ---\nboom/);
    assert.equal(run.findings.length, 1);
  });

  test('an unexpected exception in a check is an error, never a pass', async () => {
    const run = makeRun();
    const record = await run.check({ id: 'x.crash', title: 'x', category: 'code' }, async () => { JSON.parse('{'); });
    assert.equal(record.status, 'error');
    assert.match(record.reason, /SyntaxError/);
  });

  test('an errored core check makes the written report INCOMPLETE (exit 3)', async () => {
    const run = makeRun({ mode: 'code' });
    for (const id of ['code.php-lint', 'code.phpstan', 'code.eslint', 'code.stylelint']) await run.check({ id, title: id, category: 'code' }, async () => {});
    await run.check({ id: 'code.phpcs', title: 'PHPCS', category: 'code' }, async (c) => c.toolError('PHPCS', { code: 3, stdout: 'garbage', stderr: '' }));
    run.finalizeFindings();
    const { report } = writeReport(run);
    assert.equal(report.verdict.status, 'INCOMPLETE');
    assert.match(report.verdict.incomplete.join(), /code\.phpcs errored/);
  });
});

describe('scope and findings', () => {
  test('scope is recorded relative to the project root; default is the whole subject', async () => {
    const run = makeRun();
    const a = await run.check({ id: 'a.files', title: 'a', category: 'code' }, async (c) => c.scope([path.join(run.cfg._root, 'x', 'y.php'), 'https://example.com/']));
    const b = await run.check({ id: 'b.site', title: 'b', category: 'code' }, async () => {});
    assert.deepEqual(a.scope, ['https://example.com/', 'x/y.php']);
    assert.deepEqual(b.scope, ['*']);
  });

  test('the same update reported by wordpress.org and WP-CLI is deduplicated', async () => {
    const run = makeRun();
    const dir = path.join(run.cfg._wpRoot, 'wp-content', 'plugins', 'polylang');
    await run.check({ id: 'wordpress.wporg-status', title: 'a', category: 'dependencies' }, async (c) => c.finding({ severity: 'medium', rule: 'wporg.outdated', title: 'polylang outdated', file: dir, dedupeKey: 'update:plugin:polylang' }));
    await run.check({ id: 'wpcli.plugins', title: 'b', category: 'wordpress' }, async (c) => c.finding({ severity: 'medium', rule: 'plugin.update', title: 'polylang update', file: dir, dedupeKey: 'update:plugin:polylang' }));
    run.finalizeFindings();
    assert.equal(run.findings.length, 1);
    assert.equal(run.findings[0].alsoReportedBy.length, 1);
  });

  test('distinct checksum files are distinct findings (they used to collapse into one)', async () => {
    const run = makeRun();
    await run.check({ id: 'wpcli.plugins', title: 'b', category: 'wordpress' }, async (c) => {
      for (const f of ['.htaccess', 'index.php']) c.finding({ severity: 'low', rule: 'plugin.checksums', title: `x ${f}`, file: path.join(run.cfg._wpRoot, 'wp-content', 'plugins', 'aio', 'storage', f) });
    });
    run.finalizeFindings();
    assert.equal(run.findings.length, 2);
  });

  test('run IDs use local time', () => {
    assert.equal(runStamp(new Date(2026, 10, 18, 14, 8, 57)), '20261118-140857');
  });
});

test('siteReachable: a 5xx home page is not a usable target', async () => {
  const { makeRun } = await import('./helpers.mjs');
  const util = await import('../lib/util.mjs');
  const run = makeRun({ config: { site: { url: 'http://localhost:9' } } });
  const orig = globalThis.fetch;
  globalThis.fetch = async () => new Response('Bad Gateway', { status: 502 });
  try {
    const r = await run.siteReachable();
    assert.equal(r.ok, false);
    assert.match(r.error, /HTTP 502/);
  } finally { globalThis.fetch = orig; }
  assert.ok(util.httpFetch);
});
