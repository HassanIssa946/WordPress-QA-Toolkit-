// Stable finding IDs: shifting lines must not create fake new/resolved findings.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { codeAnchor, normalizeUrl, findingId } from '../lib/fingerprint.mjs';
import { coverageSummary, diffRuns } from '../lib/report.mjs';
import { makeRun, tempDir, chk, fnd } from './helpers.mjs';

describe('finding IDs', () => {
  test('same code, lines inserted above → same ID; the line number still updates', async () => {
    const run = makeRun({ config: { scan: { plugins: ['x'] } } });
    const file = path.join(tempDir(), 'a.php');
    const body = "<?php\n$wpdb->query( \"DELETE FROM t WHERE id = $id\" );\n";
    fs.writeFileSync(file, body);
    const find = (line) => run.check({ id: 'security.wp-patterns', title: 't', category: 'security' }, async (c) => c.finding({ severity: 'high', rule: 'wp.sqli', title: 'SQL', file, line }));
    await find(2);
    fs.writeFileSync(file, '<?php\n// one\n// two\n// three\n' + body.replace('<?php\n', ''));
    run._lineCache = new Map();
    await find(5);
    const [a, b] = run.findings;
    assert.equal(a.id, b.id);
    assert.deepEqual([a.line, b.line], [2, 5]);
  });

  test('two identical lines in one file stay two findings', () => {
    const file = path.join(tempDir(), 'b.php');
    fs.writeFileSync(file, 'echo $x;\necho $y;\necho $x;\n');
    assert.equal(codeAnchor(file, 1), 'echo $x;#0');
    assert.equal(codeAnchor(file, 3), 'echo $x;#1');
    assert.notEqual(findingId({ check: 'c', rule: 'r', file: 'b.php', absFile: file, line: 1 }), findingId({ check: 'c', rule: 'r', file: 'b.php', absFile: file, line: 3 }));
  });

  test('whitespace-only edits keep the ID; changing the code changes it', () => {
    const file = path.join(tempDir(), 'c.php');
    const id = () => findingId({ check: 'c', rule: 'r', file: 'c.php', absFile: file, line: 1 }, new Map());
    fs.writeFileSync(file, 'echo   $_GET["q"];\n');
    const first = id();
    fs.writeFileSync(file, '\techo $_GET["q"];   \n');
    assert.equal(id(), first);
    fs.writeFileSync(file, 'echo esc_html( $_GET["q"] );\n');
    assert.notEqual(id(), first);
  });

  test('unreadable file falls back to the line number', () => {
    assert.equal(codeAnchor(path.join(tempDir(), 'missing.php'), 3), null);
    assert.equal(findingId({ check: 'c', rule: 'r', file: 'm.php', absFile: '/nope/m.php', line: 3 }), findingId({ check: 'c', rule: 'r', file: 'm.php', absFile: '/nope/m.php', line: 3 }));
  });

  test('URL IDs ignore cache-busting parameters, fragments and parameter order', () => {
    assert.equal(normalizeUrl('https://Example.com/a.js?ver=6.8&b=2&a=1#x'), 'https://example.com/a.js?a=1&b=2');
    const id = (url) => findingId({ check: 'frontend.pages', rule: 'net.404', url });
    assert.equal(id('https://e.com/x.css?ver=1'), id('https://e.com/x.css?ver=2'));
    assert.notEqual(id('https://e.com/x.css'), id('https://e.com/y.css'));
  });
});

describe('coverage summary', () => {
  test('totals by status, planned excluded, files and URLs from executed scopes', () => {
    const checks = [
      chk('a.x', 'passed', { scope: ['p/a.php', 'p/b.php'] }),
      chk('a.y', 'failed', { scope: ['p/b.php', 'https://e.com/'] }),
      chk('b.x', 'skipped', { scope: ['p/c.php'] }),
      chk('b.y', 'error'),
      chk('c.x', 'not_applicable'),
      chk('d.*', 'skipped', { planned: true }),
      chk('e.x', 'passed'),
    ];
    assert.deepEqual(coverageSummary(checks), { total: 6, applicable: 5, executed: 3, passed: 2, failed: 1, skipped: 1, errored: 1, notApplicable: 1, planned: 1, coveragePct: 60, filesInspected: 2, urlsInspected: 1 });
  });
});

describe('comparison across schema versions', () => {
  test('previous report without schemaVersion → baseline reset, nothing marked new or resolved', () => {
    const prev = { runId: 'p', mode: 'quick', findings: [fnd('old', 'code.phpcs')], checks: [] };
    const cur = { schemaVersion: 2, findings: [fnd('new', 'code.phpcs')], checks: [chk('code.phpcs', 'failed')] };
    const d = diffRuns(prev, cur);
    assert.equal(d.baselineReset, true);
    assert.deepEqual([d.new, d.resolved, d.stillOpen, d.notRetested], [[], [], [], []]);
  });
});
