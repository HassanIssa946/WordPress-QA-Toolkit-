// Static security scanner: vulnerable fixtures must be detected, safe fixtures must produce zero findings.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import security, { scanPhp } from '../modules/security.mjs';
import { walkFiles } from '../lib/util.mjs';
import { fixturePlugin, makeRun } from './helpers.mjs';

function scanDir(dir, type = 'plugin') {
  const files = walkFiles(dir, { exts: ['.php'] });
  const allPhp = files.map((file) => ({ file, text: fs.readFileSync(file, 'utf8') }));
  const notes = [];
  const findings = [];
  for (const { file, text } of allPhp) findings.push(...scanPhp(file, text, { allPhp, type, notes }));
  return { findings, notes };
}
const scanText = (text, extra = {}) => scanPhp('inline.php', text, { allPhp: [{ file: 'inline.php', text }], notes: [], ...extra });
const describeFindings = (list) => list.map((f) => `${f.rule} ${path.basename(f.file || '')}:${f.line}`);

describe('vulnerable fixture: every pattern is detected', () => {
  const { findings } = scanDir(fixturePlugin('vuln-plugin'));
  const rules = new Set(findings.map((f) => f.rule));
  const expected = [
    'wp.xss.echo-request', 'wp.sqli.unprepared', 'wp.rest.no-permission-callback', 'wp.rest.public-write',
    'wp.csrf.ajax-no-nonce', 'wp.authz.ajax-no-capability', 'wp.rce.eval', 'wp.malware.obfuscated',
    'wp.objinj.unserialize', 'wp.lfi.include', 'wp.rce.shell', 'wp.extract-request', 'wp.open-redirect',
    'wp.ssrf-file', 'wp.upload.raw', 'wp.csrf.form-no-nonce', 'wp.direct-access',
  ];
  for (const rule of expected) {
    test(rule, () => assert.ok(rules.has(rule), `${rule} not detected; got: ${[...rules].join(', ')}`));
  }

  test('request data in SQL is critical even when {$wpdb->posts} is in the same query', () => {
    const f = findings.find((x) => x.rule === 'wp.sqli.unprepared' && /\$_GET/.test(x.evidence));
    assert.equal(f?.severity, 'critical');
  });

  test('a variable concatenated into SQL is high', () => {
    const f = findings.find((x) => x.rule === 'wp.sqli.unprepared' && /ID = \$id/.test(x.evidence));
    assert.equal(f?.severity, 'high');
  });

  test('REST write route without permission_callback is critical', () => {
    assert.equal(findings.find((x) => x.rule === 'wp.rest.no-permission-callback')?.severity, 'critical');
  });

  test('always-true REST write routes whose callback checks nothing are high (named function and closure)', () => {
    const titles = findings.filter((x) => x.rule === 'wp.rest.public-write').map((x) => x.title);
    assert.ok(titles.some((t) => t.includes('vf/v1/write')), titles.join(' | '));
    assert.ok(titles.some((t) => t.includes('vf/v1/closure-write')), titles.join(' | '));
    assert.ok(findings.filter((x) => x.rule === 'wp.rest.public-write').every((x) => x.severity === 'high'));
  });

  test('module run: hard-coded AWS key is found and the check fails', async () => {
    const run = makeRun({ config: { scan: { plugins: ['vuln-plugin'] } }, flags: { only: ['security.secrets'] } });
    await security(run);
    assert.ok(run.findings.some((f) => f.rule === 'secret.aws-access-key'));
    assert.equal(run.checks[0].status, 'failed');
  });
});

describe('safe fixture: zero security findings', () => {
  const { findings, notes } = scanDir(fixturePlugin('safe-plugin'));

  test('scanner reports nothing for the safe plugin', () => {
    assert.deepEqual(describeFindings(findings), []);
  });

  test('{$wpdb->postmeta} interpolation is not SQL injection (real-site false positive)', () => {
    const text = `<?php\nfunction a() { global $wpdb; return $wpdb->get_results( "SELECT post_id, meta_value FROM {$wpdb->postmeta} WHERE meta_key = '_alh_source'" ); }`;
    assert.deepEqual(describeFindings(scanText(text)), []);
  });

  test('$wpdb->prefix concatenation is not SQL injection', () => {
    const text = `<?php\nfunction a() { global $wpdb; return $wpdb->get_var( 'SELECT COUNT(*) FROM ' . $wpdb->prefix . 'log' ); }`;
    assert.deepEqual(describeFindings(scanText(text)), []);
  });

  test('...but a real variable next to {$wpdb->postmeta} still is', () => {
    const text = `<?php\nfunction a( $k ) { global $wpdb; return $wpdb->get_results( "SELECT * FROM {$wpdb->postmeta} WHERE meta_key = '$k'" ); }`;
    assert.deepEqual(scanText(text).map((f) => f.rule), ['wp.sqli.unprepared']);
  });

  test('nonce-protected public REST form is a review note, not a finding (real-site false positive)', () => {
    assert.ok(notes.some((n) => n.includes('sf/v1/contact') && n.includes('wp_verify_nonce')), notes.join('\n'));
  });

  test('nonce-checked inline closure REST route is a review note', () => {
    assert.ok(notes.some((n) => n.includes('sf/v1/vote')), notes.join('\n'));
  });

  test('public read-only REST route is a review note', () => {
    assert.ok(notes.some((n) => n.includes('sf/v1/items') && /read-only/.test(n)), notes.join('\n'));
  });

  test('settings_fields() counts as a nonce (real-site false positive)', () => {
    const withIt = `<?php ?>\n<form method="post" action="options.php"><?php settings_fields( 'x' ); ?></form>`;
    const without = `<?php ?>\n<form method="post" action="options.php"><input name="a"></form>`;
    assert.deepEqual(scanText(withIt).map((f) => f.rule), []);
    assert.deepEqual(scanText(without).map((f) => f.rule), ['wp.csrf.form-no-nonce']);
  });

  test('block render.php with $post/$id/$title variables gives no scanner finding', () => {
    const file = path.join(fixturePlugin('safe-plugin'), 'blocks', 'card', 'render.php');
    assert.deepEqual(describeFindings(scanPhp(file, fs.readFileSync(file, 'utf8'), { allPhp: [], notes: [], type: 'plugin' })), []);
  });

  test('module run on the safe plugin: wp-patterns, secrets and wp-config all pass with zero findings', async () => {
    const run = makeRun({ config: { scan: { plugins: ['safe-plugin'] } }, flags: { only: ['security.wp-patterns', 'security.secrets', 'security.wp-config'] } });
    await security(run);
    run.finalizeFindings();
    assert.deepEqual(run.findings.map((f) => `${f.check} ${f.rule} ${f.file}:${f.line}`), []);
    assert.deepEqual(run.checks.map((c) => [c.id, c.status]), [['security.wp-patterns', 'passed'], ['security.secrets', 'passed'], ['security.wp-config', 'passed']]);
  });
});
