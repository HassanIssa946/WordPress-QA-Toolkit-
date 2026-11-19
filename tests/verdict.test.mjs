// Verdict: PASS / FAIL / INCOMPLETE, coverage and exit codes.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { verdict, coverage, EXIT_CODES } from '../lib/report.mjs';
import { MODES } from '../lib/modes.mjs';
import { chk, fnd } from './helpers.mjs';

const core = ['code.phpcs', 'security.wp-patterns'];

describe('verdict', () => {
  test('PASS: core checks ran, no blocking findings, coverage 100%', () => {
    const v = verdict([fnd('a', 'code.phpcs', 'medium')], 'high', { checks: [chk('code.phpcs', 'failed'), chk('security.wp-patterns', 'passed')], core });
    assert.equal(v.status, 'PASS');
    assert.equal(v.pass, true);
    assert.equal(v.coveragePct, 100);
    assert.deepEqual(v.incomplete, []);
  });

  test('FAIL: a finding at/above failOn', () => {
    const v = verdict([fnd('a', 'code.phpcs', 'high')], 'high', { checks: [chk('code.phpcs', 'failed'), chk('security.wp-patterns', 'passed')], core });
    assert.equal(v.status, 'FAIL');
    assert.equal(v.blocking, 1);
  });

  test('INCOMPLETE: a core check was skipped', () => {
    const v = verdict([], 'high', { checks: [chk('code.phpcs', 'skipped', { reason: 'tool not available: php' }), chk('security.wp-patterns', 'passed'), chk('x.a', 'passed'), chk('x.b', 'passed'), chk('x.c', 'passed'), chk('x.d', 'passed')], core });
    assert.equal(v.status, 'INCOMPLETE');
    assert.equal(v.pass, false);
    assert.match(v.incomplete.join('\n'), /core check code\.phpcs was skipped: tool not available: php/);
  });

  test('INCOMPLETE: a core check errored (scanner crash / unparsable output)', () => {
    const v = verdict([], 'high', { checks: [chk('code.phpcs', 'passed'), chk('security.wp-patterns', 'error', { reason: 'scanner crashed' })], core });
    assert.equal(v.status, 'INCOMPLETE');
    assert.match(v.incomplete[0], /security\.wp-patterns errored/);
  });

  test('INCOMPLETE: optional checks skipped push coverage below minCoverage', () => {
    const checks = [chk('code.phpcs', 'passed'), chk('security.wp-patterns', 'passed'), chk('opt.a', 'skipped'), chk('opt.b', 'skipped')];
    const v = verdict([], 'high', { checks, core, minCoverage: 80 });
    assert.equal(v.coveragePct, 50);
    assert.equal(v.status, 'INCOMPLETE');
    assert.match(v.incomplete[0], /coverage 50% .* below minCoverage 80%/);
    assert.equal(verdict([], 'high', { checks, core, minCoverage: 50 }).status, 'PASS');
  });

  test('not-applicable checks do not lower coverage', () => {
    const v = verdict([], 'high', { checks: [chk('code.phpcs', 'passed'), chk('security.wp-patterns', 'passed'), chk('code.eslint', 'not_applicable')], core });
    assert.equal(v.coveragePct, 100);
    assert.equal(v.status, 'PASS');
  });

  test('phase-2 placeholders are not counted (security mode would otherwise never pass)', () => {
    const checks = [chk('code.phpcs', 'passed'), chk('security.wp-patterns', 'passed'), chk('dast.*', 'skipped', { planned: true }), chk('backend.*', 'skipped', { planned: true }), chk('dependencies.*', 'skipped', { planned: true })];
    const v = verdict([], 'high', { checks, core });
    assert.equal(v.coveragePct, 100);
    assert.equal(v.status, 'PASS');
    assert.deepEqual(coverage(checks).map((c) => c.category).sort(), ['code', 'security']);
  });

  test('INCOMPLETE: nothing executed at all', () => {
    const v = verdict([], 'high', { checks: [chk('frontend.*', 'skipped', { planned: true })], core: [] });
    assert.equal(v.status, 'INCOMPLETE');
    assert.match(v.incomplete[0], /no check was executed/);
  });

  test('FAIL wins over INCOMPLETE, but the incomplete reasons are kept', () => {
    const v = verdict([fnd('a', 'code.phpcs', 'critical')], 'high', { checks: [chk('code.phpcs', 'failed'), chk('security.wp-patterns', 'error', { reason: 'boom' })], core });
    assert.equal(v.status, 'FAIL');
    assert.match(v.incomplete[0], /security\.wp-patterns errored/);
    assert.match(v.incomplete[1], /coverage 50%/); // 1 of 2 applicable checks executed
  });

  test('failOn none never fails but can still be incomplete', () => {
    assert.equal(verdict([fnd('a', 'code.phpcs', 'critical')], 'none', { checks: [chk('code.phpcs', 'failed'), chk('security.wp-patterns', 'passed')], core }).status, 'PASS');
    assert.equal(verdict([], 'none', { checks: [chk('code.phpcs', 'skipped'), chk('security.wp-patterns', 'passed')], core }).status, 'INCOMPLETE');
  });

  test('core check not selected with --only is not required', () => {
    const v = verdict([], 'high', { checks: [chk('security.wp-patterns', 'passed')], core });
    assert.equal(v.status, 'PASS');
  });
});

describe('exit codes and modes', () => {
  test('PASS 0, FAIL 1, config error 2, INCOMPLETE 3', () => {
    assert.deepEqual(EXIT_CODES, { PASS: 0, FAIL: 1, ERROR: 2, INCOMPLETE: 3 });
  });
  test('every v1 mode declares core checks; optional extras are not core', () => {
    for (const m of ['quick', 'code', 'security', 'wordpress', 'infrastructure', 'full']) assert.ok(MODES[m].core.length > 0, m);
    for (const m of Object.values(MODES)) for (const optional of ['security.semgrep', 'wpcli.plugin-check', 'wpcli.theme-check']) assert.ok(!m.core.includes(optional));
  });
});
