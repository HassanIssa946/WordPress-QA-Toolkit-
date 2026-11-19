// CLI: strict flag parsing, and end-to-end runs of bin/wpqa.mjs with their exit codes and report files.
import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { parseArgs } from '../lib/cli.mjs';
import { TESTS_DIR, FIXTURE_SITE, tempDir } from './helpers.mjs';

const BIN = path.join(TESTS_DIR, '..', 'bin', 'wpqa.mjs');

describe('parseArgs (strict)', () => {
  test('boolean flags are exactly true; values for them are errors', () => {
    assert.deepEqual(parseArgs(['security', '--approve']).flags, { _: ['security'], approve: true });
    for (const bad of ['--approve=false', '--approve=yes', '--approve=1', '--approve=', '--changed=no']) {
      const { flags, errors } = parseArgs(['security', bad]);
      assert.equal(errors.length, 1, bad);
      assert.match(errors[0], /takes no value/);
      assert.equal(flags.approve, undefined, `${bad} must not set approve`);
    }
  });
  test('unknown flags are errors, with a suggestion for typos', () => {
    const { errors } = parseArgs(['security', '--aprove']);
    assert.match(errors[0], /unknown flag "--aprove"\. Did you mean --approve\?/);
    assert.match(parseArgs(['-x']).errors[0], /unknown flag "-x"/);
    assert.match(parseArgs(['--']).errors.join(), /^$/);
  });
  test('value flags need a value; lists are split', () => {
    assert.match(parseArgs(['run', '--only']).errors[0], /needs a value/);
    assert.match(parseArgs(['run', '--only', '--approve']).errors[0], /needs a value/);
    assert.match(parseArgs(['run', '--config=']).errors[0], /needs a value/);
    assert.deepEqual(parseArgs(['run', '--only', 'a.b, c.*', '--skip=x']).flags, { _: ['run'], only: ['a.b', 'c.*'], skip: ['x'] });
    assert.equal(parseArgs(['init', '--url=http://a.local']).flags.url, 'http://a.local');
  });
});

/** Temp project folder with a config pointing at the fixture WordPress tree. */
function project(over = {}) {
  const dir = tempDir('wpqa-cli-');
  const cfg = {
    project: { name: 'cli-fixture', wpPath: FIXTURE_SITE },
    site: { url: 'http://fixture.invalid', environment: 'local', pages: ['/'] },
    scan: { plugins: ['safe-plugin'] },
    vulnerabilityLookup: false,
    ...over,
  };
  fs.writeFileSync(path.join(dir, 'wpqa.config.json'), JSON.stringify(cfg));
  return dir;
}
function cli(args, cwd) {
  const r = spawnSync(process.execPath, [BIN, ...args], { cwd, encoding: 'utf8', timeout: 120000 });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
const latestReport = (dir) => {
  const latest = JSON.parse(fs.readFileSync(path.join(dir, '.wpqa', 'latest.json'), 'utf8'));
  return JSON.parse(fs.readFileSync(path.join(dir, latest.json), 'utf8'));
};

describe('CLI end-to-end (exit codes)', () => {
  test('exit 2: --approve=false, --approve=yes, typos, unknown mode, missing config', () => {
    const dir = project();
    for (const args of [['security', '--approve=false'], ['security', '--approve=yes'], ['security', '--aprove'], ['nonsense-mode'], ['run']]) {
      const r = cli(args, dir);
      assert.equal(r.code, 2, `${args.join(' ')} → ${r.code}\n${r.err}`);
    }
    assert.match(cli(['security', '--approve=false'], dir).err, /--approve takes no value/);
    assert.equal(fs.existsSync(path.join(dir, '.wpqa')), false, 'nothing must run on invalid arguments');
    assert.equal(cli(['security'], tempDir('wpqa-empty-')).code, 2);
  });

  test('exit 0 (PASS): safe plugin, static security checks', () => {
    const dir = project();
    const r = cli(['security', '--only', 'security.wp-patterns,security.secrets,security.wp-config'], dir);
    assert.equal(r.code, 0, r.out + r.err);
    assert.match(r.out, /Verdict: PASS/);
    const rep = latestReport(dir);
    assert.equal(rep.schemaVersion, 2);
    assert.equal(rep.verdict.status, 'PASS');
    assert.equal(rep.coverageSummary.executed, 3);
    assert.ok(rep.coverageSummary.filesInspected > 0);
    assert.ok(fs.readFileSync(path.join(dir, JSON.parse(fs.readFileSync(path.join(dir, '.wpqa', 'latest.json'), 'utf8')).report), 'utf8').includes('Files/folders inspected'));
  });

  test('exit 1 (FAIL): vulnerable plugin', () => {
    const dir = project({ scan: { plugins: ['vuln-plugin'] } });
    const r = cli(['security', '--only', 'security.wp-patterns'], dir);
    assert.equal(r.code, 1, r.out + r.err);
    assert.equal(latestReport(dir).verdict.status, 'FAIL');
  });

  test('exit 3 (INCOMPLETE): a core check skipped because its tool is missing', () => {
    const dir = project({ tools: { php: path.join(tempDir(), 'no-such-php.exe') } });
    const r = cli(['code', '--only', 'code.php-lint'], dir);
    assert.equal(r.code, 3, r.out + r.err);
    const rep = latestReport(dir);
    assert.equal(rep.verdict.status, 'INCOMPLETE');
    assert.equal(rep.coverageSummary.skipped, 1);
  });

  test('a second run compares; a schema-v1 previous report gives "baseline reset"', () => {
    const dir = project({ scan: { plugins: ['vuln-plugin'] } });
    assert.equal(cli(['security', '--only', 'security.wp-patterns'], dir).code, 1);
    // Make the first report look like a V1 report (no schemaVersion).
    const latest = JSON.parse(fs.readFileSync(path.join(dir, '.wpqa', 'latest.json'), 'utf8'));
    const p = path.join(dir, latest.json);
    const old = JSON.parse(fs.readFileSync(p, 'utf8'));
    delete old.schemaVersion;
    fs.writeFileSync(p, JSON.stringify(old));
    // Distinct run IDs need a different second (run IDs are second-precision).
    const t = Date.now(); while (Date.now() - t < 1100) { /* wait */ }
    const r = cli(['security', '--only', 'security.wp-patterns'], dir);
    assert.match(r.out, /not compared — previous report uses report schema v1/);
    assert.equal(latestReport(dir).diff.baselineReset, true);
  });

  test('allowIntrusiveOnProduction: true prints a warning and changes nothing', () => {
    const dir = project({ safety: { allowedHosts: [], allowIntrusiveOnProduction: true } });
    const r = cli(['security', '--only', 'security.wp-config'], dir);
    assert.match(r.err, /allowIntrusiveOnProduction is ignored/);
    assert.equal(r.code, 0);
  });
});
