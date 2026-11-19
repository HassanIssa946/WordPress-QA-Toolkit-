// Shared helpers for the toolkit self-tests (node:test). No network, PHP or database needed.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { loadConfig, deepMerge } from '../lib/config.mjs';
import { AuditRun } from '../lib/engine.mjs';

export const TESTS_DIR = path.dirname(fileURLToPath(import.meta.url));
export const FIXTURE_SITE = path.join(TESTS_DIR, 'fixtures', 'site');
export const fixturePlugin = (slug) => path.join(FIXTURE_SITE, 'wp-content', 'plugins', slug);

export function tempDir(prefix = 'wpqa-test-') {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

/** A real AuditRun against the fixture WordPress tree, with reports in a temp folder. */
export function makeRun({ config = {}, mode = 'security', flags = {} } = {}) {
  const dir = tempDir();
  const base = {
    project: { name: 'fixture', wpPath: FIXTURE_SITE },
    site: { url: 'http://fixture.local', environment: 'local', pages: ['/'] },
    vulnerabilityLookup: false,
  };
  fs.writeFileSync(path.join(dir, 'wpqa.config.json'), JSON.stringify(deepMerge(base, config)));
  const { cfg, problems } = loadConfig(path.join(dir, 'wpqa.config.json'));
  if (problems.length) throw new Error(problems.join('; '));
  return new AuditRun({ cfg, mode, flags: { quiet: true, ...flags }, version: 'test' });
}

/** Minimal check record as the engine produces it. */
export const chk = (id, status, extra = {}) => ({ id, title: id, category: id.split('.')[0], status, reason: extra.reason || null, notes: [], artifacts: [], stats: {}, findingCount: 0, durationMs: 0, scope: ['*'], ...extra });

/** Minimal finding. */
export const fnd = (id, check, severity = 'high', extra = {}) => ({ id, check, severity, title: id, file: null, url: null, ...extra });
