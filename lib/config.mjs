// Project configuration: defaults, loading, validation.
import fs from 'node:fs';
import path from 'node:path';
import { IS_WIN } from './util.mjs';

export const CONFIG_FILE = 'wpqa.config.json';

export const DEFAULTS = {
  project: { name: 'WordPress site', wpPath: '.' },
  site: {
    url: 'http://localhost',
    // local | staging | production — describes the site at site.url
    environment: 'local',
    pages: ['/'],
  },
  // Public, live domain for passive DNS/TLS/HTTP-header checks (optional).
  publicSite: { url: null },
  scan: {
    // Folder names under wp-content/themes and wp-content/plugins that YOU maintain.
    themes: [],
    plugins: [],
    muPlugins: false,
    extraPaths: [],
    exclude: ['node_modules', 'vendor', '.git', 'build', 'dist', '.cache', 'languages'],
  },
  tools: {
    php: 'php',
    wp: 'wp',
    composer: 'composer',
    semgrep: 'semgrep',
    docker: 'docker',
    k6: 'k6',
    npm: 'npm',
    node: 'node',
    // Extra environment for WP-CLI/PHP (e.g. PHPRC for LocalWP's php.ini).
    env: {},
    // Directories put in front of PATH for tool processes (e.g. LocalWP's ImageMagick folder for php_imagick.dll).
    pathPrepend: [],
  },
  code: {
    phpVersion: '8.1-',
    phpstanLevel: 5,
    phpstanIgnore: [],
    phpstanScanDirectories: [], // third-party code PHPStan should know about (not analysed), e.g. "app/public/wp-content/plugins/polylang"
    phpstanScanFiles: [],
    phpcsStandard: null, // null = toolkit ruleset; or path to project ruleset
    maxFindingsPerRule: 25,
  },
  frontend: {
    viewports: ['desktop', 'mobile'],
    visualRegression: true,
    visualMask: ['canvas', 'video', 'iframe', 'model-viewer', '.wpqa-mask'],
    maxLinksToCheck: 60,
    blockEditorTest: true,
    visualThreshold: 0.01, // share of pixels that may differ before a visual-regression finding
    maxPages: 12,
  },
  performance: {
    pages: 3,
    lighthouse: { performance: 0.8, accessibility: 0.9, 'best-practices': 0.9, seo: 0.9 },
    lcpMs: 2500,
    cls: 0.1,
    tbtMs: 300,
    ttfbMs: 800,
    nonceLifetimeSec: 86400, // nonce_life filter value; a cached page older than half of it may carry an expired nonce
  },
  seo: {
    maxPages: 20, // pages per target (site.pages + sitemap)
  },
  backend: {
    restP95Ms: 800,
    restSamples: 10, // timed GET requests per public route (after one warm-up)
    restNamespaces: [], // extra namespaces to treat as yours (auto-detected from register_rest_route in your code)
    restExamples: {}, // "<route>": { "path": "/ns/v1/item/5", "query": { "id": 5 } } for routes that need parameters
    autoloadKbWarn: 800,
    autoloadKbHigh: 2048,
    transientsWarn: 1000,
    revisionsWarn: 50,
    cronOverdueMin: 60,
    debugLogDays: 7,
    debugLogMaxMb: 20,
    phpunit: { enabled: false }, // also requires a test DB different from the site DB
  },
  stack: {
    cacheHours: 24, // public lookups (endoflife.date, api.wordpress.org, WPVulnerability …) are cached this long
    eolWarnDays: 180, // warn this many days before a PHP/DB/WordPress/Node branch reaches end of life
  },
  load: {
    vus: 50,
    duration: '2m',
    rampUp: '30s',
    p95Ms: 1500,
    errorRate: 0.01,
    paths: null, // defaults to site.pages
    smokeVus: 2,
    smokeDuration: '30s',
    stressStep: '1m', // stress: 4 steps of this length up to safety.limits.maxVus
  },
  dast: {
    zapImage: 'ghcr.io/zaproxy/zaproxy:2.16.1', // pinned; unpinned tags (stable/latest/weekly) are refused
    active: false, // full (active) scan; only for a disposable sandbox
    maxMinutes: 5,
  },
  safety: {
    // Hosts that intrusive tests (editor drafts, write probes, load, ZAP) may target. Nothing is added
    // automatically. Production (site.environment=production, publicSite host and its www/apex variant, or any
    // host resolving to production's address) is always refused — there is no override.
    allowedHosts: [],
    // Ceilings for load tests; can only lower the hard limits (50 VUs, 600 s) in lib/safety.mjs.
    limits: { maxVus: 50, maxDurationSec: 600 },
    // The k6 stress profile additionally needs this.
    allowStress: false,
    // Write probes only hit routes listed here: [{ route, method, body, cleanup }].
    allowedWriteEndpoints: [],
  },
  auth: {
    // Names of environment variables holding a wp-admin login for the editor test (local/staging only).
    userEnv: 'WPQA_WP_USER',
    passEnv: 'WPQA_WP_PASS',
  },
  vulnerabilityLookup: true,
  failOn: 'high', // exit non-zero when findings at/above this severity exist: critical|high|medium|low|none
  // Verdict is INCOMPLETE (exit 3) when executed ÷ applicable checks is below this percentage, or a core check
  // of the mode was skipped/errored. Phase-2 modules that do not exist yet are not counted.
  minCoverage: 80,
};

function isObj(v) { return v && typeof v === 'object' && !Array.isArray(v); }

export function deepMerge(base, over) {
  const out = Array.isArray(base) ? [...base] : { ...base };
  for (const [k, v] of Object.entries(over || {})) {
    if (k.startsWith('$') || k.startsWith('//')) continue;
    out[k] = isObj(v) && isObj(base?.[k]) ? deepMerge(base[k], v) : v;
  }
  return out;
}

/** Look for wpqa.config.json in dir and its parents. */
export function findConfig(startDir) {
  let d = path.resolve(startDir);
  for (let i = 0; i < 8; i++) {
    const p = path.join(d, CONFIG_FILE);
    if (fs.existsSync(p)) return p;
    const parent = path.dirname(d);
    if (parent === d) break;
    d = parent;
  }
  return null;
}

export function loadConfig(configPath) {
  const raw = fs.readFileSync(configPath, 'utf8');
  let user;
  try {
    user = JSON.parse(raw);
  } catch (e) {
    throw new Error(`Invalid JSON in ${configPath}: ${e.message}`);
  }
  const cfg = deepMerge(DEFAULTS, user);
  cfg._path = configPath;
  cfg._root = path.dirname(configPath);
  cfg._wpRoot = path.resolve(cfg._root, cfg.project.wpPath || '.');
  cfg._outRoot = path.join(cfg._root, '.wpqa');
  cfg._testsRoot = path.join(cfg._root, 'wpqa-tests');
  const problems = validateConfig(cfg);
  const warnings = configWarnings(user);
  return { cfg, problems, warnings };
}

/** Deprecated or ignored settings: reported, never fatal. */
export function configWarnings(user = {}) {
  const w = [];
  if (user?.safety?.allowIntrusiveOnProduction === true) {
    w.push('safety.allowIntrusiveOnProduction is ignored: intrusive tests never run against production (remove the setting).');
  }
  return w;
}

export function validateConfig(cfg) {
  const problems = [];
  const envs = ['local', 'staging', 'production'];
  if (!envs.includes(cfg.site.environment)) problems.push(`site.environment must be one of ${envs.join(', ')}`);
  try { new URL(cfg.site.url); } catch { problems.push(`site.url is not a valid URL: ${cfg.site.url}`); }
  if (cfg.publicSite?.url) { try { new URL(cfg.publicSite.url); } catch { problems.push(`publicSite.url is not a valid URL`); } }
  if (!Array.isArray(cfg.site.pages) || !cfg.site.pages.length) problems.push('site.pages must be a non-empty array of paths');
  if (!['critical', 'high', 'medium', 'low', 'none'].includes(cfg.failOn)) problems.push('failOn must be critical|high|medium|low|none');
  if (!fs.existsSync(cfg._wpRoot)) problems.push(`project.wpPath does not exist: ${cfg._wpRoot}`);
  if (typeof cfg.minCoverage !== 'number' || cfg.minCoverage < 0 || cfg.minCoverage > 100) problems.push('minCoverage must be a number from 0 to 100');
  if (!Array.isArray(cfg.tools.pathPrepend)) problems.push('tools.pathPrepend must be an array of folders');
  if (!Array.isArray(cfg.safety?.allowedHosts)) problems.push('safety.allowedHosts must be an array of host names');
  if (!Array.isArray(cfg.safety?.allowedWriteEndpoints)) problems.push('safety.allowedWriteEndpoints must be an array');
  return problems;
}

/** Absolute directories of the code the user maintains (custom themes/plugins/extra paths). */
export function customCodeDirs(cfg) {
  const wpContent = path.join(cfg._wpRoot, 'wp-content');
  const dirs = [];
  for (const t of cfg.scan.themes || []) dirs.push({ type: 'theme', slug: t, dir: path.join(wpContent, 'themes', t) });
  for (const p of cfg.scan.plugins || []) dirs.push({ type: 'plugin', slug: p, dir: path.join(wpContent, 'plugins', p) });
  if (cfg.scan.muPlugins) dirs.push({ type: 'mu-plugin', slug: 'mu-plugins', dir: path.join(wpContent, 'mu-plugins') });
  for (const e of cfg.scan.extraPaths || []) dirs.push({ type: 'path', slug: e, dir: path.resolve(cfg._root, e) });
  return dirs.filter((d) => fs.existsSync(d.dir));
}

export function siteHost(cfg) {
  try { return new URL(cfg.site.url).hostname; } catch { return ''; }
}

export const PLATFORM_HINTS = IS_WIN
  ? {
      php: 'LocalWP ships PHP at %APPDATA%\\Local\\lightning-services\\php-<version>\\bin\\win64\\php.exe — set tools.php to that path, or run from Local → "Open site shell".',
      wp: 'Run from Local → right-click site → "Open site shell" (WP-CLI + DB pre-configured), or set tools.wp to ["<php.exe>", "<path>\\wp-cli.phar"].',
      composer: 'Install from https://getcomposer.org/Composer-Setup.exe (point it at the LocalWP php.exe).',
      k6: 'winget install k6 --source winget',
      semgrep: 'pip install semgrep (or run inside WSL/Docker).',
      docker: 'Install Docker Desktop.',
    }
  : {
      php: 'Install PHP 8.1+ (brew install php / apt install php-cli).',
      wp: 'Install WP-CLI: https://wp-cli.org/#installing',
      composer: 'Install Composer: https://getcomposer.org/download/',
      k6: 'brew install k6 / see https://grafana.com/docs/k6/latest/set-up/install-k6/',
      semgrep: 'pip install semgrep / brew install semgrep',
      docker: 'Install Docker Engine or Docker Desktop.',
    };
