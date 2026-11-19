// Audit modes → modules. Intrusive modules (scalability, dast, write probes) are approval-gated inside the module.
//
// `core` lists the checks a mode cannot do without: if one of them is skipped or errors, the verdict is
// INCOMPLETE instead of PASS (a check that is "not applicable", e.g. no JavaScript files, is fine).
// Optional extras (Semgrep, Plugin Check, Theme Check) are not core: they lower coverage instead.
const CODE_CORE = ['code.php-lint', 'code.phpcs', 'code.phpstan', 'code.eslint', 'code.stylelint'];
const STATIC_SECURITY_CORE = ['security.wp-patterns', 'security.secrets', 'security.wp-config'];
const WP_STATIC_CORE = ['wordpress.theme', 'wordpress.plugin', 'wordpress.blocks', 'wordpress.vulnerabilities', 'wordpress.wporg-status'];
const WPCLI_CORE = ['wpcli.core', 'wpcli.plugins', 'wpcli.settings'];
const BACKEND_CORE = ['backend.rest', 'backend.db-health', 'backend.cron'];
const STACK_CORE = ['stack.inventory', 'stack.status', 'stack.compatibility'];
const PERF_CORE = ['performance.lighthouse', 'performance.caching', 'performance.cached-nonce'];
const SEO_CORE = ['seo.robots', 'seo.sitemap', 'seo.pages'];
const FRONTEND_CORE = ['frontend.pages', 'frontend.links'];
const INFRA_CORE = ['infra.dns', 'infra.email-dns', 'infra.tls', 'infra.redirects', 'infra.headers', 'infra.exposure'];

export const MODES = {
  quick: {
    modules: ['code', 'security', 'wordpress'],
    core: [...CODE_CORE, ...STATIC_SECURITY_CORE, 'wordpress.theme', 'wordpress.plugin', 'wordpress.blocks'],
    description: 'Fast feedback after coding: PHP lint, PHPCS/WPCS, PHPStan, ESLint/Stylelint, WordPress security patterns, theme/plugin/block checks. Use --changed to limit to git-changed files.',
  },
  code: { modules: ['code'], core: CODE_CORE, description: 'Code quality only (PHP, JS, CSS).' },
  security: {
    modules: ['security', 'wordpress', 'wpcli', 'infrastructure', 'dependencies', 'backend', 'dast'],
    core: [...STATIC_SECURITY_CORE, 'wordpress.vulnerabilities', ...WPCLI_CORE, 'infra.tls', 'infra.headers', 'infra.exposure'],
    // From backend, security runs only the REST exposure and (approval-gated) write probes.
    moduleChecks: { backend: ['backend.rest', 'backend.write-probes'] },
    description: 'Static security, vulnerable components, WordPress hardening, REST/AJAX exposure, TLS/headers/exposed files. ZAP scan and write-probes only with --approve.',
  },
  wordpress: { modules: ['wordpress', 'wpcli'], core: [...WP_STATIC_CORE, ...WPCLI_CORE], description: 'Core, plugins, themes, Gutenberg blocks, settings, updates, checksums, known vulnerabilities.' },
  frontend: { modules: ['frontend', 'seo'], core: [...FRONTEND_CORE, ...SEO_CORE], description: 'Playwright + axe per page × desktop/mobile: status, JS errors, failed requests, horizontal overflow, images, form labels, POST forms without nonce, accessibility; broken internal links; visual regression (approved baselines); e2e specs in wpqa-tests/e2e; block editor round trip on a sandbox (--approve).' },
  backend: { modules: ['backend'], core: BACKEND_CORE, description: 'REST API (custom routes, unauthenticated GET, p95 latency), write probes (sandbox, --approve), read-only database health, WP-Cron, PHP error log, PHPUnit.' },
  performance: { modules: ['performance'], core: PERF_CORE, description: 'Lighthouse lab test (mobile + desktop, first pages; LCP/CLS/TBT vs thresholds, top opportunities), page/browser caching and compression headers (local site and public production site, GET only), nonces in cached HTML.' },
  seo: { modules: ['seo'], core: SEO_CORE, description: 'robots.txt, XML sitemaps (core/Yoast/Rank Math), titles, descriptions, canonical, one H1, lang, noindex (an error only on production), hreflang, JSON-LD.' },
  infrastructure: { modules: ['infrastructure'], core: INFRA_CORE, description: 'DNS, email DNS (SPF/DMARC), TLS certificate and protocols, redirects, security headers, exposed files, network timing.' },
  stack: { modules: ['stack', 'dependencies'], core: STACK_CORE, description: 'Stack health: inventory of WordPress, PHP + extensions, database, web server, Node, Composer, WP-CLI, plugins, themes; status per item (current / update / security update / end of life / incompatible / unknown) from public sources; compatibility; local vs production drift; client IP behind a CDN; Composer/npm audit; upgrade plan. Never installs anything.' },
  scalability: { modules: ['scalability'], core: ['scalability.k6'], description: 'k6 load test (GET only; --profile smoke | load | stress; max 50 VUs / 10 min; stress needs safety.allowStress) against an allowlisted non-production host. Requires --approve.' },
  dast: { modules: ['dast'], core: ['dast.zap-baseline'], description: 'OWASP ZAP via Docker (pinned image): baseline scan; full active scan only with dast.active. Requires --approve; never production.' },
  full: {
    modules: ['code', 'security', 'wordpress', 'wpcli', 'infrastructure', 'dependencies', 'stack', 'frontend', 'backend', 'performance', 'seo', 'dast'],
    core: [...new Set([...CODE_CORE, ...STATIC_SECURITY_CORE, ...WP_STATIC_CORE, ...WPCLI_CORE, ...INFRA_CORE, ...BACKEND_CORE, ...STACK_CORE, ...PERF_CORE, ...SEO_CORE, ...FRONTEND_CORE])],
    description: 'Everything except load testing. Approval-gated tests are listed as "waiting for approval" unless --approve is given.',
  },
};

export const MODULE_IDS = [...new Set(Object.values(MODES).flatMap((m) => m.modules)), 'scalability'];

// Modules shipped in this version. Others are reported as "not tested (planned for phase 2)".
export const AVAILABLE = new Set(['code', 'security', 'wordpress', 'wpcli', 'infrastructure', 'backend', 'stack', 'dependencies', 'performance', 'seo', 'frontend', 'scalability', 'dast']);
