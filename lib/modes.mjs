// Audit modes → modules. Intrusive modules (scalability, dast, write probes) are approval-gated inside the module.
//
// `core` lists the checks a mode cannot do without: if one of them is skipped or errors, the verdict is
// INCOMPLETE instead of PASS (a check that is "not applicable", e.g. no JavaScript files, is fine).
// Optional extras (Semgrep, Plugin Check, Theme Check) are not core: they lower coverage instead.
const CODE_CORE = ['code.php-lint', 'code.phpcs', 'code.phpstan', 'code.eslint', 'code.stylelint'];
const STATIC_SECURITY_CORE = ['security.wp-patterns', 'security.secrets', 'security.wp-config'];
const WP_STATIC_CORE = ['wordpress.theme', 'wordpress.plugin', 'wordpress.blocks', 'wordpress.vulnerabilities', 'wordpress.wporg-status'];
const WPCLI_CORE = ['wpcli.core', 'wpcli.plugins', 'wpcli.settings'];
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
    description: 'Static security, vulnerable components, WordPress hardening, REST/AJAX exposure, TLS/headers/exposed files. ZAP scan and write-probes only with --approve.',
  },
  wordpress: { modules: ['wordpress', 'wpcli'], core: [...WP_STATIC_CORE, ...WPCLI_CORE], description: 'Core, plugins, themes, Gutenberg blocks, settings, updates, checksums, known vulnerabilities.' },
  frontend: { modules: ['frontend', 'seo'], core: [], description: '[phase 2] Playwright: page health, console errors, broken links, responsive layout, accessibility (axe), forms, visual regression, block editor.' },
  backend: { modules: ['backend'], core: [], description: '[phase 2] REST API, response times, database health, WP-Cron, PHP error log, PHPUnit.' },
  performance: { modules: ['performance'], core: [], description: '[phase 2] Lighthouse (Core Web Vitals), caching and compression headers.' },
  seo: { modules: ['seo'], core: [], description: '[phase 2] robots.txt, sitemaps, titles/meta/canonical/noindex, structured data, hreflang.' },
  infrastructure: { modules: ['infrastructure'], core: INFRA_CORE, description: 'DNS, email DNS (SPF/DMARC), TLS certificate and protocols, redirects, security headers, exposed files, network timing.' },
  scalability: { modules: ['scalability'], core: [], description: '[phase 2] k6 load test against an approved non-production host. Requires --approve.' },
  full: {
    modules: ['code', 'security', 'wordpress', 'wpcli', 'infrastructure', 'dependencies', 'frontend', 'backend', 'performance', 'seo', 'dast'],
    core: [...new Set([...CODE_CORE, ...STATIC_SECURITY_CORE, ...WP_STATIC_CORE, ...WPCLI_CORE, ...INFRA_CORE])],
    description: 'Everything except load testing. Approval-gated tests are listed as "waiting for approval" unless --approve is given.',
  },
};

export const MODULE_IDS = [...new Set(Object.values(MODES).flatMap((m) => m.modules)), 'scalability'];

// Modules shipped in this version. Others are reported as "not tested (planned for phase 2)".
export const AVAILABLE = new Set(['code', 'security', 'wordpress', 'wpcli', 'infrastructure']);
