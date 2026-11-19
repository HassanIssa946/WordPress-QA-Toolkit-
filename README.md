# WordPress QA Toolkit (V2)

A reusable QA, security and infrastructure auditor for WordPress projects. Claude Code drives it with `/wp-audit`.
Real tools do the testing: PHPCS/WPCS, PHPStan, ESLint, Stylelint, Semgrep, WP-CLI, WPVulnerability, Playwright + axe-core, Lighthouse, k6, OWASP ZAP (Docker) and Node's DNS/TLS/HTTP.
Claude interprets the results, proposes fixes and retests.

## What it tests

| Area | Checks |
|---|---|
| Code quality | `php -l` syntax, PHPCS + WordPress Coding Standards + PHP compatibility, PHPStan (+ WordPress extension), ESLint (incl. `innerHTML`/eval sinks), Stylelint |
| Security (static) | Built-in WordPress scanner: XSS, SQL injection, REST routes without `permission_callback`, AJAX/admin-post without nonce or capability, file inclusion, unserialize, shell/eval, open redirect, POST forms without nonce. Also hard-coded secrets, wp-config hardening and Semgrep taint rules |
| WordPress | Theme integration (`wp_head`/`wp_footer`/title-tag/enqueued assets), plugin headers, Gutenberg `block.json` (name, apiVersion, missing build files), known vulnerabilities (core/plugins/themes), outdated/closed/abandoned wp.org components |
| WP-CLI | Core checksums and updates, plugin/theme updates and checksums, inactive plugins, "discourage search engines", open registration, `admin` username, Plugin Check, Theme Check |
| Network/DNS/TLS/HTTP | A/AAAA/CNAME/NS/CAA, SPF/DMARC, certificate validity/expiry/chain, TLS 1.0/1.1, HTTP/2, HTTP→HTTPS and www canonical redirects, security headers, version leaks, mixed content, exposed `debug.log`/`.env`/`.git`/wp-config backups, user enumeration, xmlrpc, TTFB |

| Frontend (`frontend` mode) | Playwright + axe per page × desktop/mobile: HTTP status, uncaught JS and console errors, failed same-origin requests, sideways scrolling, images without alt / width+height, unlabeled fields, POST forms without a nonce, accessibility (axe: critical → high, serious → medium). Broken internal links (logout, wp-login, wp-admin, `?action=`, `_wpnonce` and cart links are never requested). Visual regression against approved baselines in `wpqa-tests/baselines/` (canvas/video/iframe/model-viewer masked; never auto-updated — `baselines update --confirm`). Site-specific specs in `wpqa-tests/e2e/*.spec.mjs`. Block-editor round trip on a sandbox (approval-gated): temporary draft with every custom block → save → reload → attributes kept, block valid → front-end render → draft **always** deleted (leftover = high) |
| Performance (`performance` mode) | Lighthouse mobile + desktop on the first 3 pages (scores as Lighthouse reports them; LCP/CLS/TBT vs thresholds; top 5 opportunities; local results labelled "lab, not production"). Page cache / CDN evidence (LiteSpeed, Hostinger hcdn, Cloudflare, Varnish …), browser caching of static files, compression. Missing cache headers = "insufficient evidence", not "cache off". **Cached nonce**: a nonce in public HTML served from a cache older than half the nonce lifetime (the nonce value is never printed) |
| SEO (`seo` mode) | robots.txt, XML sitemaps (core/Yoast/Rank Math) incl. broken/foreign URLs, title, meta description, canonical, one H1, `lang`, noindex (an error only on production), hreflang (Polylang/WPML), JSON-LD validity. Runs on the local site and, GET-only, on the public production site |
| Load (`scalability` mode) | k6 smoke / load / stress, GET only, max 50 VUs / 10 min, stress needs `safety.allowStress`; thresholds p95 and error rate. Approval-gated, sandbox only. Local results describe your machine, not production capacity |
| DAST (`dast` checks) | OWASP ZAP baseline via Docker (pinned image); full active scan only with `dast.active`. Approval-gated, never production. **Without Docker it reports "ZAP did not run" (not tested)** |
| Backend (`backend` mode) | Custom REST routes (unauthenticated GET only; public = info), p95 latency, approval-gated write probes on routes you list, read-only DB health (autoload, expired transients, revisions, table engines), overdue WP-Cron, `debug.log` grouped and redacted, PHPUnit only against a separate test DB |

| Stack health (`stack` mode) | Inventory of WordPress, PHP + extensions, database, web server, Node, npm, Composer, WP-CLI, plugins, themes, WooCommerce. Status per item: CURRENT / UPDATE AVAILABLE / SECURITY UPDATE REQUIRED / END OF LIFE / INCOMPATIBLE / UNKNOWN, from endoflife.date, api.wordpress.org, nodejs.org, getcomposer.org and WPVulnerability (cached 24 h, source URL + date recorded). `Requires PHP` / `Requires at least` / `WC requires at least` and your composer.json / package.json constraints vs what is installed (and vs production PHP when visible). Local vs production PHP/WordPress drift. Rate limits keyed on `REMOTE_ADDR` behind a CDN, and client IPs read from spoofable headers. `composer audit` / `npm audit` of your code's lock files. An upgrade plan (security → PHP/DB → core → plugins → build tools). Never installs or upgrades anything |

All V2 modules are built. OWASP ZAP needs Docker Desktop and the pinned image (`docker pull ghcr.io/zaproxy/zaproxy:2.16.1`); without them `dast.*` is reported as not tested.

## Install (Windows + LocalWP)

1. **Node 22.22+** (`node -v`). Update from nodejs.org if older.
2. Put this folder somewhere permanent, e.g. `C:\dev\wordpress-qa-toolkit`, then in PowerShell:
   ```powershell
   cd C:\dev\wordpress-qa-toolkit
   npm install
   ```
3. **PHP in your terminal.** LocalWP's PHP lives at
   `%APPDATA%\Local\lightning-services\php-8.2.29+0\bin\win64\php.exe` (the folder name may differ slightly).
   Either add that folder to PATH, or set `"tools": { "php": "C:/Users/<you>/AppData/Roaming/Local/lightning-services/php-8.2.29+0/bin/win64/php.exe" }` in each project's `wpqa.config.json`.
4. **Composer** (https://getcomposer.org/Composer-Setup.exe, point it at that php.exe), then:
   ```powershell
   composer install
   ```
   This installs PHPCS, WPCS, PHPCompatibilityWP and PHPStan into the toolkit. Your projects don't need them.
5. **WP-CLI + database.** For LocalWP sites, `init` does this for you: it reads Local's `app/.envrc` (written when the site starts) and fills `tools.php`, `tools.wp` (`[php.exe, wp-cli.phar]`), `tools.composer`, `tools.env` (`PHPRC`, `MYSQL_HOME`, …) and `tools.pathPrepend` (Local's ImageMagick/MySQL folders). Start the site in Local before `init`. Then PHP, WP-CLI and the database work from any terminal. Re-run `init --force` if you move the site or change its PHP version. (Local's **Open site shell** also still works.)
6. Optional: Semgrep (`pip install semgrep`, or use WSL), Docker Desktop + the pinned ZAP image (ZAP baseline) and k6 (load tests). Both are only used with `--approve` on an allowlisted sandbox.
7. Install the Claude Code skill:
   ```powershell
   node bin/wpqa.mjs install-skill
   ```
   Then restart Claude Code.

## Use in a project

```powershell
cd "C:\Users\<you>\Local Sites\<site-folder>"
node <toolkit>\bin\wpqa.mjs init --public https://www.example.com
node <toolkit>\bin\wpqa.mjs doctor
```
For LocalWP sites `init` takes the local URL from Local itself (the **Site domain** in Local's overview, e.g. `http://my-shop.local`), so `--url` is usually not needed. If you pass `--url`, it warns when the host does not resolve or differs from Local's domain. `site.pages` is seeded from the core sitemap, an SEO plugin's sitemap (Yoast/Rank Math) or the REST API.

Check `wpqa.config.json`. `scan.themes` and `scan.plugins` must list only your own code. `doctor` warns when `site.url` differs from WordPress's `siteurl` and predicts which optional checks will be skipped.

In Claude Code:
```
/wp-audit quick            after coding (add --changed for git-changed files only)
/wp-audit security
/wp-audit wordpress
/wp-audit infrastructure
/wp-audit stack            versions, support status, compatibility, upgrade plan
/wp-audit frontend         browser checks, accessibility, links, visual regression
/wp-audit performance      Lighthouse, caching, cached nonces
/wp-audit seo
/wp-audit full             before delivery
```
Or run directly: `node <toolkit>/bin/wpqa.mjs security --only security.wp-patterns`.

Reports go to `.wpqa/reports/<run>/report.md` and `report.json` (`init` adds `.wpqa/` to `.gitignore` unless git already ignores it). Each run is compared with the previous run **of the same mode**: new, resolved, still open, and not re-tested. Every check records what it scanned (files or URLs); a finding counts as **resolved** only if the same check ran again and re-scanned its file/URL. Anything else (check skipped/errored, file outside `--changed`) is listed as **not re-tested**.

Finding IDs don't depend on line numbers. A code finding is identified by its check, rule, file and the text of the flagged line, so adding lines above it doesn't make it look new or resolved. URL findings ignore cache-busting parameters such as `?ver=`. Reports carry `schemaVersion` (currently 2). When the previous report has a different schema version, the run says **"not compared"** and starts a new comparison baseline instead of inventing new/resolved items. Each finding has `retest` (`new` / `still-open`) and `firstSeen`.

The report's `coverageSummary` gives overall totals: applicable, executed, passed, failed, skipped, errored and not-applicable checks, plus the number of files/folders and URLs the executed checks inspected.

## Verdict

| Verdict | Exit | Meaning |
|---|---:|---|
| PASS | 0 | No findings at/above `failOn`, every core check of the mode ran, coverage ≥ `minCoverage` |
| FAIL | 1 | Findings at/above `failOn` (reported even if the run was also incomplete) |
| — | 2 | Configuration or runtime error |
| INCOMPLETE | 3 | No blocking findings, but a core check was skipped/errored or coverage < `minCoverage` (default 80%), so a PASS cannot be claimed |

Coverage = executed ÷ applicable checks. "Not applicable" checks (e.g. no JavaScript) don't count against it. Phase-2 modules aren't counted either; they don't exist yet and are listed in the report as not tested. Core checks per mode are in `lib/modes.mjs`. Optional tools (Semgrep, Plugin Check, Theme Check) are not core and only lower coverage.

When a scanner crashes or its output can't be parsed, the check is **error** (never passed) and the raw output is saved under `artifacts/<check>/` in the run folder.

## Safety model

- Read-only by default. The infrastructure, caching and SEO checks send GET requests to the public site, which is safe on production. When the audited (local) site is down, those passive production checks still run, but the check is marked skipped so the verdict is INCOMPLETE.
- Intrusive tests (editor drafts, write probes, k6 load tests, ZAP scans) all go through one gate, `lib/safety.mjs`. Every rule must pass:
  1. `--approve` given on the command line. It takes no value: `--approve=false` / `--approve=yes` is rejected with exit 2, as is any unknown or misspelled flag.
  2. The target host is listed in `safety.allowedHosts`. Nothing is allowed automatically, and `init` leaves the list empty.
  3. The target is not production: `site.environment` must be `local` or `staging`. The `publicSite` host and its www/apex variant are refused, and so is any host that resolves to the same IP address as production, or whose WordPress declares `WP_ENVIRONMENT_TYPE = production`.
  4. Load tests stay within `safety.limits`. The hard ceiling is 50 VUs and 600 s; config can lower it, not raise it. Stress also needs `safety.allowStress`.
- **There is no production override.** `safety.allowIntrusiveOnProduction` is ignored, with a warning if it is set to true.
- Every gate decision (allowed or refused, with reasons) is listed in the report under "Safety gate".
- A missing tool means **skipped**, never passed. Coverage % = executed ÷ applicable checks.
- Exit codes: 0 PASS, 1 FAIL, 2 usage/config/runtime error, 3 INCOMPLETE (see Verdict). You can use these in CI.

`init` leaves `safety.allowedHosts` empty. Add a host by hand, and only for a disposable sandbox site.

## Sandbox for intrusive tests

Editor drafts, write probes and k6 run only on a disposable sandbox site and ZAP:

1. Create a blank site (e.g. LocalWP `test.local`), run `init` there and add its host to `safety.allowedHosts` by hand.
2. For the editor test, copy `sandbox/wpqa-fixture-blocks` into its `wp-content/plugins`, activate it, and add `"wpqa-fixture-blocks"` to `scan.plugins`.
3. Put credentials in the environment, never in a file: `WPQA_WP_USER`, `WPQA_WP_PASS` (Windows: `setx`, then open a new terminal).
4. After agreeing to it, run: `frontend --approve`, `scalability --profile smoke --approve` and `dast --approve` (ZAP baseline, passive; the active scan also needs `dast.active: true`).

## Config reference

All keys and defaults are in `lib/config.mjs` (`DEFAULTS`). Commonly changed:

| Key | Meaning |
|---|---|
| `site.url`, `site.environment` | Site under test (`local` / `staging` / `production`) |
| `publicSite.url` | Live domain for DNS/TLS/redirect checks |
| `scan.themes`, `scan.plugins`, `scan.extraPaths` | Code you own |
| `code.phpVersion` | e.g. `"8.1-"` (PHPCompatibility + PHPStan) |
| `code.phpstanLevel`, `code.phpstanScanDirectories`, `code.phpstanScanFiles`, `code.phpstanIgnore` | PHPStan tuning. Symbols that PHPStan can't find but that exist in an installed plugin are reported as info, and the run notes which folders to add to `phpstanScanDirectories`. Constants your code `define()`s are bootstrapped automatically |
| `tools.php`, `tools.wp`, `tools.env` | Paths or arrays, e.g. `"wp": ["C:/…/php.exe", "C:/…/wp-cli.phar"]`. PHP is always run with `-d display_errors=stderr`, so startup warnings can't corrupt parsed output |
| `tools.pathPrepend` | Folders put in front of PATH for tool processes (LocalWP: ImageMagick for `php_imagick.dll`) |
| `failOn` | `critical` / `high` / `medium` / `low` / `none` |
| `minCoverage` | Percent of applicable checks that must run for a PASS (default `80`) |
| `safety.allowedHosts` | Hosts intrusive tests may target (never production) |
| `safety.limits`, `safety.allowStress` | Load-test ceilings (≤ 50 VUs, ≤ 600 s) and the stress opt-in |
| `safety.allowedWriteEndpoints` | The only REST routes write probes may call: `[{ route, method, body, cleanup }]` |
| `vulnerabilityLookup` | `false` to skip the WPVulnerability API |
| `backend.restExamples` | Example path/query for REST routes that need parameters, e.g. `{"/myns/v1/products": {"query": {"brand": 12}}}` |
| `backend.restP95Ms`, `backend.restSamples` | Latency threshold (800 ms) and timed requests per route (10) |
| `backend.autoloadKbWarn` / `autoloadKbHigh`, `revisionsWarn`, `transientsWarn`, `cronOverdueMin` | DB health thresholds |
| `backend.debugLogDays`, `debugLogMaxMb` | debug.log window (7 days) and how much of the end of the file to read (20 MB) |
| `backend.phpunit.enabled` | Run project PHPUnit suites (never when the test DB equals the site DB) |
| `stack.cacheHours` | How long public version/vulnerability lookups are cached in `.wpqa/cache` (24). `--offline` uses the cache only; a lookup that fails or isn't cached makes the item UNKNOWN, never CURRENT |
| `frontend.viewports`, `visualMask`, `visualThreshold`, `maxLinksToCheck`, `maxPages`, `blockEditorTest` | Browser checks (defaults: desktop+mobile; canvas/video/iframe/model-viewer masked; 1 % pixel diff; 60 links; 12 pages) |
| `performance.pages`, `lcpMs`, `cls`, `tbtMs`, `nonceLifetimeSec` | Lighthouse pages (3) and thresholds (2500 ms, 0.1, 300 ms); nonce lifetime (86400 s) |
| `seo.maxPages` | Pages per target (site.pages + sitemap, 20) |
| `load.vus`, `duration`, `rampUp`, `p95Ms`, `errorRate`, `paths`, `smokeVus`, `smokeDuration`, `stressStep` | k6 profiles (always capped by `safety.limits`); an invalid duration refuses the run |
| `dast.zapImage`, `dast.active`, `dast.maxMinutes` | ZAP image (must be pinned; default `ghcr.io/zaproxy/zaproxy:2.16.1`), active scan switch, time limit |
| `stack.eolWarnDays` | Warn this many days before a PHP/DB/WordPress/Node branch reaches end of life (180) |

## Layout

```
bin/wpqa.mjs              CLI (init, doctor, discover, run <mode>, report, install-skill)
lib/                      engine, config, discovery, reporting, modes, localwp, pages,
                          cli (strict flags), safety (intrusive-test gate), fingerprint (stable IDs),
                          versions (cycles, EOL, constraints), cache (24 h lookup cache), redact
modules/                  code, security, wordpress, wpcli, infrastructure, backend, stack, dependencies,
                          frontend, performance, seo, scalability, dast
sandbox/                  wpqa-fixture-blocks: a no-build test block for the editor test (sandbox only)
docs/                     V2-BACKLOG.md (improvements), V2-REPORT.md (completion report)
config/                   phpcs.xml, eslint.config.mjs, stubs/ (minimal WP-CLI stubs for PHPStan)
rules/semgrep/            WordPress taint rules
skill/wp-audit/           Claude Code skill + fix playbook
tests/                    self-tests (node:test) + fixtures/site (vulnerable, safe and stack plugins)
```
Add a module by creating `modules/<id>.mjs` (export a default `async (run) => run.check({...}, fn)`), then adding it to `lib/modes.mjs` (and its essential checks to that mode's `core`). In a check, call `c.scope(files|urls)` with what you examined, and `c.toolError(name, result, problem)` when the tool's output can't be trusted.

## Self-tests

```powershell
npm test
```
No PHP, network or database needed. The vulnerable fixture must trigger every scanner rule. The safe fixture (including patterns that used to be false positives: `{$wpdb->postmeta}`, a nonce-protected public REST form, `settings_fields()`, block `render.php` variables) must produce zero security findings.

Also covered:

- verdict and run comparison;
- stable IDs;
- coverage totals;
- every refusal reason of the safety gate;
- strict flag parsing;
- end-to-end CLI runs checking exit codes 0, 1, 2 and 3;
- backend checks against recorded REST/WP-CLI output;
- stack status rules (a failed lookup is UNKNOWN, never CURRENT), version constraints and the upgrade plan order, against recorded public-source data.

The fake AWS key the secrets test needs isn't committed: `tests/helpers.mjs` builds it from parts and writes it to a git-ignored fixture file.

Optional: `composer require --dev php-stubs/wp-cli-stubs` gives PHPStan the full WP-CLI API (the toolkit falls back to `config/stubs/wp-cli-min.php`).
