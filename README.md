# WordPress QA Toolkit (v1)

A reusable QA, security and infrastructure auditor for WordPress projects. Claude Code drives it with `/wp-audit`.
Real tools do the testing: PHPCS/WPCS, PHPStan, ESLint, Stylelint, Semgrep, WP-CLI, WPVulnerability and Node's DNS/TLS/HTTP.
Claude interprets the results, proposes fixes and retests.

## What v1 tests

| Area | Checks |
|---|---|
| Code quality | `php -l` syntax, PHPCS + WordPress Coding Standards + PHP compatibility, PHPStan (+ WordPress extension), ESLint (incl. `innerHTML`/eval sinks), Stylelint |
| Security (static) | Built-in WordPress scanner: XSS, SQL injection, REST routes without `permission_callback`, AJAX/admin-post without nonce or capability, file inclusion, unserialize, shell/eval, open redirect, POST forms without nonce. Also hard-coded secrets, wp-config hardening and Semgrep taint rules |
| WordPress | Theme integration (`wp_head`/`wp_footer`/title-tag/enqueued assets), plugin headers, Gutenberg `block.json` (name, apiVersion, missing build files), known vulnerabilities (core/plugins/themes), outdated/closed/abandoned wp.org components |
| WP-CLI | Core checksums and updates, plugin/theme updates and checksums, inactive plugins, "discourage search engines", open registration, `admin` username, Plugin Check, Theme Check |
| Network/DNS/TLS/HTTP | A/AAAA/CNAME/NS/CAA, SPF/DMARC, certificate validity/expiry/chain, TLS 1.0/1.1, HTTP/2, HTTP→HTTPS and www canonical redirects, security headers, version leaks, mixed content, exposed `debug.log`/`.env`/`.git`/wp-config backups, user enumeration, xmlrpc, TTFB |

**Phase 2 (not in v1, reported as "not tested"):** frontend (Playwright + axe, visual regression, block editor), backend/REST runtime + DB health, Lighthouse, SEO, k6 load tests, OWASP ZAP, composer/npm audit.

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
6. Optional: Semgrep (`pip install semgrep`, or use WSL), Docker and k6 (phase 2).
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
For LocalWP sites `init` takes the local URL from Local itself (the **Site domain** in Local's overview, e.g. `http://al-hadbaa.local`), so `--url` is usually not needed. If you pass `--url`, it warns when the host does not resolve or differs from Local's domain. `site.pages` is seeded from the core sitemap, an SEO plugin's sitemap (Yoast/Rank Math) or the REST API.

Check `wpqa.config.json`. `scan.themes` and `scan.plugins` must list only your own code. `doctor` warns when `site.url` differs from WordPress's `siteurl` and predicts which optional checks will be skipped.

In Claude Code:
```
/wp-audit quick            after coding (add --changed for git-changed files only)
/wp-audit security
/wp-audit wordpress
/wp-audit infrastructure
/wp-audit full             before delivery
```
Or run directly: `node <toolkit>/bin/wpqa.mjs security --only security.wp-patterns`.

Reports go to `.wpqa/reports/<run>/report.md` and `report.json` (`init` adds `.wpqa/` to `.gitignore` unless git already ignores it). Each run is compared with the previous run **of the same mode**: new, resolved, still open, and not re-tested. Every check records what it scanned (files or URLs); a finding counts as **resolved** only if the same check ran again and re-scanned its file/URL. Anything else (check skipped/errored, file outside `--changed`) is listed as **not re-tested**.

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

- Read-only by default. The infrastructure checks send a handful of GET requests, which is safe on production.
- Intrusive tests (phase 2 load/ZAP/write probes) need `--approve` **and** a host listed in `safety.allowedHosts`. Production is refused unless `safety.allowIntrusiveOnProduction` is true.
- A missing tool means **skipped**, never passed. Coverage % = executed ÷ applicable checks.
- Exit codes: 0 PASS, 1 FAIL, 2 config/runtime error, 3 INCOMPLETE (see Verdict). You can use these in CI.

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
| `vulnerabilityLookup` | `false` to skip the WPVulnerability API |

## Layout

```
bin/wpqa.mjs              CLI (init, doctor, discover, run <mode>, report, install-skill)
lib/                      engine, config, discovery, reporting, modes, localwp, pages
modules/                  code, security, wordpress, wpcli, infrastructure
config/                   phpcs.xml, eslint.config.mjs, stubs/ (minimal WP-CLI stubs for PHPStan)
rules/semgrep/            WordPress taint rules
skill/wp-audit/           Claude Code skill + fix playbook
tests/                    self-tests (node:test) + fixtures/site (vulnerable and safe plugins)
```
Add a module by creating `modules/<id>.mjs` (export a default `async (run) => run.check({...}, fn)`), then adding it to `lib/modes.mjs` (and its essential checks to that mode's `core`). In a check, call `c.scope(files|urls)` with what you examined, and `c.toolError(name, result, problem)` when the tool's output can't be trusted.

## Self-tests

```powershell
npm test
```
No PHP, network or database needed. The vulnerable fixture must trigger every scanner rule. The safe fixture (including patterns that used to be false positives: `{$wpdb->postmeta}`, a nonce-protected public REST form, `settings_fields()`, block `render.php` variables) must produce zero security findings. Verdict, run comparison and the `--approve` gate are covered too.

Optional: `composer require --dev php-stubs/wp-cli-stubs` gives PHPStan the full WP-CLI API (the toolkit falls back to `config/stubs/wp-cli-min.php`).
