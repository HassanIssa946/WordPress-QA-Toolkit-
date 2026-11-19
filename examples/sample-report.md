> Sample output from a test WordPress site with deliberately planted bugs (not a real site scan).

# WordPress QA Report — site

**Mode:** `quick` · **Target:** http://127.0.0.1:8899 (local)  
**Run:** 20261118-110709-quick · **Duration:** 5s · **Toolkit:** v1.0.0

## Verdict

❌ **FAIL** — 14 finding(s) at or above `high`

> ⚠️ 2 check(s) were skipped or errored and are **not** counted as passed — see "Not tested" below.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 3 | 11 | 14 | 16 | 7 |

## Coverage

Coverage = executed checks ÷ applicable checks. It measures how much was tested, not how good the site is.

| Area | Passed | Failed | Skipped | Errors | N/A | Coverage |
|---|---:|---:|---:|---:|---:|---:|
| Code Quality | 0 | 5 | 0 | 0 | 0 | 100% |
| Security | 0 | 4 | 0 | 0 | 0 | 100% |
| WordPress (themes, plugins, blocks) | 0 | 3 | 0 | 0 | 0 | 100% |
| Dependencies & Vulnerabilities | 0 | 0 | 2 | 0 | 0 | 0% |

## Changes since previous run (`20261118-110553-security`)

- 🆕 New: **42** · 🔁 Still open: **9** · ✅ Resolved: **1** · ❔ Not re-tested this run: **0**

Resolved:
- ~~HIGH — Request data printed without escaping (reflected XSS)~~ app/public/wp-content/themes/alhadbaa/functions.php

## Findings

### Critical (3)

#### [C1] PHP syntax error (fatal on load) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/template-parts/broken.php:2`
- **Check:** `code.php-lint` · **Tool:** php -l · **Rule:** `php-syntax` · **Confidence:** confirmed
- **Evidence:**

  ```
  Errors parsing /home/claude/fixture/site/app/public/wp-content/themes/alhadbaa/template-parts/broken.php
  ```
- **Fix:** Fix the syntax error; this file will crash any request that loads it.

#### [C2] REST route alhadbaa/v1/partner has no permission_callback and accepts writes
- **Where:** `app/public/wp-content/themes/alhadbaa/functions.php:15`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.rest.no-permission-callback` · **Confidence:** confirmed
- **Evidence:**

  ```
  ( 'alhadbaa/v1', '/partner', array(
  		'methods'  => 'POST',
  		'callback' => 'alhadbaa_save_partner',
  	) )
  ```
- **Fix:** Add 'permission_callback' => fn() => current_user_can( 'edit_posts' ) (or the right capability). Use '__return_true' only for intentionally public read-only routes.

#### [C3] File inclusion from request data
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:19`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.lfi.include` · **Confidence:** likely
- **Evidence:**

  ```
  include $_GET['tpl'];
  ```
- **Fix:** Never build include paths from input; map allowed values to fixed files.

### High (11)

#### [H1] Unescaped output (possible XSS) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/header.php:5`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.EscapeOutput` · **Confidence:** likely
- **Details:** All output should be run through an escaping function (see the Security sections in the WordPress Developer Handbooks), found 'get_template_directory_uri'.
- **Fix:** Escape late with esc_html(), esc_attr(), esc_url(), wp_kses_post() matching the output context.

#### [H2] Unescaped output (possible XSS) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/functions.php:10`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.EscapeOutput` · **Confidence:** likely · also: wpqa scanner, Semgrep
- **Details:** All output should be run through an escaping function (see the Security sections in the WordPress Developer Handbooks), found '$_GET['brand']'.
- **Fix:** Escape late with esc_html(), esc_attr(), esc_url(), wp_kses_post() matching the output context.

#### [H3] Dynamic code execution (eval-like) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/assets/js/main.js:3`
- **Check:** `code.eslint` · **Tool:** ESLint · **Rule:** `no-implied-eval` · **Confidence:** confirmed
- **Details:** Implied eval. Consider passing a function instead of a string.
- **Fix:** Remove eval/new Function/string timers; they enable XSS-to-RCE in the browser.

#### [H4] Public AJAX/admin-post handler "handle_contact" has no nonce check and changes data (CSRF)
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:9`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.csrf.ajax-no-nonce` · **Confidence:** likely
- **Evidence:**

  ```
  add_action('wp_ajax_nopriv_alhadbaa_contact', …) → handle_contact()
  ```
- **Fix:** Send a nonce from the page (wp_create_nonce('action')) and call check_ajax_referer('action') first in the handler.

#### [H5] Logged-in AJAX/admin-post handler "alhadbaa_save_settings" has no nonce check and changes data (CSRF)
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:14`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.csrf.ajax-no-nonce` · **Confidence:** likely
- **Evidence:**

  ```
  add_action('wp_ajax_alhadbaa_settings', …) → alhadbaa_save_settings()
  ```
- **Fix:** Send a nonce from the page (wp_create_nonce('action')) and call check_ajax_referer('action') first in the handler.

#### [H6] AJAX handler "alhadbaa_save_settings" changes data without current_user_can() (any logged-in user, incl. subscribers)
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:14`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.authz.ajax-no-capability` · **Confidence:** likely
- **Fix:** Add if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( null, 403 ); }

#### [H7] Stripe live secret key in source code 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/functions.php:35`
- **Check:** `security.secrets` · **Tool:** wpqa scanner · **Rule:** `secret.stripe-live-secret-key` · **Confidence:** likely
- **Evidence:**

  ```
  $stripe = '•••redacted•••';
  ```
- **Fix:** Move it to wp-config.php constants or environment variables, rotate the key, and purge it from git history.

#### [H8] Request data used as a file path or include (LFI / arbitrary file access)
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:19`
- **Check:** `security.semgrep` · **Tool:** Semgrep · **Rule:** `wp-file-request-path` · **Confidence:** likely
- **Evidence:**

  ```
  requires login
  ```
- **Fix:** Map allowed values to fixed paths; use basename() + allow-list; never include user paths.

#### [H9] wp_head() is never called 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa`
- **Check:** `wordpress.theme` · **Tool:** wpqa · **Rule:** `theme.wp_head` · **Confidence:** confirmed
- **Fix:** Call wp_head() before </head>; without it plugins, SEO tags and enqueued CSS/JS break.

#### [H10] wp_footer() is never called 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa`
- **Check:** `wordpress.theme` · **Tool:** wpqa · **Rule:** `theme.wp_footer` · **Confidence:** confirmed
- **Fix:** Call wp_footer() before </body>; footer scripts (forms, analytics, blocks) depend on it.

#### [H11] Block alhadbaa/brand-card: editorScript file missing (file:./index.js) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/blocks/brand-card/build/block.json`
- **Check:** `wordpress.blocks` · **Tool:** wpqa · **Rule:** `block.asset-missing` · **Confidence:** confirmed
- **Fix:** Run the build (npm run build) and commit/deploy the build folder.

### Medium (14)

#### [M1] Scripts/styles hard-coded instead of enqueued (1 occurrence) 🆕
- **Locations:** `app/public/wp-content/themes/alhadbaa/header.php:5`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.WP.EnqueuedResources` · **Confidence:** confirmed
- **Details:** Stylesheets must be registered/enqueued via wp_enqueue_style()
- **Fix:** Use wp_enqueue_script()/wp_enqueue_style() so caching, dependencies and plugins work.

#### [M2] Form/request data processed without nonce verification (CSRF) 🆕
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:10`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.NonceVerification` · **Confidence:** likely
- **Details:** Processing form data without nonce verification.
- **Fix:** Verify with check_admin_referer()/wp_verify_nonce()/check_ajax_referer() before acting on $_POST/$_GET.

#### [M3] Form/request data processed without nonce verification (CSRF) 🆕
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:15`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.NonceVerification` · **Confidence:** likely
- **Details:** Processing form data without nonce verification.
- **Fix:** Verify with check_admin_referer()/wp_verify_nonce()/check_ajax_referer() before acting on $_POST/$_GET.

#### [M4] Form/request data processed without nonce verification (CSRF) 🆕
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:18`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.NonceVerification` · **Confidence:** likely
- **Details:** Processing form data without nonce verification.
- **Fix:** Verify with check_admin_referer()/wp_verify_nonce()/check_ajax_referer() before acting on $_POST/$_GET.

#### [M5] Form/request data processed without nonce verification (CSRF) 🆕
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:19`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.NonceVerification` · **Confidence:** likely
- **Details:** Processing form data without nonce verification.
- **Fix:** Verify with check_admin_referer()/wp_verify_nonce()/check_ajax_referer() before acting on $_POST/$_GET.

#### [M6] Form/request data processed without nonce verification (CSRF) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/functions.php:8`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.NonceVerification` · **Confidence:** likely
- **Details:** Processing form data without nonce verification.
- **Fix:** Verify with check_admin_referer()/wp_verify_nonce()/check_ajax_referer() before acting on $_POST/$_GET.

#### [M7] Form/request data processed without nonce verification (CSRF) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/functions.php:10`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.NonceVerification` · **Confidence:** likely
- **Details:** Processing form data without nonce verification.
- **Fix:** Verify with check_admin_referer()/wp_verify_nonce()/check_ajax_referer() before acting on $_POST/$_GET.

#### [M8] Request input not validated/sanitized 🆕
- **Where:** `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:19`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.ValidatedSanitizedInput` · **Confidence:** likely
- **Details:** $_GET['tpl'] not unslashed before sanitization. Use wp_unslash() or similar · Detected usage of a non-sanitized input variable: $_GET['tpl']
- **Fix:** isset() check, wp_unslash(), then sanitize_text_field()/absint()/sanitize_email() etc.

#### [M9] Request input not validated/sanitized 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/functions.php:8`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.ValidatedSanitizedInput` · **Confidence:** likely
- **Details:** Detected usage of a possibly undefined superglobal array index: $_GET['brand']. Check that the array index exists before using it. · $_GET['brand'] not unslashed before sanitization. Use wp_unslash() or similar · Detected usage of a non-sanitized input variable: $_GET['brand']
- **Fix:** isset() check, wp_unslash(), then sanitize_text_field()/absint()/sanitize_email() etc.

#### [M10] Request input not validated/sanitized 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/functions.php:10`
- **Check:** `code.phpcs` · **Tool:** PHPCS · **Rule:** `WordPress.Security.ValidatedSanitizedInput` · **Confidence:** likely
- **Details:** Detected usage of a possibly undefined superglobal array index: $_GET['brand']. Check that the array index exists before using it. · $_GET['brand'] not unslashed before sanitization. Use wp_unslash() or similar · Detected usage of a non-sanitized input variable: $_GET['brand']
- **Fix:** isset() check, wp_unslash(), then sanitize_text_field()/absint()/sanitize_email() etc.

#### [M11] Unsanitized HTML injection (innerHTML/insertAdjacentHTML) 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa/assets/js/main.js:2`
- **Check:** `code.eslint` · **Tool:** ESLint · **Rule:** `no-unsanitized/property` · **Confidence:** likely
- **Details:** Unsafe assignment to innerHTML
- **Fix:** Use textContent, or build DOM nodes; if HTML is required, sanitize (e.g. DOMPurify) and never insert URL/user data.

#### [M12] POST form without a WordPress nonce field
- **Where:** `app/public/wp-content/themes/alhadbaa/index.php:3`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.csrf.form-no-nonce` · **Confidence:** heuristic
- **Evidence:**

  ```
  <form method="post" action="">
  ```
- **Fix:** Add wp_nonce_field( 'my_action', 'my_nonce' ) and verify it in the handler.

#### [M13] add_theme_support( 'title-tag' ) missing 🆕
- **Where:** `app/public/wp-content/themes/alhadbaa`
- **Check:** `wordpress.theme` · **Tool:** wpqa · **Rule:** `theme.title-tag` · **Confidence:** confirmed
- **Fix:** Let WordPress/SEO plugins manage <title>; remove hard-coded <title>.

#### [M14] Script/stylesheet hard-coded in a template instead of enqueued (1 occurrence) 🆕
- **Locations:** `app/public/wp-content/themes/alhadbaa/header.php:5`
- **Check:** `wordpress.theme` · **Tool:** wpqa · **Rule:** `theme.hardcoded-asset` · **Confidence:** confirmed
- **Fix:** Use wp_enqueue_script/style in functions.php (with version + dependencies).

### Low & info (23)

| Ref | Sev | Finding | Where | Fix |
|---|---|---|---|---|
| L1 | low | Coding standard: Squiz.PHP.EmbeddedPhp (1 occurrence) | `app/public/wp-content/themes/alhadbaa/index.php:6` | Follow WordPress Coding Standards. |
| L2 | low | Coding standard: Squiz.ControlStructures.ControlSignature (1 occurrence) | `app/public/wp-content/themes/alhadbaa/index.php:6` | Auto-fixable with phpcbf. |
| L3 | low | Coding standard: Generic.Formatting.DisallowMultipleStatements (1 occurrence) | `app/public/wp-content/themes/alhadbaa/index.php:6` | Auto-fixable with phpcbf. |
| L4 | low | Coding standard: Generic.PHP.Syntax (1 occurrence) | `app/public/wp-content/themes/alhadbaa/template-parts/broken.php:4` | Follow WordPress Coding Standards. |
| L5 | low | Coding standard: PEAR.Functions.FunctionCallSignature (1 occurrence) | `app/public/wp-content/themes/alhadbaa/functions.php:2` | Auto-fixable with phpcbf. |
| L6 | low | Syntax error, unexpected EOF on line 4 | `app/public/wp-content/themes/alhadbaa/template-parts/broken.php:4` | Fix the type/logic error or add a precise @var/@param annotation if PHPStan lacks context. |
| L7 | low | 'undefinedThing' is not defined. | `app/public/wp-content/themes/alhadbaa/assets/js/main.js:4` | If this is a wp_localize_script/global, declare it with /* global name */; otherwise it is a ReferenceError at runtime. |
| L8 | low | Stylelint: property-no-unknown (1 occurrence) | `app/public/wp-content/themes/alhadbaa/style.css:6` | Fix the CSS mistake (duplicate/invalid/unknown property or selector). |
| L9 | low | Plugin file executes code without an ABSPATH guard | `app/public/wp-content/plugins/alhadbaa-core/alhadbaa-core.php:1` | Add at the top: defined( 'ABSPATH' ) \|\| exit; |
| L10 | low | Theme/plugin file editor enabled (DISALLOW_FILE_EDIT not set) | `app/public/wp-config.php` | define( 'DISALLOW_FILE_EDIT', true ); — an admin-account takeover then can't directly edit PHP. |
| L11 | low | style.css missing "Text Domain" header (alhadbaa) | `app/public/wp-content/themes/alhadbaa/style.css` | Add "Text Domain:" to the style.css header. |
| L12 | low | wp_body_open() not called after <body> | `app/public/wp-content/themes/alhadbaa` |  |
| L13 | low | Plugin header missing "Requires PHP" (alhadbaa-core) | `app/public/wp-content/plugins/alhadbaa-core` |  |
| L14 | low | Custom plugin alhadbaa-core has no "Update URI" header | `app/public/wp-content/plugins/alhadbaa-core` | Add "Update URI: false" so a same-named wordpress.org plugin can never overwrite it via updates. |
| L15 | low | Block alhadbaa/brand-card uses apiVersion 2 | `app/public/wp-content/themes/alhadbaa/blocks/brand-card/build/block.json` | Use apiVersion 3 so the block works in the iframed editor (WP 6.3+). |
| L16 | low | Block alhadbaa/brand-card has no textdomain | `app/public/wp-content/themes/alhadbaa/blocks/brand-card/build/block.json` |  |
| I1 | info | Coding standard: Universal.WhiteSpace.PrecisionAlignment (1 occurrence) | `app/public/wp-content/themes/alhadbaa/index.php:4` | Auto-fixable with phpcbf. |
| I2 | info | Coding standard: Generic.CodeAnalysis.UnconditionalIfStatement (1 occurrence) | `app/public/wp-content/themes/alhadbaa/template-parts/broken.php:2` | Follow WordPress Coding Standards. |
| I3 | info | 21 coding-standard issue(s) can be fixed automatically |  | php "/home/claude/wordpress-qa-toolkit/vendor/squizlabs/php_codesniffer/bin/phpcbf" --standard="/home/claude/wordpress-qa-toolkit/config/phpcs.xml" --runtime-set installed_paths "/home/claude/wordpress-qa-toolkit/vendor/wp-coding-standards/wpcs,/home/claude/wordpress-qa-toolkit/vendor/phpcompatibility/php-compatibility,/home/claude/wordpress-qa-toolkit/vendor/phpcompatibility/phpcompatibility-paragonie,/home/claude/wordpress-qa-toolkit/vendor/phpcompatibility/phpcompatibility-wp,/home/claude/wordpress-qa-toolkit/vendor/phpcsstandards/phpcsutils,/home/claude/wordpress-qa-toolkit/vendor/phpcsstandards/phpcsextra" <path> (review the diff before committing) |
| I4 | info | Public REST route alhadbaa/v1/brands — confirm the data is meant to be public | `app/public/wp-content/themes/alhadbaa/functions.php:19` | Fine for public data; make sure it never returns emails, private meta or drafts. |
| I5 | info | WP_DEBUG on with errors displayed | `app/public/wp-config.php` | OK for local development; make sure it is off on the live server. |
| I6 | info | Default table prefix wp_ | `app/public/wp-config.php` | Low value hardening; only change on new installs. |
| I7 | info | No screenshot.png | `app/public/wp-content/themes/alhadbaa` |  |

## Checks

| Check | Area | Status | Findings | Notes |
|---|---|---|---:|---|
| `code.php-lint` | code | ❌ failed | 1 | 6 PHP file(s) linted |
| `code.phpcs` | code | ❌ failed | 42 | 21 issue(s) auto-fixable with phpcbf |
| `code.phpstan` | code | ❌ failed | 1 |  |
| `code.eslint` | code | ❌ failed | 3 |  |
| `code.stylelint` | code | ❌ failed | 1 |  |
| `security.wp-patterns` | security | ❌ failed | 9 | Heuristic scanner: confirm each finding by reading the code before fixing. |
| `security.secrets` | security | ❌ failed | 1 |  |
| `security.wp-config` | security | ❌ failed | 3 |  |
| `security.semgrep` | security | ❌ failed | 2 |  |
| `wordpress.theme` | wordpress | ❌ failed | 8 |  |
| `wordpress.plugin` | wordpress | ❌ failed | 3 |  |
| `wordpress.blocks` | wordpress | ❌ failed | 3 |  |
| `wordpress.vulnerabilities` | dependencies | ⏭️ skipped | 0 | vulnerability database unreachable (19 lookups failed) |
| `wordpress.wporg-status` | dependencies | ⏭️ skipped | 0 | wordpress.org API unreachable |

## Not tested (skipped or errored)

| Check | Reason | How to enable |
|---|---|---|
| `wordpress.vulnerabilities` | vulnerability database unreachable (19 lookups failed) | Check internet access to www.wpvulnerability.net |
| `wordpress.wporg-status` | wordpress.org API unreachable | Check internet access |

## Environment

```
WordPress 7.2-RC1-65566 at /home/claude/fixture/site/app/public (LocalWP site "site")
wp-config: WP_DEBUG=true, WP_DEBUG_LOG=unset, WP_ENVIRONMENT_TYPE=unset, table_prefix=wp_
Themes (17): alhadbaa@1.0.0 [custom?], ipsum@1.0 [block theme], twentyeleven@5.2, twentyfifteen@4.3, twentyfourteen@4.6, twentynineteen@3.4, twentyseventeen@4.2, twentysixteen@3.9, twentyten@4.7, twentythirteen@4.7, twentytwelve@4.9, twentytwenty@3.3, twentytwentyfive@1.5 [block theme], twentytwentyfour@1.6 [block theme], twentytwentyone@2.9, twentytwentythree@1.7 [block theme], twentytwentytwo@2.2 [block theme]
Plugins (3): alhadbaa-core@0.1 [custom?], hello@1.7.2, sqlite-database-integration@3.1.3
Custom blocks: alhadbaa/brand-card
Drop-ins: db.php
debug.log present: /home/claude/fixture/site/app/public/wp-content/debug.log
Custom code scanned: theme:alhadbaa, plugin:alhadbaa-core
Tools: php=8.3.6, semgrep=1.185.0
Node v22.23.4 on linux
```
