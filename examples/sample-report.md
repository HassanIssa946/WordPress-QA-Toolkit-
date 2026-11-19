# WordPress QA Report — Example plugin fixture

**Mode:** `quick` · **Target:** http://example.invalid (local)  
**Run:** 20261119-115102-quick · **Duration:** 14s · **Toolkit:** v1.0.0

## Verdict

❌ **FAIL** — 17 finding(s) at or above `high`

Also incomplete:
- coverage 77% (7/9 applicable checks executed) is below minCoverage 80%

> ⚠️ 2 check(s) were skipped or errored and are **not** counted as passed — see "Not tested" below.

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 6 | 11 | 4 | 4 | 0 |

## Coverage

Coverage = executed checks ÷ applicable checks. It measures how much was tested, not how good the site is.

| Area | Passed | Failed | Skipped | Errors | N/A | Coverage |
|---|---:|---:|---:|---:|---:|---:|
| Code Quality | 2 | 1 | 0 | 0 | 2 | 100% |
| Security | 1 | 2 | 1 | 0 | 0 | 75% |
| WordPress (themes, plugins, blocks) | 0 | 1 | 0 | 0 | 2 | 100% |
| Dependencies & Vulnerabilities | 0 | 0 | 1 | 0 | 1 | 0% |

Overall: **77%** (minimum 80%).

| Applicable | Executed | Passed | Failed | Skipped | Errored | N/A | Files/folders inspected | URLs inspected |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 9 | 7 | 3 | 4 | 2 | 0 | 5 | 9 | 0 |

## Findings

### Critical (6)

#### [C1] SQL injection: request data in $wpdb query without prepare()
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:19`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.sqli.unprepared` · **Confidence:** likely
- **Evidence:**

  ```
  ( "SELECT * FROM {$wpdb->posts} WHERE post_title = '" . $_GET['t'] . "'" )
  ```
- **Fix:** $wpdb->get_results( $wpdb->prepare( "SELECT … WHERE id = %d AND slug = %s", $id, $slug ) ). Use %i for identifiers (WP 6.2+).

#### [C2] REST route vf/v1/open has no permission_callback and accepts writes
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:32`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.rest.no-permission-callback` · **Confidence:** confirmed
- **Evidence:**

  ```
  ( 'vf/v1', '/open', array( 'methods' => 'POST', 'callback' => 'vf_open' ) )
  ```
- **Fix:** Add 'permission_callback' => fn() => current_user_can( 'edit_posts' ) (or the right capability). Use '__return_true' only for intentionally public read-only routes.

#### [C3] eval() used
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:71`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.rce.eval` · **Confidence:** likely
- **Evidence:**

  ```
  eval( base64_decode( $_POST['c'] ) );
  ```
- **Fix:** Remove eval(); it executes arbitrary PHP. Combined with base64_decode it is a typical backdoor signature.

#### [C4] unserialize() on request data (PHP object injection)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:76`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.objinj.unserialize` · **Confidence:** likely
- **Evidence:**

  ```
  return unserialize( $_COOKIE['d'] );
  ```
- **Fix:** Use json_decode() for client data.

#### [C5] File inclusion from request data
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:79`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.lfi.include` · **Confidence:** likely
- **Evidence:**

  ```
  // wp.lfi.include
  ```
- **Fix:** Never build include paths from input; map allowed values to fixed files.

#### [C6] Obfuscated eval — possible backdoor/malware
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:71`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.malware.obfuscated` · **Confidence:** confirmed
- **Evidence:**

  ```
  eval( base64_decode( $_POST['c'] ) );
  ```
- **Fix:** Treat the site as compromised until this file is explained; compare with a clean copy.

### High (11)

#### [H1] REST route vf/v1/closure-write allows unauthenticated writes (permission_callback always true, no nonce/capability check in the callback)
- **Where:** `wp-content/plugins/vuln-plugin/includes/rest-closure.php:9`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.rest.public-write` · **Confidence:** confirmed
- **Evidence:**

  ```
  (
  			'vf/v1',
  			'/closure-write',
  			array(
  				'methods'             => WP_REST_Server::CREATABLE,
  				'permission_callback' => '__return_true',
  				'callback'            => static function ( WP_REST_Request $req ) {
  					update_option( 'vf_closure', sanitize_text_field( (string) $req['v'] ) );
  		
  ```
- **Fix:** Check a capability, or verify a nonce in the callback (wp_verify_nonce). If it is a public form endpoint, add rate limiting, validation and spam protection.

#### [H2] REST route vf/v1/write allows unauthenticated writes (permission_callback always true, no nonce/capability check in the callback)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:34`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.rest.public-write` · **Confidence:** confirmed
- **Evidence:**

  ```
  (
  			'vf/v1',
  			'/write',
  			array(
  				'methods'             => 'POST',
  				'callback'            => 'vf_write',
  				'permission_callback' => '__return_true',
  			)
  		)
  ```
- **Fix:** Check a capability, or verify a nonce in the callback (wp_verify_nonce). If it is a public form endpoint, add rate limiting, validation and spam protection.

#### [H3] Request data printed without escaping (reflected XSS)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:11`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.xss.echo-request` · **Confidence:** likely
- **Evidence:**

  ```
  // wp.xss.echo-request
  ```
- **Fix:** Escape on output: esc_html( wp_unslash( $_GET[...] ) ), esc_attr() in attributes, esc_url() for URLs.

#### [H4] SQL query built from variables without $wpdb->prepare()
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:25`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.sqli.unprepared` · **Confidence:** heuristic
- **Evidence:**

  ```
  ( "SELECT * FROM {$wpdb->posts} WHERE ID = $id" )
  ```
- **Fix:** $wpdb->get_results( $wpdb->prepare( "SELECT … WHERE id = %d AND slug = %s", $id, $slug ) ). Use %i for identifiers (WP 6.2+).

#### [H5] Public AJAX/admin-post handler "vf_save" has no nonce check and changes data (CSRF)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:57`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.csrf.ajax-no-nonce` · **Confidence:** likely
- **Evidence:**

  ```
  add_action('wp_ajax_nopriv_vf_save', …) → vf_save()
  ```
- **Fix:** Send a nonce from the page (wp_create_nonce('action')) and call check_ajax_referer('action') first in the handler.

#### [H6] Logged-in AJAX/admin-post handler "vf_admin" has no nonce check and changes data (CSRF)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:64`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.csrf.ajax-no-nonce` · **Confidence:** likely
- **Evidence:**

  ```
  add_action('wp_ajax_vf_admin', …) → vf_admin()
  ```
- **Fix:** Send a nonce from the page (wp_create_nonce('action')) and call check_ajax_referer('action') first in the handler.

#### [H7] AJAX handler "vf_admin" changes data without current_user_can() (any logged-in user, incl. subscribers)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:64`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.authz.ajax-no-capability` · **Confidence:** likely
- **Fix:** Add if ( ! current_user_can( 'manage_options' ) ) { wp_send_json_error( null, 403 ); }

#### [H8] Shell command execution
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:86`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.rce.shell` · **Confidence:** likely
- **Evidence:**

  ```
  return shell_exec( 'ls ' . $_GET['dir'] );
  ```
- **Fix:** Avoid shell execution; if unavoidable, use escapeshellarg() on every argument and never pass request data.

#### [H9] extract() on request data (variable injection)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:91`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.extract-request` · **Confidence:** likely
- **Evidence:**

  ```
  extract( $_POST );
  ```
- **Fix:** Read the needed keys explicitly and sanitize them.

#### [H10] File/URL access built from request data (SSRF / file disclosure)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:102`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.ssrf-file` · **Confidence:** likely
- **Evidence:**

  ```
  return wp_remote_get( $_GET['url'] );
  ```
- **Fix:** Allow-list hosts/paths; use wp_safe_remote_get().

#### [H11] AWS access key in source code
- **Where:** `wp-content/plugins/vuln-plugin/includes/generated-secret.php:3`
- **Check:** `security.secrets` · **Tool:** wpqa scanner · **Rule:** `secret.aws-access-key` · **Confidence:** likely
- **Evidence:**

  ```
  $vf_aws_key = '•••redacted•••';
  ```
- **Fix:** Move it to wp-config.php constants or environment variables, rotate the key, and purge it from git history.

### Medium (4)

#### [M1] Parameter #2 $callback of function add_action expects callable(): mixed, 'vf_init' given.
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:9`
- **Check:** `code.phpstan` · **Tool:** PHPStan · **Rule:** `argument.type` · **Confidence:** confirmed
- **Fix:** Fix the type/logic error or add a precise @var/@param annotation if PHPStan lacks context.

#### [M2] Redirect target taken from request (open redirect)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:96`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.open-redirect` · **Confidence:** likely
- **Evidence:**

  ```
  wp_redirect( $_GET['to'] );
  ```
- **Fix:** Use wp_safe_redirect() + wp_validate_redirect().

#### [M3] Raw move_uploaded_file() (bypasses WordPress upload checks)
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:107`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.upload.raw` · **Confidence:** likely
- **Evidence:**

  ```
  move_uploaded_file( $_FILES['f']['tmp_name'], '/tmp/upload' );
  ```
- **Fix:** Use wp_handle_upload()/media_handle_upload() with an allowed mime list and a capability check.

#### [M4] POST form without a WordPress nonce field
- **Where:** `wp-content/plugins/vuln-plugin/vuln-plugin.php:114`
- **Check:** `security.wp-patterns` · **Tool:** wpqa scanner · **Rule:** `wp.csrf.form-no-nonce` · **Confidence:** heuristic
- **Evidence:**

  ```
  <form method="post" action="">
  ```
- **Fix:** Add wp_nonce_field( 'my_action', 'my_nonce' ) and verify it in the handler.

### Low & info (4)

| Ref | Sev | Finding | Where | Fix |
|---|---|---|---|---|
| L1 | low | Plugin file executes code without an ABSPATH guard | `wp-content/plugins/vuln-plugin/includes/rest-closure.php:1` | Add at the top: defined( 'ABSPATH' ) \|\| exit; |
| L2 | low | Plugin file executes code without an ABSPATH guard | `wp-content/plugins/vuln-plugin/vuln-plugin.php:1` | Add at the top: defined( 'ABSPATH' ) \|\| exit; |
| L3 | low | Plugin header missing "Requires PHP" (vuln-plugin) | `wp-content/plugins/vuln-plugin` |  |
| L4 | low | Custom plugin vuln-plugin has no "Update URI" header | `wp-content/plugins/vuln-plugin` | Add "Update URI: false" so a same-named wordpress.org plugin can never overwrite it via updates. |

## Checks

| Check | Area | Status | Findings | Notes |
|---|---|---|---:|---|
| `code.php-lint` | code | ✅ passed | 0 | 3 PHP file(s) linted |
| `code.phpcs` | code | ✅ passed | 0 |  |
| `code.phpstan` | code | ❌ failed | 1 |  |
| `code.eslint` | code | ➖ n/a | 0 | no JavaScript source files in scope |
| `code.stylelint` | code | ➖ n/a | 0 | no CSS source files in scope |
| `security.wp-patterns` | security | ❌ failed | 21 | Heuristic scanner: confirm each finding by reading the code before fixing. |
| `security.secrets` | security | ❌ failed | 1 |  |
| `security.wp-config` | security | ✅ passed | 0 |  |
| `security.semgrep` | security | ⏭️ skipped | 0 | tool not available: semgrep |
| `wordpress.theme` | wordpress | ➖ n/a | 0 | no custom theme configured |
| `wordpress.plugin` | wordpress | ❌ failed | 3 |  |
| `wordpress.blocks` | wordpress | ➖ n/a | 0 | no block.json in custom code |
| `wordpress.vulnerabilities` | dependencies | ⏭️ skipped | 0 | disabled (vulnerabilityLookup: false) |
| `wordpress.wporg-status` | dependencies | ➖ n/a | 0 | no wordpress.org components detected |

## Not tested (skipped or errored)

| Check | Reason | How to enable |
|---|---|---|
| `security.semgrep` | tool not available: semgrep | pip install semgrep (or run inside WSL/Docker). |
| `wordpress.vulnerabilities` | disabled (vulnerabilityLookup: false) |  |

## Environment

```
WordPress 6.8.1 at <toolkit>\tests\fixtures\site
wp-config: WP_DEBUG=false, WP_DEBUG_LOG=unset, WP_ENVIRONMENT_TYPE=unset, table_prefix=sf_
Themes (0): 
Plugins (2): safe-plugin@1.0.0 [custom?], vuln-plugin@1.0.0 [custom?]
Custom blocks: safe-fixture/card
Custom code scanned: plugin:vuln-plugin
Tools: php=8.2.29, semgrep=unavailable
Node v24.18.0 on win32
```
