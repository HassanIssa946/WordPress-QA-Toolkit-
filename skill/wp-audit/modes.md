# /wp-audit — mode and report details

Read this only when you need detail beyond SKILL.md.

## Report fields worth knowing (report.json, schemaVersion 2)

- `verdict.status`: PASS / FAIL / INCOMPLETE. `verdict.incomplete[]` explains why a PASS can't be claimed.
- `coverageSummary`: applicable, executed, passed, failed, skipped, errored and notApplicable checks, plus
  filesInspected and urlsInspected. Quote these when the user asks "what was tested".
- `diff`: comparison with the previous run of the same mode.
  - `diff.baselineReset = true` means the previous report used an older format, so nothing is new or resolved this
    time. Say so; don't report every finding as new.
  - `diff.notRetested[].why` explains why an item could not be confirmed as fixed. Treat it as still open.
- `findings[].retest` (`new` / `still-open`) and `findings[].firstSeen` (run ID).
- `approvals[]`: every safety-gate decision. `needsApproval[]`: tests that only lack `--approve`.
  Refused items list their reasons (host not allowlisted, production, limits …). Explain them; don't try to work
  around them.

## Modes

| Mode | What runs | Notes |
|---|---|---|
| quick | code + static security + theme/plugin/block checks | `--changed` limits to git-changed files |
| code | php-lint, PHPCS/WPCS, PHPStan, ESLint, Stylelint | |
| security | static security, vulnerable components, WP-CLI hardening, TLS/headers/exposure | |
| wordpress | themes, plugins, blocks, updates, checksums, settings | needs WP-CLI + DB for wpcli.* |
| infrastructure | DNS, SPF/DMARC, TLS, redirects, headers, exposed files, timing | uses publicSite.url |
| backend | REST (custom routes, unauthenticated GET, p95), write probes, DB health, WP-Cron, debug.log, PHPUnit | see below |
| stack | inventory + status per component, compatibility, local/production drift, client IP behind a CDN, composer/npm audit, upgrade plan | see below |
| frontend | Playwright + axe per page × viewport, links, visual regression, e2e specs, block editor (sandbox, --approve) | see below |
| performance | Lighthouse (lab), caching/compression headers, cached nonces | see below |
| seo | robots, sitemaps, title/description/canonical/H1/lang/noindex/hreflang/JSON-LD | local + production (GET) |
| scalability | k6 smoke/load/stress, GET only, ≤ 50 VUs / 10 min (sandbox, --approve) | not part of full |
| full | everything except load testing (ZAP and the editor test still need --approve) | |

Modes not listed here are not built yet. The report shows them as "planned — not tested".

## backend

- `backend.rest`: only routes in namespaces your code registers (`register_rest_route`). Unauthenticated GET only.
  A public route is **info** ("confirm the data is meant to be public"), not a vulnerability. Routes with required
  args or path parameters are skipped unless `backend.restExamples` gives an example. Write routes are listed,
  never called.
- `backend.rest-latency`: p50/p95 over `backend.restSamples` requests. On local sites it is a lab number, not
  production.
- `backend.write-probes`: only routes in `safety.allowedWriteEndpoints`, only with `--approve` on an allowlisted
  non-production host (use the sandbox). A 2xx without login is **high**.
- `backend.db-health`: read-only SELECTs through `$wpdb` (enforced by `readOnlySql`): autoload size, expired
  transients, revisions, non-InnoDB tables. `backend.cron`: overdue events (low on local sites, where WP-Cron only
  runs on visits).
- `backend.php-log`: debug.log grouped by message. Fatal = high; warnings in your code = medium; deprecations = low;
  third-party/core noise is one step lower and grouped. Evidence is redacted.
- `backend.phpunit`: only with `backend.phpunit.enabled` and a test DB that differs from the site DB.

## stack

- Statuses: CURRENT, UPDATE AVAILABLE, SECURITY UPDATE REQUIRED, END OF LIFE, INCOMPATIBLE, UNKNOWN.
  "Not the latest" is UPDATE AVAILABLE (low), never a security problem by itself. UNKNOWN means a lookup failed or
  there is no public data (custom code, a server that hides its version). Never present UNKNOWN as current.
- `where` tells whose problem it is: `site` (core/plugins/themes, shipped to production), `local` (LocalWP's
  PHP/DB/nginx, low severity), `production` (seen in public headers), `tool` (Node, npm, Composer, WP-CLI).
- The report's "Stack inventory" section has the table and the upgrade plan (security → PHP/DB → core → plugins →
  build tools); `sections[].data.items[].sources` cites each source URL and fetch date.
- `stack.ratelimit-remote-addr` is a heuristic: confirm what REMOTE_ADDR holds on production before calling it
  a bug. Never suggest trusting X-Forwarded-For as sent.
- Never install or upgrade anything yourself. Propose the plan; the user applies it on staging first.

## frontend / performance / seo / load / ZAP

- axe impact → severity: critical → high, serious → medium, moderate → low, minor → info.
- `frontend.visual` is **skipped** until baselines exist. Show the user the screenshots in the report's
  `artifacts/visual` folder; only after a yes run `baselines update --confirm`. Never update baselines to make a diff go away.
- `frontend.block-editor` uses a temporary draft and always deletes it. `editor.leftover-draft` (high) means the
  user must delete it by hand.
- Lighthouse on a local site gives lab numbers ("lab, local — not production"). Scores are Lighthouse's own output;
  findings come only from the LCP/CLS/TBT thresholds.
- Caching: no cache headers = "insufficient evidence", never "cache is off".
- `cache.nonce`: "confirmed" = the cached copy was older than half the nonce lifetime when fetched; "likely" = cache
  HIT but its age/TTL is not visible. Never paste nonce values.
- noindex and robots "Disallow: /" are errors only on production; on local/staging they are info.
- When the local site is down, caching/SEO/cached-nonce still check production (GET) but are marked skipped:
  report INCOMPLETE and say the local part was not tested.
- k6 and ZAP on local machines describe the machine, not production capacity. ZAP without Docker is "not run" —
  never say the site passed a ZAP scan.
