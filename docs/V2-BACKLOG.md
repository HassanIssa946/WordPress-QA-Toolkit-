# V2 improvement backlog

Non-blocking improvements, possible false positives and ideas, collected while finishing V2.
Workflow: complete V2 → integration testing → evaluate the whole toolkit → prioritise this list → improve modules one
by one → final validation. Nothing here blocks V2; blockers are fixed immediately and listed under "Fixed during V2".

Priority: **P1** = affects how much a reader can trust a result · **P2** = accuracy/usability · **P3** = polish/ideas.

## Stack (M4)

| # | Pri | Item |
|---|---|---|
| S1 | P1 | **Map advisories to the vendor's release notes.** Example verified on 2026-11-19: WordPress 7.1.5's announcement lists 20 items = 18 vulnerability fixes + 2 hardening changes (JSON media-type regex, Imgur embed removal). WPVulnerability (Wordfence data) lists 19 advisories: the 18 fixes, with "Author+ authorization bypass via comment editing" split into two records (private-note publication via comment type change; unauthorized comment move). Show this mapping (and hardening items with no advisory) in the report. |
| S2 | P1 | **List every advisory ID and source in the report**, not only in report.json (`sections[].data.items[].vulns`). Markdown currently shows the first 8 titles. Add Wordfence IDs + links, CVEs when present. |
| S3 | P1 | **Unrated severity.** WPVulnerability core records carry no CVSS (`impact: []`); the toolkit defaults them to high. Now flagged in data (`severityRated: false`); show it in the report text and derive severity from the advisory title (unauthenticated SQLi/RCE → critical/high; Contributor+ XSS → medium) instead of a flat default. |
| S4 | P1 | **Production exposure column.** Separate "local development risk" from "production vulnerability" explicitly per row: site code (core/plugins/themes) → production affected when production runs the same version (observed via asset `?ver=`/generator, else "likely, not observed"); LocalWP PHP/nginx/MySQL → local only, with production's own version if visible. |
| S5 | P1 | **npm build-only advisories by real exposure**, not only "ships or not": classify by CWE/title into dev-server exposure (webpack-dev-server, http-proxy — reachable on the network while `npm start` runs), untrusted-input processing (Babel/PostCSS/Terser parsers — only exploitable when building attacker-controlled code, e.g. CI building fork PRs), DoS/ReDoS (build slowdown only), install-time/malware (always critical). Detect CI (`.github/workflows`, etc.) and whether it builds untrusted PRs. |
| S6 | P2 | Findings whose ID scheme changes between toolkit versions (e.g. per-advisory → grouped per component) show as "resolved" + "new" in the next diff. Add a per-check version so such checks are reported as "re-baselined — kept open until retested" instead of "resolved". |
| S7 | P2 | `stack.ratelimit-remote-addr` is heuristic: add a one-shot production probe (documented, opt-in) or instructions to read REMOTE_ADDR in production logs, and lower to info when the host is known to restore client IPs. |
| S8 | P2 | PHP extensions are read from the CLI binary; on non-LocalWP hosts the web SAPI may differ. Read them through a web request (`wp eval` over HTTP is not possible read-only) or document the limitation in the report. |
| S9 | P3 | endoflife.date lags (listed WordPress 7.1.4 as latest on 2026-11-19 while api.wordpress.org had 7.1.5). Already using api.wordpress.org for "latest"; consider the same for other products where an official feed exists. |
| S10 | P3 | `npm audit` takes ~80 s on a cold cache for a large lock file; run the two audits in parallel or reuse one result with `--omit=dev` filtering via the lock file's `dev` flags. |

## Backend (M2)

| # | Pri | Item |
|---|---|---|
| B1 | P2 | Routes needing parameters are skipped unless `backend.restExamples` is configured — suggest example values from the route's `args` schema (enum/default) automatically. |
| B2 | P3 | debug.log "connection refused" bursts (database stopped) could be grouped as an environment event rather than a PHP warning. |

## Frontend / performance / SEO (M1, M3)

| # | Pri | Item |
|---|---|---|
| F1 | P1 | Lighthouse runs only on the audited (local) site. Add an opt-in production run (Lighthouse is read-only, but it is heavy) or PageSpeed Insights API data, clearly labelled field vs lab. |
| F2 | P2 | `cache.nonce` confidence depends on fetch timing: a page fetched shortly after the cache was refreshed shows "likely", and the same page later "confirmed". Report the cache TTL / age source next to the confidence, and consider a second fetch. |
| F3 | P2 | Production SEO/caching checks read only `site.pages` + sitemap URLs (max 20). Add a crawl of internal links (same cap) so pages missing from the sitemap are covered. |
| F4 | P2 | `frontend.visual` needs the user to approve baselines first; add a side-by-side HTML viewer (baseline / current / diff) to make that review easier. |
| F5 | P3 | axe runs with default rules; let the config pick WCAG level (2.1 AA / 2.2 AA) and list the rule set in the report. |

## Load / DAST (M5)

| # | Pri | Item |
|---|---|---|
| L1 | **Release blocker** | OWASP ZAP needs Docker (not installed). `dast.zap-baseline` is reported "not run". Install Docker Desktop (user approval needed), then run the baseline on the sandbox with `--approve`. |
| L2 | P2 | `dast.zap-full` reports "site not reachable" instead of N/A when the site is down and `dast.active` is off. Should be N/A first. |
| L3 | P2 | k6 is found via the `C:\Program Files\k6` fallback when not on PATH; document adding it to PATH and show the found path in `doctor`. (Done in doctor; README note missing.) |
| L4 | P3 | k6 smoke uses `site.pages`; add the sitemap URLs (GET only, capped) for a more realistic mix. |

## Data quality

| # | Pri | Item |
|---|---|---|
| D2 | P1 | `infra.dns` should query each authoritative nameserver directly and report SERVFAIL/timeouts as a DNS reliability finding. On 2026-11-19, alhadbadental.com's NS (apollo/athena.dns-parking.com) returned SERVFAIL/timeouts for A/TXT/MX, which made this machine's lookups fail intermittently; today that only shows up as "skipped". Also retry once before skipping. |
| D1 | P1 | WPVulnerability lists 246 advisories for MySQL 8.4.0 (sandbox, LocalWP). Plausible (Oracle CPU entries), but not verified. Check the count against Oracle's Critical Patch Update advisories and consider grouping per CPU release. |

## Fixed during V2 (blockers)

- `--approve=false` granted approval → strict flag parsing (M0).
- `init` added the site host to `safety.allowedHosts` automatically → list starts empty.
- WPVulnerability records sharing one uuid collapsed into a single finding (19 WordPress core advisories → 1) → advisory ID from the source record.
- A site answering HTTP 5xx counted as reachable → checks are skipped and the verdict is INCOMPLETE.
- Stack inventory passed with the site down / database unreachable → skipped (INCOMPLETE), components UNKNOWN.
- Core vulnerability titles showed only the version number → title from the source record.
- Run comparison dropped findings that the previous run listed as "not re-tested" (false TLS critical never shown as resolved; SPF/DMARC re-appeared as "new") → carried until a run re-tests them. Covered in `tests/compare.test.mjs`.
- ZAP alerts from one plugin were merged (26 alert types → 23 findings; four CSP alerts of 10055 became one), "URLs inspected" showed 1 instead of 50, and "ZAP is Out of Date" was a site finding → keyed by `alertRef`, scope = ZAP's URLs, scanner self-alerts are notes. Covered in `tests/load-dast.test.mjs`. Root cause of the leftover editor draft confirmed on retest: test.local answers `DELETE` with HTTP 405.
- DNS failures on the auditing machine became findings: `EAI_AGAIN` → critical "HTTPS not available", failed TXT lookups → "No SPF/DMARC record". Now `infra.tls` and `infra.email-dns` are skipped (INCOMPLETE) unless DNS demonstrably answered; real "no record" / "port 443 refused" are still reported. Covered by `tests/infra-dns.test.mjs`.
- Block-editor test left draft #6 on test.local; the cleanup error was discarded, so the exact server answer is unknown → cleanup now runs through the browser context (survives a crashed/closed page), checks the nonce, logs in again if the session or nonce is rejected, falls back to POST + `X-HTTP-Method-Override`, deletes again if the post was only trashed, and reports HTTP status + WordPress error code (never the nonce). A failed save no longer waits for the 60 s timeout. The check notes list the steps that completed. Covered by `tests/editor-cleanup.test.mjs` (real Chromium, fake WordPress).
