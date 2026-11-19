# WordPress QA Toolkit — V2 completion report

Date: 2026-11-19 · Status: **RELEASE READY — v2.0.0** (version bumped in `package.json`; git commit and tag are prepared in §10 for the maintainer to run)

## 1. Summary

| | |
|---|---|
| Modules | 13 (code, security, wordpress, wpcli, infrastructure, backend, stack, dependencies, frontend, performance, seo, scalability, dast) |
| Modes | quick, security, wordpress, code, infrastructure, backend, stack, frontend, performance, seo, scalability, dast, full (+ fix, retest, baselines) |
| Automated tests | **292 / 292 pass**, 0 skipped, 0 cancelled, 65 suites (run after the version bump) |
| Real tools wired in | PHPCS/WPCS, PHPStan, ESLint, Stylelint, WP-CLI, WPVulnerability, Playwright 1.65.1 + Chromium, axe-core 4.14.0, Lighthouse 13.6.0, k6 2.4.0, Docker 29.9.3 + OWASP ZAP 2.16.1 (`ghcr.io/zaproxy/zaproxy:2.16.1`, digest `sha256:7840969c7c9f…`) |
| Sandbox execution tests (test.local) | editor round trip ✅ · k6 smoke ✅ · ZAP baseline (corrected code) ✅ |
| Al-Hadbaa read-only audit | ✅ complete: coverage 87 % (41/47), 0 toolkit errors; site verdict FAIL on real site findings |
| Optional, not installed | Semgrep; Plugin Check / Theme Check plugins |

## 2. Implemented capabilities per milestone

| Milestone | Status | What exists |
|---|---|---|
| M0 fixes | Done | Strict `--approve` parsing; `init` leaves `safety.allowedHosts` empty; 5xx = site not reachable → INCOMPLETE; advisory-ID collision fixed; WP-CLI "no plugins" no longer an error |
| M1 frontend | Done, sandbox-validated | Playwright + axe per page × desktop/mobile; internal link check (never requests logout/admin/nonce/cart links); visual regression against approved baselines (`baselines update --confirm`, never automatic); e2e specs; block-editor round trip (approval-gated, credentials from env vars, draft always deleted and verified); fixture block `sandbox/wpqa-fixture-blocks` |
| M2 backend | Done (unchanged) | REST/AJAX/cron/debug.log/DB health checks |
| M3 performance + SEO | Done, validated on Al-Hadbaa | Lighthouse (lab label on local), cache/CDN evidence, static TTL, compression, cached-nonce detection (values never printed); robots, sitemaps, page SEO; passive production GETs; local site down → INCOMPLETE |
| M4 stack | Done, validated on Al-Hadbaa | Inventory, support/EOL, compatibility, drift local vs production, grouped security findings, client-IP heuristic, upgrade plan; composer + npm audit |
| M5 load + DAST | Done, sandbox-validated | k6 smoke/load/stress (GET only, ≤ 50 VUs / 600 s, approval + allowlist); ZAP baseline via Docker with pinned image; active scan only with `dast.active` (not run) |

## 3. Test results

`npm test`: **292 tests, 292 pass, 0 fail, 0 skipped, 0 cancelled** (65 suites).

| Area | Must-detect fixture | Clean fixture |
|---|---|---|
| M1 | `tests/fixtures/frontend/bad.html` (real Chromium) — all rules fire | `good.html` — 0 findings |
| M1 editor | fake WordPress + real Chromium (`tests/editor-cleanup.test.mjs`): save error, closed tab, DELETE blocked (405), session expired, nonce rejected, post only trashed, deletion refused → draft deleted, or leftover reported with the reason | success: all 6 steps, attributes kept, block rendered, draft deleted |
| M3 | `bad-page.html` + `lighthouse-slow.json` — cached nonce, noindex, robots, page SEO, Lighthouse | `good-page.html` + `lighthouse-fast.json` — 0 findings |
| M4 | `stack-plugin` fixture — all detected | clean site — 0 findings |
| M5 | refusal matrix for k6 and ZAP (no approval, `--approve=yes`, host not allowed, production host / www / production IP, limits, stress, invalid duration, unpinned image, no Docker); ZAP result with 4 alerts from one plugin + ZAP self-alert; no ZAP JSON → error | real k6 smoke against 127.0.0.1 |
| Infra | DNS outage / ENOTFOUND / partial failure / EAI_AGAIN → skipped | working DNS without SPF/DMARC → findings; valid TLS → 0 findings |
| History | finding skipped in 2 runs is carried, then resolved / still open when re-tested | — |

## 4. Defects found during validation (all fixed, each with regression tests)

| Defect | Evidence | Fix |
|---|---|---|
| Editor test left draft #6 on test.local | Retest log: `DELETE: HTTP 405` — test.local's server rejects the DELETE method; the old cleanup sent only DELETE and discarded the answer | Cleanup through the browser context; nonce check; re-login on rejected session/nonce; POST + `X-HTTP-Method-Override` fallback; re-delete if trashed; 404 verification; attempts logged (status + WP code, never the nonce). Retest: draft 9 deleted via the fallback, verified 404 |
| DNS failures on this machine became findings | Al-Hadbaa run: critical "HTTPS not available (EAI_AGAIN)", "No SPF", "No DMARC" while DNS was failing | `infra.tls` / `infra.email-dns` skipped unless DNS demonstrably answered; real problems still reported |
| ZAP alerts merged / mislabelled | 26 ZAP alert types shown as 23 findings; "1 URL inspected" (ZAP covered 50); "ZAP is Out of Date" as a site finding | Keyed by ZAP `alertRef`; scope = ZAP's URLs; scanner self-alerts are notes. Corrected run: 25 = 25 = 25 |
| "Not re-tested" findings dropped from history | Al-Hadbaa final run showed "Resolved 0, New 9": the false TLS critical was never marked resolved; SPF/DMARC/MX re-appeared as "new" | Run comparison carries "not re-tested" items until a run re-tests them. Recomputed from the saved reports: **resolved 1** (the false TLS critical), still open 105, new 6, not re-tested 0 |

The stored Markdown of Al-Hadbaa run `20261119-162553-full` still shows the old comparison line (written before the fix). Its findings, verdict and coverage are unaffected; the next run will compare correctly.

## 5. Runs on authorized targets

### Sandbox `test.local` (approval-gated runs, started by the user)

| Run | Result |
|---|---|
| `frontend --approve` (20261119-160532) | **PASS**, coverage 85 %. `frontend.block-editor` passed: login → editor → insert → save → reload → preview; `wpqa-fixture/notice` attributes kept, block valid, rendered; draft 9 deleted and verified (404). `frontend.visual` skipped (no approved baselines — by design) |
| `scalability --profile smoke --approve` (20261119-160841) | **PASS**, coverage 100 %, 0 findings: 2 VUs, 30 s, 28 requests, p95 97 ms, 0 % errors (this machine, not production capacity) |
| `dast --approve` (20261119-162116, corrected code) | **PASS** (failOn=high), coverage 100 %: ZAP 2.16.1 baseline (passive); 25 alert types (0 high, 8 medium, 8 low, 9 info) on 51 URLs; the four CSP alerts are separate findings; "ZAP is Out of Date" is a note. Active scan N/A. Describes the blank LocalWP sandbox, not Al-Hadbaa |
| `doctor` | All OK except optional Semgrep / Plugin Check; Docker 29.9.3; container reaches `test.local` via `--add-host test.local:host-gateway`; report mount writable |

### Al-Hadbaa (read-only; local `al-hadbaa.local`, production `alhadbadental.com`)

`safety.allowedHosts` is empty in Al-Hadbaa's `wpqa.config.json`; the safety gate refused the editor test and ZAP there. No application file, database or setting of the site was changed.

Final `full` run (20261119-162553): coverage **87 %** (41/47 applicable), **0 toolkit errors**, no incomplete reasons. **Site verdict: FAIL** — 0 critical / 20 high / 28 medium / 41 low / 22 info, all actual website findings.

- DNS-dependent checks now executed: `infra.dns` (A records, NS apollo/athena.dns-parking.com), `infra.email-dns`, `infra.tls` (passed: TLS 1.3, Let's Encrypt, expires 2027-02-03, h2), `infra.headers`, `infra.timing` (passed: TTFB 233 ms), `infra.redirects` (passed).
- The false critical from the DNS-affected run is resolved (TLS re-tested and fine).

## 6. Security findings detail (open until retested)

### WordPress 7.1.4 core — 19 advisories vs 20 items in the 7.1.5 release

Source of truth: [WordPress 7.1.5 Security Release](https://wordpress.org/news/2026/11/wordpress-7-1-5-release/) (2026-11-18) lists **20 items = 18 vulnerability fixes + 2 hardening changes** (JSON media-type regex; removal of the Imgur embed). Hardening items have no advisory. WPVulnerability (data from Wordfence Intelligence) has **19 records**: the 18 fixes, with "Author+ authorization bypass via comment editing" published as two advisories (#1 and #4 below). So 18 − 1 + 2 = 19, and 19 + 2 hardening − 1 split = 20. Every record is fixed in 7.1.5. Local and production both run 7.1.4, so these are **production vulnerabilities**, not only local ones. The upgrade is your decision; the toolkit never upgrades.

Severity: WPVulnerability gives no CVSS for these records, so the toolkit rates them high by default (backlog S3). No CVE IDs were published in the source data at the time of the run.

| # | Advisory (Wordfence) | ID |
|---|---|---|
| 1 | [Author+ Private Note Publication via Admin Comment Type Change](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-690-714-authenticated-author-private-note-publication-via-admin-comment-type-change) | e4a2927eea8d68cc99a5fa288dabb2972ce6adba |
| 2 | [Administrator+ Privilege Escalation to Super Administrator via Customizer Menu Preview](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-430-714-authenticated-administrator-privilege-escalation-to-super-administrator-via-customizer-menu-preview) | 7431b5d9dbde5e28a2a5101a46300d27af3da047 |
| 3 | [Unauthenticated Private Taxonomy Term Disclosure via REST Search](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-560-714-unauthenticated-private-taxonomy-term-disclosure-via-rest-search) | 42c5b340a9407efa1d08c5fb12f0e2b598d7e469 |
| 4 | [Author+ Unauthorized Comment Move via Admin Editing](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-420-714-authenticated-author-unauthorized-comment-move-via-admin-editing) | d4864c18416aad2b18700e246266764084500201 |
| 5 | [Author+ User Email Disclosure via REST Comment Author Refresh](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-470-714-authenticated-author-user-email-disclosure-via-rest-comment-author-refresh) | a30c199bab2e0ed6101eecc44efde8eea0633e55 |
| 6 | [Subscriber+ Private Comment and Commenter Information Disclosure via XML-RPC wp.getComments](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-440-714-authenticated-subscriber-private-comment-and-commenter-information-disclosure-via-xml-rpc-wpgetcomments) | cfa9a1ef3218017a25ef130de7f7a180fc124d2a |
| 7 | [Unauthenticated SQL Injection via Nested WP_Meta_Query Relation](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-410-714-unauthenticated-sql-injection-via-nested-wp-meta-query-relation) | 68a20b5df42074c7832e7d96a3c2995344a258f7 |
| 8 | [Administrator+ Stored XSS via Customizer Preview](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-470-714-authenticated-administrator-stored-cross-site-scripting-via-customizer-preview) | 17fdf3455dbf6182d7155e62fb57d7da01f1fbd2 |
| 9 | [Editor+ Network User Enumeration via REST Post Author Assignment](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-470-714-authenticated-editor-network-user-enumeration-via-rest-post-author-assignment) | b338c873ef0db1a6be5bc7d2ea70471f61b5907a |
| 10 | [Unauthenticated Reflected XSS via Legacy Media Popup and REST Route](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-440-714-unauthenticated-reflected-cross-site-scripting-via-legacy-media-popup-and-rest-route) | 8088e95794ce1b9f0387e67a6b7e075995365a11 |
| 11 | [Contributor+ Stored XSS via Comment Date Format](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-600-714-authenticated-contributor-stored-cross-site-scripting-via-comment-date-format) | bafa7c65b6568b6c50d418660b83729067d222be |
| 12 | [Unauthenticated XSS via Interactivity API Store Namespace](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-650-714-unauthenticated-cross-site-scripting-via-interactivity-api-store-namespace) | bbf58eaa7c79fca39f3b9a49d2b638a4c576017b |
| 13 | [Administrator+ SQL Injection via Customizer Front-Page Preview](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-340-714-authenticated-administrator-sql-injection-via-customizer-front-page-preview) | 93c512c799342c4dcc6be8bb43adcbc0d3cb9f58 |
| 14 | [Contributor+ Stored XSS via oEmbed Provider Scripts](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-480-714-authenticated-contributor-stored-cross-site-scripting-via-oembed-provider-scripts) | a90b4388c6dc0e9cc1eb00df76f0befaf79c5702 |
| 15 | [Unauthenticated DoS via Batched XML-RPC Pingbacks](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-150-714-unauthenticated-denial-of-service-via-batched-xml-rpc-pingbacks) | 933b901aea8bd719640003030968e9bfc7a95e95 |
| 16 | [Contributor+ Stored XSS via File Transform Filename](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-590-714-authenticated-contributor-stored-cross-site-scripting-via-file-transform-filename) | f8ab1cacf542e1f9824c794e903640eb2fc04327 |
| 17 | [Unauthenticated Stored XSS via Openverse Image Metadata](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-620-714-unauthenticated-stored-cross-site-scripting-via-openverse-image-metadata) | 4d4a9075d64b88c46f61fb09bea0ebca9d81d1c7 |
| 18 | [Unauthenticated Stored XSS via Escaped Shortcode Attributes in Comments](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-250-714-unauthenticated-stored-cross-site-scripting-via-escaped-shortcode-attributes-in-comments) | 3cf373cf23f2c82d4dee40728cb0230f463e5ab5 |
| 19 | [CSRF to Administrator Account Creation via Template Part Entity Key](https://www.wordfence.com/threat-intel/vulnerabilities/wordpress-core/wordpress-core-590-714-cross-site-request-forgery-to-administrator-account-creation-via-template-part-entity-key) | 4af09f0bd740262b8c524774f180baaa2615e943 |

Data source: `https://www.wpvulnerability.net/core/7.1.4/` (all 19 records share one record UUID; the toolkit now keys them by the source advisory ID).


### Local vs production risk (Al-Hadbaa, final run)

| Finding | Where | Severity | Note |
|---|---|---|---|
| WordPress 7.1.4 (19 advisories) + 7.1.5 update | **production + local** | high | Fixed in 7.1.5; upgrading is the site owner's decision (the toolkit never upgrades) |
| No SPF record, no DMARC record (and no MX) | **production** | medium (MX info) | Confirmed by the toolkit with working DNS; contact-form mail may be spoofed or land in spam |
| `xmlrpc.php` enabled | **production** | medium | Brute-force amplification; disable if not used |
| Cached nonce on `/contact-us/` and `/ar/contact/` | **production** | medium (likely) | Exclude these pages from cache or fetch the nonce via AJAX |
| REMOTE_ADDR rate limit behind Hostinger CDN (`alhadbaa-core` `includes/rest.php:81`) | **production** (heuristic) | medium | Confirm from production logs |
| No CAA record; `X-Powered-By: PHP/8.3.36`; WordPress version in generator; `readme.html` accessible; usernames via `?author=1` | **production** | low | Information disclosure / hardening |
| PHP drift: local 8.2.29 vs production 8.3.36 | both | medium | |
| PHP 8.2 EOL 2026-12-31; LocalWP PHP / MySQL / nginx / Node advisories | local only | low | Developer machine, not internet-facing |
| 50 npm advisories in build-only dependencies | build / CI only | medium (summary) | Not shipped to visitors (backlog S5) |
| Hostinger nameservers returned SERVFAIL / timeouts earlier today | production | manual observation | Not a toolkit finding yet (backlog D2) |

## 7. The six skipped checks in the final Al-Hadbaa run

| Check | Why skipped | Release requirement? |
|---|---|---|
| `security.semgrep` | Semgrep not installed | **Optional** — extra rule engine; `doctor` lists it as optional. The built-in security checks ran |
| `wpcli.plugin-check` | Plugin Check plugin not active | **Optional** — needs a plugin installed on the site; installing it on Al-Hadbaa would modify the site (not allowed) |
| `wpcli.theme-check` | Theme Check plugin not active | **Optional** — same reason |
| `frontend.visual` | No approved baselines (first run takes the screenshots) | **Not required** — by design it compares against user-approved baselines; the capability is covered by real-Chromium tests (diff detected / identical / masks) |
| `frontend.block-editor` | Safety gate: no approval, host not allowlisted | **Correct refusal** — Al-Hadbaa is read-only; the editor test is validated on test.local |
| `dast.zap-baseline` | Safety gate: no approval, host not allowlisted | **Correct refusal** — Al-Hadbaa is read-only; ZAP is validated on test.local |

None of them hides a mandatory check; each is reported as "not tested", never as passed. The six N/A checks (composer audit, e2e, REST latency, write probes, PHPUnit, ZAP active scan) have nothing to run on this site or are disabled by design.

## 8. Release criteria (verified against the saved reports)

| Criterion | Evidence | Status |
|---|---|---|
| All modules implemented; M0/M2/M4 preserved | §2; full suite | ✅ |
| Full automated suite passes | 292 / 292, 0 skipped | ✅ |
| Must-detect + clean fixture per milestone | §3 | ✅ |
| Docs (README, SKILL.md < 150 lines, modes.md) | SKILL.md 100 lines | ✅ |
| Sandbox editor round trip (approved) | 20261119-160532-frontend | ✅ |
| Sandbox k6 smoke (approved) | 20261119-160841-scalability | ✅ |
| Sandbox ZAP baseline on final code (approved, pinned image) | 20261119-162116-dast | ✅ |
| Al-Hadbaa read-only `full` audit complete (coverage ≥ 80 %, 0 toolkit errors) | 20261119-162553-full: 87 %, 0 errors | ✅ |
| Al-Hadbaa never modified; intrusive tests refused there | empty allowlist; safety gate refusals in the report | ✅ |
| No unrun check counted as passed; no misleading results | 4 such defects found and fixed (§4) | ✅ |
| No secrets in output | Saved reports scanned for nonces, auth cookies and passwords: 0 hits | ✅ |

### Verdict: **READY — v2.0.0 can be tagged.**

No critical toolkit defects or unsafe behaviour remain known. Non-blocking improvements are in the backlog.

## 9. Improvement opportunities

See [V2-BACKLOG.md](V2-BACKLOG.md): stack S1–S10, backend B1–B2, frontend/performance/SEO F1–F5, load/DAST L1–L4, data quality D1–D2. No optimisation work has been started.

## 10. Release preparation

Done in the working tree: `package.json` / `package-lock.json` → 2.0.0, user agent `wpqa-toolkit/2.0`, README title "(V2)".

Git (to be run by the maintainer; nothing has been committed or tagged):

- V1 is commit `1387f7c` ("Initial commit") on `main`; no tags exist yet. Tagging it `v1.0.0` (and a `v1` branch) preserves it.
- V1 tracked `node_modules/` (2,378 files) and `vendor/` (2,780 files). The new `.gitignore` excludes them, but tracked files stay tracked; untracking them keeps ~215 MB of installed packages out of the V2 commit (users run `npm install` and `composer install`, as the README says). V1 keeps its copies under the `v1.0.0` tag.
