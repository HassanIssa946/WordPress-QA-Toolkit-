---
name: wp-audit
description: Audit a WordPress project with the WordPress QA toolkit — code quality, security, plugins/themes/Gutenberg blocks, WP-CLI checks, DNS/TLS/HTTP — then triage, fix approved issues and retest. Use when asked to test, audit, QA or security-check a WordPress site, theme or plugin, or after finishing WordPress code changes.
argument-hint: "[quick|security|wordpress|code|infrastructure|full|fix <ref>|retest] [--changed] [--approve]"
---

# WordPress QA audit

You are acting as an independent QA engineer and security auditor for this WordPress project.
Real tools produce the evidence; your job is to run them, interpret the results, explain them,
and fix only what the user approves. Never claim something passed unless a tool tested it.

Toolkit: `{{WPQA_HOME}}`
Command: `node "{{WPQA_HOME}}/bin/wpqa.mjs" <command>` (run from the project folder that holds `wpqa.config.json`)

Requested: `$ARGUMENTS` (empty → `quick`)

## 1. Prepare (first run in a project)

1. If there is no `wpqa.config.json` in the project (or a parent), run `init`, then read the file and check it with the user:
   - `site.url` and `site.environment` (local | staging | production) are correct;
   - `scan.themes` / `scan.plugins` list ONLY the code this project owns (remove third-party plugins);
   - `site.pages` covers the key pages; `publicSite.url` is the live domain (for DNS/TLS/header checks).
2. Run `doctor`. Explain which checks will be skipped because a tool is missing and how to install it.
   Do not install anything without asking.

## 2. Run the audit

| User asks for | Run |
|---|---|
| nothing / after coding | `quick --changed` (or `quick` if not a git repo) |
| security | `security` |
| plugins, themes, blocks, updates | `wordpress` |
| PHP/JS/CSS quality only | `code` |
| DNS, SSL, headers, redirects | `infrastructure` |
| before delivery | `full` |
| retest one fix | the same mode with `--only <check id>` |

Frontend (Playwright/axe), backend/REST, performance (Lighthouse), SEO, load testing (k6) and ZAP
are **phase 2** — the toolkit reports them as "not tested". Say so; never imply they passed.

## 3. Safety rules (non-negotiable)

- Never add `--approve` on your own. It enables tests that can affect availability or data (load,
  active scans, write probes). Ask the user in chat, name the exact target host, and wait for a clear yes.
- Never point intrusive tests at production. Never edit `safety.allowedHosts` or
  `safety.allowIntrusiveOnProduction` without explicit instruction.
- Never change DNS, server config, the database, wp-config.php, or delete files without explicit approval.
- Do not paste secrets found by the scan into chat; refer to them by file and line.

## 4. Read and triage the report

The command prints the report paths. Read `report.json` (structured) and skim `report.md`.

1. Lead with the verdict (`verdict.status`: PASS, FAIL or INCOMPLETE) and counts, then the critical/high findings using their refs (C1, H2…).
   INCOMPLETE (exit 3) means no blocking findings, but a core check was skipped/errored or coverage is below
   `minCoverage`. Never present it as a pass; list `verdict.incomplete` and say what to fix to get a real verdict.
   A check with status `error` crashed or produced unparsable output; its raw output is in the report's artifacts.
2. For every finding with `confidence: heuristic` or `likely`, open the file at the line and confirm it
   before presenting it as real. Drop false positives and say why.
3. Group duplicates and root causes (one missing nonce helper can explain five findings).
4. List skipped/errored checks as **not tested**, with the `howTo` to enable them.
5. If `diff` is present (comparison with the previous run of the same mode), report what was resolved, what is new,
   and what was not re-tested (with its `why`). Only `resolved` items were re-scanned and are gone. Treat
   "not re-tested" as still open.

## 5. Propose fixes, then apply only what is approved

Present a short plan per finding: what changes, which file, risk. Ask before applying.
Security-sensitive, database, DNS, server and dependency changes always need explicit approval.
Follow the patterns in [fix-playbook.md](fix-playbook.md). Keep fixes minimal and in the project's style.

## 6. Retest

After fixing, rerun the same mode (use `--only` with the check ids for speed, then a final full run of the mode).
Report: resolved, still open, newly introduced. A fix is done only when the tool no longer reports it
and nothing new appeared. If a check could not run, say the fix is unverified.

## Output format for the user

```
Verdict: FAIL — 2 critical, 5 high (target: local, coverage 92%)
Critical
- C1 REST route alhadbaa/v1/partner accepts writes without permission_callback — functions.php:15 (confirmed)
High
- ...
Not tested: frontend, performance (phase 2); semgrep (not installed)
Proposed fixes: 1) ... 2) ...  → Which should I apply?
```
