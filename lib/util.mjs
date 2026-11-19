// Shared helpers: process execution (Windows-safe), file walking, HTTP, versions.
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';

export const TOOLKIT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const IS_WIN = process.platform === 'win32';
const require = createRequire(import.meta.url);

/* ------------------------------------------------------------------ */
/* Command resolution                                                  */
/* ------------------------------------------------------------------ */

const whichCache = new Map();

/** Name of the PATH variable in an environment object (Windows uses "Path" when launched from cmd/PowerShell). */
export function pathKey(env = process.env) {
  return Object.keys(env).find((k) => k.toUpperCase() === 'PATH') || 'PATH';
}

/**
 * Find an executable on PATH (honours PATHEXT on Windows). Returns absolute path or null.
 * searchPath: optional PATH string to search instead of process.env.PATH (e.g. with tools.pathPrepend applied).
 */
export function which(cmd, searchPath) {
  if (!cmd) return null;
  const cacheKey = searchPath ? `${cmd}\0${searchPath}` : cmd;
  if (whichCache.has(cacheKey)) return whichCache.get(cacheKey);
  let found = null;
  const exts = IS_WIN ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';').map((e) => e.toLowerCase()) : [''];
  const candidates = (p) => (IS_WIN && !path.extname(p) ? exts.map((e) => p + e) : [p]);
  if (cmd.includes('/') || cmd.includes('\\')) {
    for (const c of candidates(path.resolve(cmd))) if (isFile(c)) { found = c; break; }
  } else {
    const dirs = (searchPath ?? process.env[pathKey()] ?? '').split(path.delimiter).filter(Boolean);
    outer: for (const d of dirs) {
      for (const c of candidates(path.join(d, cmd))) if (isFile(c)) { found = c; break outer; }
    }
  }
  whichCache.set(cacheKey, found);
  return found;
}

/**
 * Environment for tool processes: config tools.env plus tools.pathPrepend (directories put in front of PATH,
 * e.g. LocalWP's ImageMagick folder so php_imagick.dll loads). Always returns the PATH under the key the
 * current process uses, so Windows never ends up with both "Path" and "PATH".
 */
export function toolEnv(tools = {}) {
  const env = { ...(tools.env || {}) };
  const pre = (tools.pathPrepend || []).filter(Boolean).map((p) => path.normalize(p));
  const key = pathKey();
  const userKey = Object.keys(env).find((k) => k.toUpperCase() === 'PATH');
  const base = userKey ? env[userKey] : process.env[key] || '';
  if (userKey) delete env[userKey];
  if (pre.length || userKey) env[key] = [...pre, base].filter(Boolean).join(path.delimiter);
  return env;
}

function isFile(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}

/**
 * Normalise a tool setting from config into [command, ...prefixArgs].
 * Accepts "php", "C:/path/php.exe", ["php", "C:/wp-cli.phar"], or "C:/wp-cli.phar" (php is prefixed).
 */
export function toolCommand(setting, phpCmd = 'php') {
  if (!setting) return null;
  let parts = Array.isArray(setting) ? [...setting] : [setting];
  if (parts.length === 1 && /\.phar$/i.test(parts[0])) parts = [...(Array.isArray(phpCmd) ? phpCmd : [phpCmd]), parts[0]];
  return withPhpFlags(parts);
}

/** PHP CLI flags that keep startup/runtime diagnostics out of stdout (they break JSON and value parsing). */
export const PHP_SAFE_FLAGS = ['-d', 'display_errors=stderr'];

export function isPhpBinary(cmd) {
  return /^php(\d+(\.\d+)?)?(\.exe)?$/i.test(path.basename(String(cmd || '')));
}

/** Insert PHP_SAFE_FLAGS right after the php binary (once). */
export function withPhpFlags(parts) {
  if (!parts?.length || !isPhpBinary(parts[0])) return parts;
  if (parts[1] === PHP_SAFE_FLAGS[0] && parts[2] === PHP_SAFE_FLAGS[1]) return parts;
  return [parts[0], ...PHP_SAFE_FLAGS, ...parts.slice(1)];
}

// "Warning: PHP Startup: Unable to load dynamic library … in Unknown on line 0", "PHP Notice: … in /x.php on line 12", "Deprecated: …"
const PHP_DIAG_RE = /^\s*(?:PHP )?(?:Warning|Notice|Deprecated|Strict Standards|Fatal error|Parse error|Recoverable fatal error|Core Warning|Startup error)\s*:\s.*\bon line \d+\s*$/;

/**
 * Move PHP diagnostic lines (startup warnings, notices printed by display_errors=On) out of stdout.
 * Returns { stdout, diagnostics[] }. Needed when a wrapper (wp.bat, a custom script) hides the php binary
 * so PHP_SAFE_FLAGS cannot be passed.
 */
export function cleanPhpOutput(text) {
  const diagnostics = [];
  const kept = [];
  for (const line of String(text ?? '').split(/\r?\n/)) {
    if (PHP_DIAG_RE.test(line)) diagnostics.push(line.trim());
    else kept.push(line);
  }
  let stdout = kept.join('\n');
  if (diagnostics.length) stdout = stdout.replace(/^\s*\n/, ''); // PHP prints a blank line before each diagnostic
  return { stdout, diagnostics };
}

/** Resolve the JS entry of an npm package binary inside the toolkit, so we can run it with `node` on any OS. */
export function nodePackageBin(pkg, binName) {
  try {
    const pkgJsonPath = require.resolve(`${pkg}/package.json`, { paths: [TOOLKIT_ROOT] });
    const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
    let rel = typeof pkgJson.bin === 'string' ? pkgJson.bin : pkgJson.bin?.[binName || Object.keys(pkgJson.bin || {})[0]];
    if (!rel) return null;
    return path.join(path.dirname(pkgJsonPath), rel);
  } catch {
    return null;
  }
}

export function hasNodePackage(pkg) {
  try { require.resolve(`${pkg}/package.json`, { paths: [TOOLKIT_ROOT] }); return true; } catch { return false; }
}

/* ------------------------------------------------------------------ */
/* Process execution                                                   */
/* ------------------------------------------------------------------ */

function quoteWinArg(a) {
  if (a === '') return '""';
  if (!/[\s"&|<>^%()!]/.test(a)) return a;
  return '"' + a.replace(/(\\*)"/g, '$1$1\\"').replace(/(\\+)$/, '$1$1') + '"';
}

/**
 * Run a command and capture output. Never throws for non-zero exits.
 * Returns { code, stdout, stderr, timedOut, error, durationMs, command }.
 */
export function run(cmd, args = [], opts = {}) {
  const { cwd, env, timeoutMs = 10 * 60 * 1000, input, maxBuffer = 64 * 1024 * 1024 } = opts;
  return new Promise((resolve) => {
    const started = Date.now();
    let resolved = cmd;
    let finalArgs = args;
    let useShell = false;
    const envPathKey = env && Object.keys(env).find((k) => k.toUpperCase() === 'PATH');
    const abs = which(cmd, envPathKey ? env[envPathKey] : undefined);
    if (abs) resolved = abs;
    if (IS_WIN && /\.(cmd|bat)$/i.test(resolved)) {
      // Node refuses to spawn .cmd/.bat without a shell; build a safely quoted command line.
      finalArgs = ['/d', '/s', '/c', '"' + [quoteWinArg(resolved), ...args.map(quoteWinArg)].join(' ') + '"'];
      resolved = process.env.ComSpec || 'cmd.exe';
      useShell = false;
    }
    const commandLine = [cmd, ...args].join(' ');
    let child;
    try {
      child = spawn(resolved, finalArgs, {
        cwd,
        env: { ...process.env, ...env },
        shell: useShell,
        windowsHide: true,
        windowsVerbatimArguments: IS_WIN && /cmd(\.exe)?$/i.test(resolved),
      });
    } catch (error) {
      resolve({ code: -1, stdout: '', stderr: String(error), error, timedOut: false, durationMs: 0, command: commandLine });
      return;
    }
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      try { child.kill('SIGKILL'); } catch { /* ignore */ }
    }, timeoutMs);
    child.stdout?.on('data', (d) => { if (stdout.length < maxBuffer) stdout += d; });
    child.stderr?.on('data', (d) => { if (stderr.length < maxBuffer) stderr += d; });
    if (input !== undefined) { child.stdin?.end(input); } else { child.stdin?.end(); }
    child.on('error', (error) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: stderr + String(error), error, timedOut, durationMs: Date.now() - started, command: commandLine });
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: code ?? -1, stdout, stderr, timedOut, durationMs: Date.now() - started, command: commandLine });
    });
  });
}

/**
 * Run a tool defined by a config setting (string/array).
 * opts.cleanPhp: move PHP diagnostics out of stdout into stderr (result.phpDiagnostics lists them).
 */
export async function runTool(setting, args, opts = {}) {
  const cmd = toolCommand(setting, opts.php || 'php');
  if (!cmd) return { code: -1, stdout: '', stderr: 'tool not configured', command: '' };
  const r = await run(cmd[0], [...cmd.slice(1), ...args], opts);
  if (opts.cleanPhp) {
    const { stdout, diagnostics } = cleanPhpOutput(r.stdout);
    r.rawStdout = r.stdout;
    r.stdout = stdout;
    r.phpDiagnostics = diagnostics;
    if (diagnostics.length) r.stderr = [diagnostics.join('\n'), r.stderr].filter(Boolean).join('\n');
  }
  return r;
}

/** Run a node script with the current Node binary. */
export function runNode(script, args, opts = {}) {
  return run(process.execPath, [script, ...args], opts);
}

/** Parse JSON from tool output that may contain banners/warnings before or after the JSON. */
export function parseJsonLoose(text) {
  if (!text) return null;
  try { return JSON.parse(text); } catch { /* continue */ }
  const starts = [text.indexOf('{'), text.indexOf('[')].filter((i) => i >= 0).sort((a, b) => a - b);
  for (const s of starts) {
    const open = text[s];
    const close = open === '{' ? '}' : ']';
    const e = text.lastIndexOf(close);
    if (e > s) {
      try { return JSON.parse(text.slice(s, e + 1)); } catch { /* try next */ }
    }
  }
  return null;
}

/* ------------------------------------------------------------------ */
/* Files                                                               */
/* ------------------------------------------------------------------ */

export const DEFAULT_EXCLUDES = ['node_modules', 'vendor', '.git', '.svn', 'build', 'dist', '.cache', '.wpqa', 'wpqa-tests'];

/** Recursively list files under dir with given extensions, skipping excluded directory names. */
export function walkFiles(dir, { exts = null, exclude = DEFAULT_EXCLUDES, maxFiles = 20000, includeMin = false } = {}) {
  const out = [];
  const excl = new Set(exclude);
  const stack = [dir];
  while (stack.length && out.length < maxFiles) {
    const d = stack.pop();
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
    for (const e of entries) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) {
        if (!excl.has(e.name)) stack.push(p);
      } else if (e.isFile()) {
        if (!includeMin && /\.min\.(js|css)$/i.test(e.name)) continue;
        if (!exts || exts.includes(path.extname(e.name).toLowerCase())) out.push(p);
      }
    }
  }
  return out.sort();
}

export function readText(p, max = 5 * 1024 * 1024) {
  try {
    const st = fs.statSync(p);
    if (st.size > max) return null;
    return fs.readFileSync(p, 'utf8');
  } catch { return null; }
}

export function readJson(p) {
  const t = readText(p);
  if (t == null) return null;
  try { return JSON.parse(t); } catch { return undefined; }
}

export function exists(p) {
  try { fs.accessSync(p); return true; } catch { return false; }
}

export async function ensureDir(p) {
  await fsp.mkdir(p, { recursive: true });
  return p;
}

export function rel(from, to) {
  return path.relative(from, to).split(path.sep).join('/');
}

/** Parse WordPress-style file headers (Plugin Name:, Theme Name:, ...). */
export function parseWpHeaders(text, keys) {
  const head = (text || '').slice(0, 8192);
  const out = {};
  for (const k of keys) {
    const re = new RegExp('^[ \\t/*#@]*' + k.replace(/ /g, '\\s') + ':(.*)$', 'mi');
    const m = head.match(re);
    if (m) out[k] = m[1].replace(/\s*(?:\*\/|\?>).*$/, '').trim();
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Misc                                                                */
/* ------------------------------------------------------------------ */

export function hash(...parts) {
  return crypto.createHash('sha1').update(parts.map((p) => String(p ?? '')).join('|')).digest('hex').slice(0, 12);
}

/** Compare dotted versions. Returns -1, 0, 1. Non-numeric suffixes (RC, beta) sort before release. */
export function compareVersions(a, b) {
  const norm = (v) => String(v || '0').trim().split(/[.+-]/);
  const pa = norm(a), pb = norm(b);
  const n = Math.max(pa.length, pb.length);
  for (let i = 0; i < n; i++) {
    const x = pa[i], y = pb[i];
    if (x === undefined) return /^\d+$/.test(y) ? (Number(y) === 0 ? 0 : -1) : 1;
    if (y === undefined) return /^\d+$/.test(x) ? (Number(x) === 0 ? 0 : 1) : -1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { const d = Number(x) - Number(y); if (d) return d > 0 ? 1 : -1; continue; }
    if (nx !== ny) return nx ? 1 : -1;
    const c = x.localeCompare(y); if (c) return c > 0 ? 1 : -1;
  }
  return 0;
}

/** Map with bounded concurrency. */
export async function pMap(items, fn, concurrency = 4) {
  const results = new Array(items.length);
  let i = 0;
  const workers = Array.from({ length: Math.min(concurrency, items.length) }, async () => {
    while (i < items.length) {
      const idx = i++;
      results[idx] = await fn(items[idx], idx);
    }
  });
  await Promise.all(workers);
  return results;
}

/** fetch() with timeout; never throws (returns { ok:false, error }). Does not follow redirects unless asked. */
export async function httpFetch(url, { method = 'GET', headers = {}, redirect = 'manual', timeoutMs = 20000, body, readBody = true, maxBody = 3 * 1024 * 1024 } = {}) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), timeoutMs);
  const started = performance.now();
  try {
    const res = await fetch(url, {
      method,
      headers: { 'user-agent': 'wpqa-toolkit/2.0 (+QA audit)', ...headers },
      redirect,
      body,
      signal: ctrl.signal,
    });
    const ttfbMs = performance.now() - started;
    let text = '';
    if (readBody && method !== 'HEAD') {
      const buf = await res.arrayBuffer();
      text = Buffer.from(buf.byteLength > maxBody ? buf.slice(0, maxBody) : buf).toString('utf8');
    } else {
      // An unconsumed body keeps the socket open; on Windows process.exit() then aborts with a libuv
      // assertion (UV_HANDLE_CLOSING, exit code 127 instead of the verdict's exit code).
      try { await res.body?.cancel(); } catch { /* ignore */ }
    }
    const h = {};
    res.headers.forEach((v, k) => { h[k] = v; });
    return { ok: true, status: res.status, headers: h, text, url: res.url || url, ttfbMs, totalMs: performance.now() - started };
  } catch (error) {
    return { ok: false, status: 0, headers: {}, text: '', url, error: error.name === 'AbortError' ? `timeout after ${timeoutMs}ms` : (error.cause?.code || error.message) };
  } finally {
    clearTimeout(t);
  }
}

/** Follow redirects manually and return the chain. */
export async function followRedirects(url, { max = 10, timeoutMs = 20000 } = {}) {
  const chain = [];
  let current = url;
  for (let i = 0; i <= max; i++) {
    const r = await httpFetch(current, { timeoutMs, readBody: false, method: 'GET' });
    chain.push({ url: current, status: r.status, location: r.headers?.location || null, error: r.error || null });
    if (!r.ok || r.status < 300 || r.status >= 400 || !r.headers.location) return { chain, final: r, finalUrl: current };
    current = new URL(r.headers.location, current).toString();
  }
  return { chain, final: null, finalUrl: current, tooMany: true };
}

export function joinUrl(base, p) {
  return new URL(p, base.endsWith('/') ? base : base + '/').toString();
}

export function median(arr) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

export function percentile(arr, p) {
  if (!arr.length) return 0;
  const s = [...arr].sort((a, b) => a - b);
  return s[Math.min(s.length - 1, Math.ceil((p / 100) * s.length) - 1)];
}

export function truncate(s, n = 400) {
  s = String(s ?? '');
  return s.length > n ? s.slice(0, n) + '…' : s;
}

/** Line number (1-based) of a character offset. */
export function lineOf(text, offset) {
  let line = 1;
  for (let i = 0; i < offset && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

export function isLocalHost(hostname) {
  return /^(localhost|127\.\d+\.\d+\.\d+|::1|\[::1\])$/i.test(hostname) || /\.(local|test|localhost|lndo\.site|ddev\.site)$/i.test(hostname);
}
