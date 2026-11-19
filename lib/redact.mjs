// Redaction for evidence written to reports and artifacts (logs, HTTP responses, tool output).
// Errs on the side of hiding: a report must never carry passwords, cookies, nonces, tokens or personal data.
import os from 'node:os';

const HOME = os.homedir();
const RULES = [
  // key=value / "key": "value" pairs whose key looks secret
  [/((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|auth(?:orization)?|nonce|_wpnonce|session|cookie|salt|private[_-]?key|access[_-]?key)["']?\s*[:=]\s*["']?)([^"'\s&,;]{3,})/gi, '$1[redacted]'],
  // HTTP headers
  [/((?:Authorization|Cookie|Set-Cookie|X-WP-Nonce)\s*:\s*)[^\r\n]+/gi, '$1[redacted]'],
  // WordPress auth cookies
  [/(wordpress_(?:logged_in|sec)?_[0-9a-f]{32}=)[^;\s]+/gi, '$1[redacted]'],
  // query-string secrets
  [/([?&](?:_wpnonce|nonce|token|key|pass|pwd|password|auth|sig|signature)=)[^&\s"']+/gi, '$1[redacted]'],
  // e-mail addresses
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, '[email]'],
  // IPv4 (keep loopback, useful for local diagnostics)
  [/\b(?!127\.0\.0\.1\b)(?:\d{1,3}\.){3}\d{1,3}\b/g, '[ip]'],
  // bearer / long opaque tokens next to typical words
  [/(Bearer\s+)[A-Za-z0-9._~+/=-]{8,}/g, '$1[redacted]'],
];

/** Redact secrets and personal data. Paths under the user's home folder become "~". */
export function redact(text) {
  if (text == null) return text;
  let s = String(text);
  if (HOME && HOME.length > 3) {
    s = s.split(HOME).join('~');
    s = s.split(HOME.split('\\').join('/')).join('~');
  }
  for (const [re, rep] of RULES) s = s.replace(re, rep);
  return s;
}
