// Strict command-line parsing. Unknown or malformed flags are errors (exit 2), never silently ignored:
// "--approve=false" must not be read as approval, and a typo like "--aprove" must not run without its meaning.

/** Flags that take no value. "--flag=anything" is rejected. */
export const BOOLEAN_FLAGS = new Set(['approve', 'changed', 'quiet', 'json', 'force', 'help', 'offline', 'confirm']);
/** Flags that need a value: "--flag value" or "--flag=value". */
export const VALUE_FLAGS = new Set(['config', 'url', 'env', 'public', 'only', 'skip', 'profile', 'scope']);
const LIST_FLAGS = new Set(['only', 'skip']);

function suggest(name) {
  const all = [...BOOLEAN_FLAGS, ...VALUE_FLAGS];
  const dist = (a, b) => {
    const m = Array.from({ length: a.length + 1 }, (_, i) => [i, ...Array(b.length).fill(0)]);
    for (let j = 1; j <= b.length; j++) m[0][j] = j;
    for (let i = 1; i <= a.length; i++) for (let j = 1; j <= b.length; j++) m[i][j] = Math.min(m[i - 1][j] + 1, m[i][j - 1] + 1, m[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    return m[a.length][b.length];
  };
  const best = all.map((f) => [f, dist(name, f)]).sort((x, y) => x[1] - y[1])[0];
  return best && best[1] <= 2 ? ` Did you mean --${best[0]}?` : '';
}

/**
 * Parse argv. Returns { flags, errors }. flags._ holds positional arguments.
 * Boolean flags are exactly `true` when given; there is no way to pass a value to them.
 */
export function parseArgs(argv) {
  const flags = { _: [] };
  const errors = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--') { flags._.push(...argv.slice(i + 1)); break; }
    if (a.startsWith('--')) {
      const eq = a.indexOf('=');
      const name = eq === -1 ? a.slice(2) : a.slice(2, eq);
      const value = eq === -1 ? undefined : a.slice(eq + 1);
      if (!name) { errors.push(`malformed flag "${a}"`); continue; }
      if (BOOLEAN_FLAGS.has(name)) {
        if (value !== undefined) { errors.push(`--${name} takes no value (got "${a}"). Use --${name} on its own, or leave it out.`); continue; }
        flags[name] = true;
      } else if (VALUE_FLAGS.has(name)) {
        let v = value;
        if (v === undefined) {
          const next = argv[i + 1];
          if (next === undefined || next.startsWith('-')) { errors.push(`--${name} needs a value`); continue; }
          v = next;
          i++;
        }
        if (v === '') { errors.push(`--${name} needs a value`); continue; }
        if (LIST_FLAGS.has(name)) {
          const list = v.split(',').map((s) => s.trim()).filter(Boolean);
          if (!list.length) { errors.push(`--${name} needs at least one check id`); continue; }
          flags[name] = [...(flags[name] || []), ...list];
        } else flags[name] = v;
      } else errors.push(`unknown flag "--${name}".${suggest(name)}`);
    } else if (a.startsWith('-') && a.length > 1) {
      errors.push(`unknown flag "${a}" (flags start with --)`);
    } else flags._.push(a);
  }
  return { flags, errors };
}
