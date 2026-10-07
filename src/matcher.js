/**
 * Shared rule-list parser and matcher, used by both the routing ruleset
 * (rules.js) and the blocklist (filter.js).
 *
 * Rule file format (one pattern per line):
 *   - bare  `foo.com`   => suffix match: `foo.com`, `a.foo.com`, ...
 *   - `full:foo.com`    => exact-match only
 *   - `regexp:^...`     => regex applied to the full qname (case-insensitive)
 *
 * Both callers feed their lists through the exact same parser so suffix/full/
 * regexp semantics can never drift between "route to domestic" and "block".
 */

/** Parse list text into { plain, plainSet, full, regexp, version }. */
export function parseRuleText(text) {
  const plain = [];
  const plainSet = new Set();
  const full = new Set();
  const regexp = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    if (line.startsWith("full:")) {
      const d = line.slice(5).trim().toLowerCase();
      if (d) full.add(d);
    } else if (line.startsWith("regexp:")) {
      const d = line.slice(7).trim();
      if (d) regexp.push(new RegExp(d, "i"));
    } else {
      const d = line.toLowerCase();
      plain.push(d);
      plainSet.add(d);
    }
  }
  // Sort for determinism; not required for correctness of suffix matching,
  // but it keeps iterations cache-friendly and test assertions stable.
  plain.sort();
  return { plain, plainSet, full, regexp, version: text.length };
}

/**
 * Does `qname` match `rule` (a parseRuleText result)? Suffix, exact or regexp.
 * `qname` is lower-cased here; the caller's plain/full sets are pre-lower-cased.
 */
export function matchesRule(qname, rule) {
  const q = qname.toLowerCase();
  if (!rule) return false;
  if (rule.full && rule.full.has(q)) return true;

  if (rule.plainSet) {
    if (rule.plainSet.has(q)) return true;
    let dotIdx = q.indexOf(".");
    while (dotIdx !== -1) {
      const parent = q.slice(dotIdx + 1);
      if (rule.plainSet.has(parent)) return true;
      dotIdx = q.indexOf(".", dotIdx + 1);
    }
  } else if (rule.plain) {
    for (let i = 0; i < rule.plain.length; i += 1) {
      const p = rule.plain[i];
      if (q === p || q.endsWith(`.${p}`)) return true;
    }
  }

  if (rule.regexp) {
    for (let i = 0; i < rule.regexp.length; i += 1) {
      if (rule.regexp[i].test(q)) return true;
    }
  }
  return false;
}