/**
 * Shared rule-matcher tests (src/matcher.js) plus a cross-caller consistency
 * guard: rules.js and filter.js must agree on identical rule text, so the
 * suffix/full/regexp semantics can never drift after the shared-engine
 * extraction (review finding F7).
 * Run: node test/matcher.test.mjs
 */

import { parseRuleText, matchesRule } from "../src/matcher.js";
import { loadRulesFromText, isDomestic } from "../src/rules.js";
import { loadBlockFromText, isBlocked } from "../src/filter.js";

let passed = 0;
let failed = 0;
const check = (cond, label) => {
  if (cond) { passed += 1; console.log(`  ok - ${label}`); }
  else { failed += 1; console.error(`  FAIL - ${label}`); }
};

// ---- parsing semantics ----
{
  const r = parseRuleText(
    [
      "# comment line",
      "// another comment",
      "",
      "Example.COM",
      "foo.example.com",
      "full:exact.test",
      "regexp:^ads[0-9]+\\.net$",
      "full:",
      "regexp:",
    ].join("\n")
  );
  check(r.plain.length === 2 && r.plain.includes("example.com") && r.plain.includes("foo.example.com"), "bare lines lower-cased and collected");
  check(r.plainSet.has("example.com") && r.full.has("exact.test") && r.regexp.length === 1, "full:/regexp: routed to their sets");
  check(!r.full.has("") && r.regexp.length === 1, "empty full:/regexp: lines are ignored");
}

// ---- matching semantics ----
{
  const r = parseRuleText("example.com\nfull:exact.test\nregexp:^ads[0-9]+\\.net$");
  check(matchesRule("example.com", r), "suffix: exact domain matches");
  check(matchesRule("a.b.example.com", r), "suffix: subdomain matches");
  check(matchesRule("EXAMPLE.COM", r), "suffix: case-insensitive");
  check(!matchesRule("notexample.com", r), "suffix: label-boundary respected (no partial match)");
  check(!matchesRule("example.com.evil.net", r), "suffix: does not match when the label is not the tail");
  check(matchesRule("exact.test", r), "full: exact match");
  check(!matchesRule("sub.exact.test", r), "full: subdomain is NOT an exact match");
  check(matchesRule("ads12.net", r), "regexp: matches");
  check(!matchesRule("ads.net", r), "regexp: non-matching name");
}

// ---- null/absent rule ----
{
  check(!matchesRule("anything.com", null), "null rule matches nothing");
  check(!matchesRule("anything.com", undefined), "undefined rule matches nothing");
}

// ---- cross-caller consistency (regression guard for F7) ----
{
  const text = ["foo.cn", "full:bar.cn", "regexp:^rx[0-9]+\\.io$"].join("\n");
  const rules = loadRulesFromText(text);
  const block = loadBlockFromText(text);
  const names = [
    "foo.cn",
    "deep.foo.cn",
    "notfoo.cn",
    "bar.cn",
    "x.bar.cn",
    "rx7.io",
    "rx.io",
    "unrelated.net",
  ];
  // isDomestic also folds in BUILTIN_OVERRIDE, so compare on non-builtin names.
  const agree = names.every((n) => isDomestic(n, rules) === isBlocked(n, block));
  check(agree, "rules.js and filter.js agree on identical rule text (shared matcher, no drift)");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;