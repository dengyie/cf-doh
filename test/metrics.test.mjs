/**
 * Metrics counter unit tests — inc guard, snapshot shape, reset.
 * Run: node test/metrics.test.mjs
 */

import { metrics } from "../src/metrics.js";

let passed = 0;
let failed = 0;
const check = (cond, label) => {
  if (cond) { passed += 1; console.log(`  ok - ${label}`); }
  else { failed += 1; console.error(`  FAIL - ${label}`); }
};

metrics.resetMetrics();

// ---- known counter names increment normally ----
{
  metrics.inc("requests");
  metrics.inc("requests", 2);
  const s = metrics.snapshot();
  check(s.requests === 3, "known counter inc + snapshot");
}

// ---- unknown counter name: warns once, registers, and returns in snapshot ----
{
  const warnings = [];
  const warn = console.warn;
  console.warn = (msg) => warnings.push(msg);
  try {
    metrics.inc("dot_typo_misspelled", 1);
    check(warnings.length === 1 && warnings[0].includes("dot_typo_misspelled"),
      "unknown counter: one-shot warning logged");
    // Second call to the same unknown name must NOT warn again.
    metrics.inc("dot_typo_misspelled", 1);
    check(warnings.length === 1, "unknown counter: second inc does not re-warn");
    const s = metrics.snapshot();
    check(s.dot_typo_misspelled === 2, "unknown counter: value accumulated in snapshot");
  } finally {
    console.warn = warn;
  }
}

// ---- unknown counter removed by resetMetrics ----
{
  metrics.inc("another_typo", 5);
  const s1 = metrics.snapshot();
  check("another_typo" in s1 && s1.another_typo === 5, "unknown counter visible before reset");
  metrics.resetMetrics();
  const s2 = metrics.snapshot();
  check(!("another_typo" in s2), "unknown counter removed after resetMetrics");
  check(s2.requests === 0, "known counter reset to 0 after resetMetrics");
}

// ---- known counters are never warned about ----
{
  const warnings = [];
  const warn = console.warn;
  console.warn = (msg) => warnings.push(msg);
  try {
    metrics.inc("dot_connections", 1);
    metrics.inc("dot_rate_limited");
    metrics.inc("dot_idle_timeouts");
    check(warnings.length === 0, "known dot_* counters never trigger warn");
  } finally {
    console.warn = warn;
  }
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;