import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const dir = dirname(fileURLToPath(import.meta.url));
const tests = [
  "dns.test.mjs",
  "cache.test.mjs",
  "cache.worker.mjs",
  "routing.mjs",
  "ecs.forward.mjs",
  "filter-json-dnssec.mjs",
  "hardening.mjs",
  "landing.cors.mjs",
  "analytics.test.mjs",
  "analytics-global.test.mjs",
  "rules-sync.test.mjs",
  "bundle.smoke.mjs",
];
let allOk = true;
for (const t of tests) {
  process.stdout.write(`\n=== ${t} ===\n`);
  const r = spawnSync(process.execPath, [join(dir, t)], { stdio: "inherit" });
  if (r.status !== 0) allOk = false;
}
process.stdout.write(allOk ? "\nALL TESTS PASSED\n" : "\nSOME TESTS FAILED\n");
process.exitCode = allOk ? 0 : 1;
