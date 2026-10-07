/**
 * Per-IP rate limiter unit tests (token bucket + connection cap + sweep).
 * Run: node test/ratelimit.test.mjs
 */

import { createIpLimiter } from "../src/ratelimit.js";

let passed = 0;
let failed = 0;
const check = (cond, label) => {
  if (cond) { passed += 1; console.log(`  ok - ${label}`); }
  else { failed += 1; console.error(`  FAIL - ${label}`); }
};

let fake = 1_000_000;

// ---- query budget: token bucket ----
{
  const lim = createIpLimiter({ maxQpsPerIp: 5, maxConnectionsPerIp: 0, now: () => fake });
  // Burst = maxQpsPerIp, so first 5 should pass.
  for (let i = 0; i < 5; i += 1) check(lim.allowQuery("1.2.3.4"), `token bucket: query ${i + 1} allowed`);
  check(!lim.allowQuery("1.2.3.4"), "token bucket: 6th query denied (bucket empty)");
  check(lim.allowQuery("5.5.5.5"), "token bucket: different IP has its own bucket");
  // 200ms later → partial refill
  fake += 200;
  check(lim.allowQuery("1.2.3.4"), "token bucket: partial refill after 200ms (5*0.2=1 token)");
  check(!lim.allowQuery("1.2.3.4"), "token bucket: refill exhausted again");
  // 1s later → full refill
  fake += 1000;
  for (let i = 0; i < 5; i += 1) lim.allowQuery("1.2.3.4"); // drain
  check(!lim.allowQuery("1.2.3.4"), "token bucket: full refill works");
}

// ---- query budget disabled ----
{
  const lim = createIpLimiter({ maxQpsPerIp: 0, maxConnectionsPerIp: 0, now: () => fake });
  for (let i = 0; i < 200; i += 1) check(lim.allowQuery("1.2.3.4"), `maxQps=0: query ${i + 1} always allowed`);
}

// ---- connection cap ----
{
  const lim = createIpLimiter({ maxQpsPerIp: 0, maxConnectionsPerIp: 2, now: () => fake });
  check(lim.acquireConnection("9.9.9.9"), "conn cap: first conn ok");
  check(lim.acquireConnection("9.9.9.9"), "conn cap: second conn ok");
  check(!lim.acquireConnection("9.9.9.9"), "conn cap: third conn denied");
  check(lim.acquireConnection("8.8.8.8"), "conn cap: different IP ok");
  lim.releaseConnection("9.9.9.9");
  check(lim.acquireConnection("9.9.9.9"), "conn cap: slot freed by release");
}

// ---- connection cap disabled ----
{
  const lim = createIpLimiter({ maxConnectionsPerIp: 0, now: () => fake });
  for (let i = 0; i < 200; i += 1) check(lim.acquireConnection("1.2.3.4"), `maxConn=0: conn ${i + 1} always ok`);
}

// ---- null/undefined IP always passes (rely on global cap) ----
{
  const lim = createIpLimiter({ maxQpsPerIp: 5, maxConnectionsPerIp: 2, now: () => fake });
  check(lim.allowQuery(null), "null IP always allowed (allowQuery)");
  check(lim.allowQuery(undefined), "undefined IP always allowed (allowQuery)");
  check(lim.acquireConnection(null), "null IP always allowed (acquireConnection)");
  lim.releaseConnection(null); // must not throw
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;