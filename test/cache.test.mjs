/**
 * Verifies the DNS response cache: hit/miss, expiry, ECS keying, and that the
 * cached bytes are what the client receives. Runs without the Cloudflare runtime.
 * Run: node test/cache.test.mjs
 */

import { createCache } from "../src/cache.js";

let fake = 1000000;
const now = () => fake;

let passed = 0;
let failed = 0;
const check = (cond, label) => {
  if (cond) { passed += 1; console.log(`  ok - ${label}`); }
  else { failed += 1; console.error(`  FAIL - ${label}`); }
};

// ---- miss then hit ----
{
  const c = createCache({ now });
  check(c.get("github.com", 1, "1:1.2.3.0") === null, "initial miss");
  const a = new Uint8Array([1, 2, 3]);
  c.set("github.com", 1, "1:1.2.3.0", a, 100);
  const got = c.get("github.com", 1, "1:1.2.3.0");
  check(!!got && got.length === 3 && got[0] === 1, "hit returns stored bytes");
}

// ---- expiry ----
{
  const c = createCache({ now });
  c.set("a.com", 1, "none", new Uint8Array([9]), 60);
  fake += 61 * 1000;
  check(c.get("a.com", 1, "none") === null, "expired entry gone");
  fake += 1000;
}

// ---- ECS must be part of the key ----
{
  const c = createCache({ now });
  c.set("x.io", 1, "1:1.2.3.0", new Uint8Array([5]), 60);
  check(c.get("x.io", 1, "1:2.3.4.0") === null, "different ECS is a miss (no leak)");
  check(c.get("x.io", 1, "1:1.2.3.0") !== null, "same ECS still hits");
}

// ---- qtype is part of the key ----
{
  const c = createCache({ now });
  c.set("y.net", 1, "none", new Uint8Array([7]), 60);
  check(c.get("y.net", 28, "none") === null, "different qtype is a miss");
}

// ---- ttl<=0 does not store ----
{
  const c = createCache({ now });
  c.set("z.com", 1, "none", new Uint8Array([1]), 0);
  check(c.get("z.com", 1, "none") === null, "ttl 0 not cached");
}

// ---- size bound eviction ----
{
  const c = createCache({ now, size: 2 });
  c.set("a", 1, "none", new Uint8Array([1]), 60);
  c.set("b", 1, "none", new Uint8Array([2]), 60);
  c.set("c", 1, "none", new Uint8Array([3]), 60); // evicts "a"
  check(c.get("a", 1, "none") === null, "oldest evicted when over size");
  check(c.get("c", 1, "none") !== null && c.get("b", 1, "none") !== null, "newer entries retained");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;