/**
 * Verifies the cache is actually engaged through the worker: the FIRST identical
 * query hits upstream (miss), the SECOND identical query returns from cache
 * (no new upstream call). ECS keying is confirmed by using a distinct IP that
 * produces a distinct /24, forcing a miss.
 *
 * Run: node test/cache.worker.mjs
 */

function buildQuery(name, id = 0x7777) {
  const header = new Uint8Array(12);
  header[0] = id >> 8; header[1] = id & 0xff; header[2] = 0x01; header[5] = 1;
  const parts = [];
  for (const lab of name.split(".")) { parts.push(lab.length); for (let i = 0; i < lab.length; i += 1) parts.push(lab.charCodeAt(i)); }
  parts.push(0, 0, 1, 0, 1);
  return new Uint8Array([...header, ...parts]);
}

let upstreamCalls = 0;
globalThis.fetch = async (url, init) => {
  upstreamCalls += 1;
  const q = new Uint8Array(init.body);
  const ans = new Uint8Array(q.length + 8);
  ans.set(q, 0); ans[2] = 0x81; ans[3] = 0x80;
  // add one answer RR with TTL=600 to give the cache a lifetime: owner name (same as qname literal),
  // but simplest: just leave header; TTL parsing sees no records -> ttl=0 -> uses config ttl.
  return new Response(ans, { headers: { "content-type": "application/dns-message" } });
};

function fakeKv(text) {
  return { async get(k) { if (k === "rules:data") return text ?? "\n"; return null; }, async put() {} };
}

const env = {
  RULES_KV: fakeKv("\n"),
  DOMESTIC_DOH_URL: "https://dns.alidns.com/dns-query",
  DOMESTIC_FALLBACK_DOH_URL: "",
  GLOBAL_DOH_URL: "https://dns.google/dns-query",
  GLOBAL_FALLBACK_DOH_URL: "",
  CACHE_TTL_SECONDS: "120",
};

const mod = await import("../src/worker.js");

function req(id, ip) {
  return new Request("https://doh.test/doh", {
    method: "POST",
    headers: { "content-type": "application/dns-message", "cf-connecting-ip": ip },
    body: buildQuery("cache.test", id),
  });
}

let ok = true;
const check = (c, l) => { console.log(c ? `  ok - ${l}` : `  FAIL - ${l}`); if (!c) ok = false; };

// first query -> upstream miss
upstreamCalls = 0;
await mod.handleRequest(req(0x1000, "1.2.3.4"), env);
check(upstreamCalls > 0, "first query hits upstream");

// identical query (same IP, same qname) -> cache hit, no upstream call
const calls2 = upstreamCalls;
await mod.handleRequest(req(0x1001, "1.2.3.4"), env);
check(upstreamCalls === calls2, "second identical query served from cache (no upstream)");

// Different ECS (different IP) -> different cache key -> miss -> fans out to BOTH global upstreams
await mod.handleRequest(req(0x1002, "5.6.7.8"), env);
check(upstreamCalls === calls2 + 2, "different ECS forces a new upstream (miss fans out to both upstreams)");

console.log(ok ? "\nCACHE WORKER: PASS" : "\nCACHE WORKER: FAIL");
process.exitCode = ok ? 0 : 1;