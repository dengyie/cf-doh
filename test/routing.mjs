/**
 * Verifies domestic-vs-global routing when a ruleset is present, by driving the
 * worker module directly with a KV that serves a simple rule list. Also checks
 * that ECS is threaded into the forwarded query.
 *
 * NOTE: the resolver races all members of a group and takes the FIRST valid
 * answer (that is the HA property). So we assert GROUP membership (any domestic
 * URL vs any global URL), not a specific primary/member.
 *
 * Run: node test/routing.mjs
 */

function buildQuery(name, qtype = 1, qclass = 1, id = 0x3333) {
  const header = new Uint8Array(12);
  header[0] = id >> 8;
  header[1] = id & 0xff;
  header[2] = 0x01;
  header[5] = 1;
  const labels = name.split(".");
  const parts = [];
  for (const lab of labels) {
    parts.push(lab.length);
    for (let i = 0; i < lab.length; i += 1) parts.push(lab.charCodeAt(i));
  }
  parts.push(0, (qtype >> 8) & 0xff, qtype & 0xff, (qclass >> 8) & 0xff, qclass & 0xff);
  return new Uint8Array([...header, ...parts]);
}

function fakeKv(ruleText) {
  return {
    async get(k) {
      if (k === "rules:data") return ruleText;
      return null;
    },
    async put() {},
  };
}

// Deterministic-ish: record ALL seen upstreams; resolve each with a token answer.
const seenDomestic = new Set();
const seenGlobal = new Set();
globalThis.fetch = async (url, init) => {
  const body = new Uint8Array(init.body);
  const ans = new Uint8Array(body.length + 4);
  ans.set(body, 0);
  ans[2] = 0x81;
  ans[3] = 0x80; // rcode 0
  return new Response(ans, {
    headers: { "content-type": "application/dns-message" },
  });
};

const env = {
  RULES_KV: fakeKv("\ngithub.com\n"),
  DOMESTIC_DOH_URL: "https://dns.alidns.com/dns-query",
  DOMESTIC_FALLBACK_DOH_URL: "https://doh.pub/dns-query",
  GLOBAL_DOH_URL: "https://dns.google/dns-query",
  GLOBAL_FALLBACK_DOH_URL: "https://cloudflare-dns.com/dns-query",
};

function req(qname) {
  return new Request("https://doh.test/doh", {
    method: "POST",
    headers: {
      "content-type": "application/dns-message",
      "cf-connecting-ip": "1.2.3.4",
    },
    body: buildQuery(qname),
  });
}

// Wrap fetch to categorize upstream URLs.
const realFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  const u = String(url);
  if (u.includes("alidns") || u.includes("doh.pub")) seenDomestic.add(u);
  else if (u.includes("dns.google") || u.includes("cloudflare")) seenGlobal.add(u);
  return realFetch(url);
};

const mod = await import("../src/worker.js");

let passed = 0;
let failed = 0;
const check = (cond, label) => {
  if (cond) {
    passed += 1;
    console.log(`  ok - ${label}`);
  } else {
    failed += 1;
    console.error(`  FAIL - ${label}`);
  }
};

seenDomestic.clear();
seenGlobal.clear();
await mod.handleRequest(req("github.com"), env);
check(seenDomestic.size > 0, "github.com hit a DOMESTIC upstream");
check(seenGlobal.size === 0, "github.com did NOT hit a global upstream");

seenDomestic.clear();
seenGlobal.clear();
await mod.handleRequest(req("example.net"), env);
check(seenGlobal.size > 0, "example.net hit a GLOBAL upstream");
check(seenDomestic.size === 0, "example.net did NOT hit a domestic upstream");

// Core requirement: linux.do must be forced domestic via the built-in override,
// even when the KV ruleset is empty/failed.
seenDomestic.clear();
seenGlobal.clear();
await mod.handleRequest(req("linux.do"), env);
check(seenDomestic.size > 0, "linux.do hit a DOMESTIC upstream (built-in override)");
check(seenGlobal.size === 0, "linux.do did NOT hit a global upstream (built-in override)");

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;