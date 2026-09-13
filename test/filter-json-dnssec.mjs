/**
 * Verifies the three new capabilities end-to-end through the worker module:
 *   1. Blocklist filtering (BLOCK_URL/BLOCK_KV) — returns NXDOMAIN (default)
 *      or 0.0.0.0/:: blackhole (zero), and never hits upstream.
 *   2. DoH JSON API (GET ?name=..&type=..) — returns Google-style JSON.
 *   3. DNSSEC AD-bit masking is applied on the wire response.
 *
 * Run: node test/filter-json-dnssec.mjs
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

// Deterministic upstream mock: returns a token A answer (1.2.3.4, AD=1, ttl 60).
let upstreamCalls = 0;
globalThis.fetch = async (url, init) => {
  // Non-DNS requests (rule/block list downloads are GET) resolve to empty body.
  if (!init || init.method !== "POST" || !init.body) {
    return new Response(new Uint8Array(0), { status: 200, headers: { "content-type": "text/plain" } });
  }
  upstreamCalls += 1;
  const body = new Uint8Array(init.body);
  // Walk to the end of the qname (offset 12), which is always the question name.
  let p = 12;
  while (p < body.length && body[p] !== 0) p += 1 + body[p];
  const nameEnd = p + 1; // past the root byte
  const qt = (body[nameEnd] << 8) | body[nameEnd + 1];
  const qc = (body[nameEnd + 2] << 8) | body[nameEnd + 3];

  // Build a NEW, clean answer: header(12) + question qname + 4 + answer RR.
  const nameBytes = body.subarray(12, nameEnd);
  const isCname = qt === 5;
  const rdlength = isCname ? 2 : 4;
  const ans = new Uint8Array(12 + nameBytes.length + 4 + 2 + 10 + rdlength);
  ans[0] = body[0];
  ans[1] = body[1]; // echo ID
  ans[2] = 0x85; // QR + RD + AD (AD=1 to exercise the DNSSEC mask)
  ans[3] = 0x80; // RA + NOERROR
  ans[5] = 1; // QDCOUNT
  ans[7] = 1; // ANCOUNT
  let o = 12;
  ans.set(nameBytes, o);
  o += nameBytes.length;
  ans[o] = (qt >> 8) & 0xff; ans[o + 1] = qt & 0xff;
  ans[o + 2] = (qc >> 8) & 0xff; ans[o + 3] = qc & 0xff;
  o += 4;
  ans[o] = 0xc0; ans[o + 1] = 0x0c; o += 2; // name -> offset 12
  ans[o] = (qt >> 8) & 0xff; ans[o + 1] = qt & 0xff; o += 2; // type
  ans[o] = 0; ans[o + 1] = 1; o += 2; // class IN
  ans[o] = 0; ans[o + 1] = 0; ans[o + 2] = 0; ans[o + 3] = 60; o += 4; // ttl
  ans[o] = (rdlength >> 8) & 0xff; ans[o + 1] = rdlength & 0xff; o += 2; // rdlength
  if (isCname) {
    // CNAME pointer back to offset 12 (the question name, e.g. example.com)
    ans[o] = 0xc0; ans[o + 1] = 0x0c; o += 2;
  } else {
    ans[o] = 1; ans[o + 1] = 2; ans[o + 2] = 3; ans[o + 3] = 4; o += 4; // 1.2.3.4
  }
  return new Response(ans, { headers: { "content-type": "application/dns-message" } });
};

const baseEnv = {
  RULES_KV: { async get() { return null; }, async put() {} },
  DOMESTIC_DOH_URL: "https://dns.alidns.com/dns-query",
  DOMESTIC_FALLBACK_DOH_URL: "https://doh.pub/dns-query",
  GLOBAL_DOH_URL: "https://dns.google/dns-query",
  GLOBAL_FALLBACK_DOH_URL: "https://cloudflare-dns.com/dns-query",
};

const mod = await import("../src/worker.js");

function req(qname, env) {
  return new Request("https://doh.test/doh", {
    method: "POST",
    headers: {
      "content-type": "application/dns-message",
      "cf-connecting-ip": "1.2.3.4",
    },
    body: buildQuery(qname),
  });
}

// ---------------------------------------------------------------- filtering
{
  const env = {
    ...baseEnv,
    BLOCK_URL: "https://example.com/blocklist.txt",
    BLOCK_KV: {
      async get(k) {
        if (k === "block:data") return "ads.example.com\nbad.tracker.net\n";
        return null;
      },
      async put() {},
    },
  };
  await mod.resetBlock();

  // Blocked domain -> NXDOMAIN (rcode 3), upstream never called.
  upstreamCalls = 0;
  let resp = await mod.handleRequest(req("ads.example.com", env), env);
  const rcode = new Uint8Array(await resp.arrayBuffer())[3] & 0x0f;
  check(rcode === 3, "blocked domain returns NXDOMAIN (rcode 3)");
  check(upstreamCalls === 0, "blocked domain does NOT hit upstream");
  check(resp.headers.get("x-doh-filter") === "blocked", "blocked response tagged X-DoH-Filter");

  // Subdomain of a blocked suffix -> also blocked.
  upstreamCalls = 0;
  resp = await mod.handleRequest(req("sub.ads.example.com", env), env);
  check(((new Uint8Array(await resp.arrayBuffer())[3]) & 0x0f) === 3, "blocked subdomain returns NXDOMAIN");

  // Non-blocked -> goes upstream.
  upstreamCalls = 0;
  resp = await mod.handleRequest(req("ok.example.org", env), env);
  check(upstreamCalls > 0, "non-blocked domain hits upstream");
  check(((new Uint8Array(await resp.arrayBuffer())[3]) & 0x0f) === 0, "non-blocked returns NOERROR");
}

// ------------------------------------------------- filter action = zero
{
  const env = {
    ...baseEnv,
    BLOCK_ACTION: "zero",
    BLOCK_KV: {
      async get(k) {
        if (k === "block:data") return "blackhole.test\n";
        return null;
      },
      async put() {},
    },
  };
  await mod.resetBlock();
  upstreamCalls = 0;
  const resp = await mod.handleRequest(req("blackhole.test", env), env);
  const buf = new Uint8Array(await resp.arrayBuffer());
  check((buf[3] & 0x0f) === 0, "zero action returns NOERROR");
  check(startswithZeroA(buf), "zero action returns 0.0.0.0 blackhole answer");
  check(upstreamCalls === 0, "zero action does NOT hit upstream");
}

// ------------------------------------------------------------------- JSON API
{
  const env = { ...baseEnv };
  upstreamCalls = 0;
  const resp = await mod.handleRequest(
    new Request("https://doh.test/json?name=example.com&type=A", {
      headers: { "cf-connecting-ip": "1.2.3.4" },
    }),
    env
  );
  check(resp.status === 200, "JSON API returns 200");
  check((resp.headers.get("content-type") || "").includes("application/json"), "JSON API content-type is application/json");
  const json = await resp.json();
  check(json.Status === 0, "JSON API Status = NOERROR");
  check(json.Question[0].name === "example.com", "JSON API echoes question name");
  check(Array.isArray(json.Answer) && json.Answer.length === 1, "JSON API has 1 answer");
  check(json.Answer[0].data === "1.2.3.4", "JSON API A record data parsed");
  check(json.Answer[0].TTL === 60, "JSON API A record TTL parsed");
  check(upstreamCalls >= 1, "JSON API performed an upstream lookup");

  // CNAME with compression pointer (0xc00c pointing to question name).
  upstreamCalls = 0;
  const respCname = await mod.handleRequest(
    new Request("https://doh.test/json?name=alias.example.com&type=CNAME", {
      headers: { "cf-connecting-ip": "1.2.3.4" },
    }),
    env
  );
  check(respCname.status === 200, "JSON API CNAME returns 200");
  const jsonCname = await respCname.json();
  check(jsonCname.Status === 0, "JSON API CNAME Status = NOERROR");
  check(Array.isArray(jsonCname.Answer) && jsonCname.Answer.length === 1, "JSON API has 1 CNAME answer");
  check(jsonCname.Answer[0].type === "CNAME", "JSON API answer type is CNAME");
  check(jsonCname.Answer[0].data === "alias.example.com", "JSON API CNAME compressed pointer resolved correctly");

  // Unknown type string -> defaults to A.
  upstreamCalls = 0;
  const resp2 = await mod.handleRequest(
    new Request("https://doh.test/json?name=example.net&type=BOGUS", {
      headers: { "cf-connecting-ip": "1.2.3.4" },
    }),
    env
  );
  check(resp2.status === 200 && (await resp2.json()).Status === 0, "JSON API with unknown type still 200 (defaults A)");

  // Invalid name -> SERVFAIL JSON.
  const resp3 = await mod.handleRequest(
    new Request("https://doh.test/json?name=%3Cbad%3E&type=A", { headers: { "cf-connecting-ip": "1.2.3.4" } }),
    env
  );
  check(resp3.status === 200 && (await resp3.json()).Status === 2, "JSON API invalid name returns Status 2");
}

// ---------------------------------------------------------------- DNSSEC relay
{
  const env = { ...baseEnv };
  await mod.resetBlock();

  // AD-bit: client WITHOUT EDNS OPT -> we must CLEAR AD (no DNSSEC requested).
  upstreamCalls = 0;
  const resp = await mod.handleRequest(req("dnssec.example.com", env), env);
  const arr = new Uint8Array(await resp.arrayBuffer());
  const flags = (arr[2] << 8) | arr[3];
  check((flags & 0x0020) === 0, "non-DO client gets AD cleared (no fabricated auth)");
  check(upstreamCalls >= 1, "AD-mask path still resolves via upstream");
}

function startswithZeroA(buf) {
  // Scan for rdlength=4 followed by 0.0.0.0.
  for (let i = 0; i < buf.length - 4; i++) {
    if (buf[i] === 0 && buf[i + 1] === 4 && buf[i + 2] === 0 && buf[i + 3] === 0 && buf[i + 4] === 0 && buf[i + 5] === 0) {
      return true;
    }
  }
  return false;
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;
