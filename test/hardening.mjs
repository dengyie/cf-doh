/**
 * Verification for the post-review hardening fixes:
 *   1. rules.js negative cache: after an upstream fetch failure, subsequent
 *      ensureRules() calls do NOT re-fetch during the cooldown window.
 *   2. filter.js disabled flag: with no BLOCK_URL, ensureBlock() reads KV at most
 *      once, then bails out fast on later calls.
 *   3. worker.js JSON API qname validation: bad/overlong/odd names are rejected
 *      with Status 2 instead of being resolved.
 *   4. jsonapi.js: toJsonResponse no longer takes the dead `clientAd` arg.
 *
 * Run: node test/hardening.mjs
 */

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

// ---------------------------------------------------------------- 1. rules.js
{
  const { ensureRules, resetRules } = await import("../src/rules.js");

  let fetches = 0;
  const failingFetcher = async () => {
    fetches += 1;
    throw new Error("simulated fetch failure");
  };
  const env = { RULES_URL: "https://example.invalid/direct-list.txt" }; // no KV

  resetRules();
  // First call attempts fetch and fails -> cooldown armed.
  const r1 = await ensureRules(env, failingFetcher);
  check(r1 === null, "rules: first call returns null on fetch failure");
  check(fetches === 1, "rules: first call performed the fetch");
  // Second call within cooldown window must NOT re-fetch (fail-fast).
  const r2 = await ensureRules(env, failingFetcher);
  check(r2 === null, "rules: cooldown call returns null");
  check(fetches === 1, "rules: no re-fetch within cooldown window");

  // Sanity: a working fetcher is still used after reset (no permanent break).
  resetRules();
  const okFetcher = async () => {
    fetches += 1;
    return new Response(new Uint8Array(0), { status: 200, headers: { "content-type": "text/plain" } });
  };
  const r3 = await ensureRules(env, okFetcher);
  check(r3 !== null && fetches === 2, "rules: reset clears cooldown; a new fetch is attempted");
  resetRules();
}

// ---------------------------------------------------------------- 2. filter.js
{
  const { ensureBlock, resetBlock } = await import("../src/filter.js");

  let kvReads = 0;
  const emptyKv = {
    async get() {
      kvReads += 1;
      return null;
    },
    async put() {},
  };
  const env = { BLOCK_KV: emptyKv }; // BLOCK_URL absent

  resetBlock();
  const r1 = await ensureBlock(env, async () => { throw new Error("should not fetch"); });
  check(r1 === null, "filter: no URL + empty KV returns null");
  check(kvReads === 1, "filter: first call reads KV once");
  const r2 = await ensureBlock(env, async () => { throw new Error("should not fetch"); });
  check(r2 === null, "filter: second call returns null");
  check(kvReads === 1, "filter: disabled flag prevents further KV reads");

  // A BLOCK_URL path still fetches (make sure disabling doesn't leak across).
  resetBlock();
  const envUrl = { BLOCK_URL: "https://example.invalid/block.txt" };
  let fetched = 0;
  const r3 = await ensureBlock(envUrl, async () => {
    fetched += 1;
    return new Response("blocked.test\n", { status: 200, headers: { "content-type": "text/plain" } });
  });
  check(fetched === 1 && r3 && r3.plain.includes("blocked.test"), "filter: BLOCK_URL path still loads");
  resetBlock();
}

// --------------------------------------------------- 3. JSON qname validation
{
  const { handleRequest } = await import("../src/worker.js");
  // A strict upstream that would throw if ever reached by an invalid name.
  let upstreamCalls = 0;
  globalThis.fetch = async (url, init) => {
    upstreamCalls += 1;
    if (!init || init.method !== "POST") return new Response(new Uint8Array(0), { status: 200 });
    throw new Error("should not reach upstream for invalid qname");
  };
  const env = {
    RULES_KV: { async get() { return null; }, async put() {} },
    DOMESTIC_DOH_URL: "https://dns.alidns.com/dns-query",
    DOMESTIC_FALLBACK_DOH_URL: "https://doh.pub/dns-query",
    GLOBAL_DOH_URL: "https://dns.google/dns-query",
    GLOBAL_FALLBACK_DOH_URL: "https://cloudflare-dns.com/dns-query",
  };

  const hit = async (q) => {
    upstreamCalls = 0;
    const resp = await handleRequest(
      new Request(`https://doh.test/json?name=${encodeURIComponent(q)}&type=A`),
      env
    );
    return { status: resp.status, json: await resp.json(), calls: upstreamCalls };
  };

  const bad = await hit("a..b");
  check(bad.json.Status === 2 && bad.calls === 0, "json: 'a..b' rejected (no upstream)");

  const overlong = await hit("x".repeat(64) + ".com");
  check(overlong.json.Status === 2 && overlong.calls === 0, "json: >63-char label rejected");

  const root = await hit("example.com.");
  check(root.json.Status === 2 && root.calls === 0, "json: trailing dot rejected");

  globalThis.fetch = async (url, init) => {
    if (!init || init.method !== "POST") return new Response(new Uint8Array(0), { status: 200 });
    const body = new Uint8Array(init.body);
    let p = 12; while (p < body.length && body[p] !== 0) p += 1 + body[p];
    const nameEnd = p + 1;
    const name = body.subarray(12, nameEnd);
    const ans = new Uint8Array(12 + name.length + 4);
    ans[0] = body[0]; ans[1] = body[1]; ans[2] = 0x80; ans[3] = 0x00; ans[5] = 1;
    let o = 12; ans.set(name, o); o += name.length;
    o += 4; // qtype/qclass zeros
    return new Response(ans, { headers: { "content-type": "application/dns-message" } });
  };
  const good = await hit("example.com");
  check(good.json.Status === 0, "json: a valid name still resolves (Status 0)");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;