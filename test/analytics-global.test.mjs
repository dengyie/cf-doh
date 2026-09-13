import test from "node:test";
import assert from "node:assert/strict";
import { parseAnalyticsRows, queryGlobalStats, globalStatsResponse, metrics } from "../src/metrics.js";
import worker from "../src/worker.js";

test("parseAnalyticsRows handles empty and null rows gracefully", () => {
  const parsed = parseAnalyticsRows([], {});
  assert.equal(parsed.scope, "global");
  assert.equal(parsed.available, true);
  assert.equal(parsed.totalRequests, 0);
  assert.equal(parsed.cache.hitRate, "0.0%");
  assert.equal(parsed.latency.domestic.count, 0);
  assert.equal(parsed.upstreams.domestic.totalWins, 0);
});

test("parseAnalyticsRows correctly aggregates win rates and weighted latencies", () => {
  const sampleRows = [
    {
      host: "dns.alidns.com",
      group_name: "domestic",
      cache_status: "miss",
      total_count: 80,
      avg_duration: 15.0,
      p50: 12.0,
      p90: 20.0,
      p95: 25.0,
      min_duration: 8.0,
      max_duration: 50.0,
    },
    {
      host: "doh.pub",
      group_name: "domestic",
      cache_status: "miss",
      total_count: 20,
      avg_duration: 25.0,
      p50: 20.0,
      p90: 35.0,
      p95: 40.0,
      min_duration: 12.0,
      max_duration: 60.0,
    },
    {
      host: "dns.google",
      group_name: "global",
      cache_status: "miss",
      total_count: 60,
      avg_duration: 80.0,
      p50: 75.0,
      p90: 95.0,
      p95: 110.0,
      min_duration: 60.0,
      max_duration: 180.0,
    },
    {
      host: "cloudflare-dns.com",
      group_name: "global",
      cache_status: "miss",
      total_count: 40,
      avg_duration: 90.0,
      p50: 85.0,
      p90: 105.0,
      p95: 120.0,
      min_duration: 65.0,
      max_duration: 200.0,
    },
    {
      host: "cache",
      group_name: "domestic",
      cache_status: "hit",
      total_count: 50,
      avg_duration: 0.2,
      p50: 0.1,
      p90: 0.5,
      p95: 0.8,
      min_duration: 0.1,
      max_duration: 1.2,
    },
  ];

  const config = {
    domesticUrls: ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
    globalUrls: ["https://dns.google/dns-query", "https://cloudflare-dns.com/dns-query"],
  };

  const parsed = parseAnalyticsRows(sampleRows, config);

  assert.equal(parsed.totalRequests, 250);
  assert.equal(parsed.cache.hits, 50);
  assert.equal(parsed.cache.misses, 200);
  assert.equal(parsed.cache.hitRate, "20.0%");

  // Domestic wins: 80 vs 20 -> 80% vs 20%
  const dom = parsed.upstreams.domestic;
  assert.equal(dom.totalWins, 100);
  assert.equal(dom.upstreams["dns.alidns.com"].wins, 80);
  assert.equal(dom.upstreams["dns.alidns.com"].winRate, "80.0%");
  assert.equal(dom.upstreams["doh.pub"].wins, 20);
  assert.equal(dom.upstreams["doh.pub"].winRate, "20.0%");

  // Domestic latency weighted avg: (80*15 + 20*25)/100 = 17.0 ms
  assert.equal(parsed.latency.domestic.avgMs, 17);
  assert.equal(parsed.latency.domestic.p95Ms, 40); // max p95
  assert.equal(parsed.latency.domestic.minMs, 8);
  assert.equal(parsed.latency.domestic.maxMs, 60);

  // Global wins: 60 vs 40 -> 60% vs 40%
  const glob = parsed.upstreams.global;
  assert.equal(glob.totalWins, 100);
  assert.equal(glob.upstreams["dns.google"].wins, 60);
  assert.equal(glob.upstreams["dns.google"].winRate, "60.0%");
  assert.equal(glob.upstreams["cloudflare-dns.com"].wins, 40);
  assert.equal(glob.upstreams["cloudflare-dns.com"].winRate, "40.0%");
});

test("queryGlobalStats returns helpful fallback when credentials are missing", async () => {
  const res = await queryGlobalStats({}, {});
  assert.equal(res.scope, "global");
  assert.equal(res.available, false);
  assert.equal(res.reason, "missing_credentials");
  assert.ok(res.message.includes("CF_ACCOUNT_ID"));
  assert.ok(res.fallback);
});

test("queryGlobalStats calls Cloudflare API and parses returned data when credentials provided", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async (url, opts) => {
      assert.ok(url.includes("analytics_engine/sql"));
      assert.equal(opts.method, "POST");
      assert.equal(opts.headers.Authorization, "Bearer mock-token");
      assert.ok(opts.body.includes("SELECT"));

      return new Response(
        JSON.stringify({
          meta: [],
          data: [
            {
              host: "dns.alidns.com",
              group_name: "domestic",
              cache_status: "miss",
              total_count: 10,
              avg_duration: 12.0,
              p50: 10.0,
              p90: 15.0,
              p95: 18.0,
              min_duration: 5.0,
              max_duration: 25.0,
            },
          ],
          rows: 1,
        }),
        { status: 200, headers: { "Content-Type": "application/json" } }
      );
    };

    const env = {
      CF_ACCOUNT_ID: "mock-account-id",
      CF_ANALYTICS_READ_TOKEN: "mock-token",
    };
    const res = await queryGlobalStats(env, {});
    assert.equal(res.scope, "global");
    assert.equal(res.available, true);
    assert.equal(res.totalRequests, 10);
    assert.equal(res.upstreams.domestic.upstreams["dns.alidns.com"].wins, 10);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("queryGlobalStats returns graceful fallback when API returns error", async () => {
  const originalFetch = globalThis.fetch;
  try {
    globalThis.fetch = async () => {
      return new Response("Dataset not found", { status: 404 });
    };

    const env = {
      CF_ACCOUNT_ID: "mock-account-id",
      CF_ANALYTICS_READ_TOKEN: "mock-token",
    };
    const res = await queryGlobalStats(env, {});
    assert.equal(res.scope, "global");
    assert.equal(res.available, false);
    assert.equal(res.reason, "http_404");
    assert.ok(res.fallback);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("Worker routes /api/stats?scope=global and /api/stats/global properly", async () => {
  const req1 = new Request("https://doh.example/api/stats?scope=global");
  const resp1 = await worker.fetch(req1, {});
  assert.equal(resp1.status, 200);
  const json1 = await resp1.json();
  assert.equal(json1.scope, "global");

  const req2 = new Request("https://doh.example/api/stats/global");
  const resp2 = await worker.fetch(req2, {});
  assert.equal(resp2.status, 200);
  const json2 = await resp2.json();
  assert.equal(json2.scope, "global");

  const req3 = new Request("https://doh.example/api/stats");
  const resp3 = await worker.fetch(req3, {});
  assert.equal(resp3.status, 200);
  const json3 = await resp3.json();
  assert.equal(json3.service, "cf-doh");
    assert.equal(typeof json3.scope, "undefined"); // Local snapshot
  });

  test("queryGlobalStats enforces interval allowlist", async () => {
    const originalFetch = globalThis.fetch;
    try {
      let capturedSql = "";
      globalThis.fetch = async (_url, opts) => {
        capturedSql = opts.body;
        return new Response(JSON.stringify({ data: [] }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      };

      const env = {
        CF_ACCOUNT_ID: "mock-account-id",
        CF_ANALYTICS_READ_TOKEN: "mock-token",
      };

      // Valid interval '7 DAY'
      await queryGlobalStats(env, {}, { interval: "7 DAY" });
      assert.ok(capturedSql.includes("INTERVAL '7 DAY'"), "valid interval 7 DAY preserved");

      // Invalid/dangerous interval should fallback to '1 DAY'
      await queryGlobalStats(env, {}, { interval: "999999 DAY" });
      assert.ok(capturedSql.includes("INTERVAL '1 DAY'"), "out-of-allowlist interval falls back to 1 DAY");

      await queryGlobalStats(env, {}, { interval: "1 MICROSECOND" });
      assert.ok(capturedSql.includes("INTERVAL '1 DAY'"), "unsupported interval falls back to 1 DAY");
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
