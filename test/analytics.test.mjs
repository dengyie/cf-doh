import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { metrics } from "../src/metrics.js";

async function testAnalyticsAndStats() {
  console.log("=== analytics.test.mjs ===");
  metrics.resetMetrics();

  // 1. In-memory win tracking and percentiles
  metrics.recordUpstreamRace("domestic", "https://dns.alidns.com/dns-query", 12.5);
  metrics.recordUpstreamRace("domestic", "https://dns.alidns.com/dns-query", 18.0);
  metrics.recordUpstreamRace("domestic", "https://doh.pub/dns-query", 25.4);
  metrics.recordUpstreamRace("global", "https://dns.google/dns-query", 45.0);
  metrics.recordUpstreamRace("global", "https://cloudflare-dns.com/dns-query", 55.2);

  const snap = metrics.statsSnapshot();
  assert.equal(snap.upstreams.domestic.upstreams["dns.alidns.com"].wins, 2);
  assert.equal(snap.upstreams.domestic.upstreams["doh.pub"].wins, 1);
  assert.equal(snap.upstreams.domestic.upstreams["dns.alidns.com"].winRate, "66.7%");
  assert.equal(snap.upstreams.domestic.upstreams["doh.pub"].winRate, "33.3%");
  console.log("  ok - recordUpstreamRace correctly tallies wins and percentages");

  assert.equal(snap.latency.domestic.count, 3);
  assert.equal(snap.latency.domestic.p50Ms, 18);
  assert.equal(snap.latency.domestic.minMs, 12.5);
  assert.equal(snap.latency.domestic.maxMs, 25.4);
  assert.equal(snap.latency.domestic.avgMs, 18.6);
  console.log("  ok - latency percentiles (P50, min, max, avg) computed accurately");

  // 2. Analytics Engine data point write
  let capturedPoint = null;
  const mockEnv = {
    DOH_ANALYTICS: {
      writeDataPoint(data) {
        capturedPoint = data;
      },
    },
  };

  metrics.recordAnalyticsPoint(mockEnv, {
    group: "domestic",
    winnerUrl: "https://dns.alidns.com/dns-query",
    durationMs: 14.8,
    qtype: "A",
    rcode: "NOERROR",
    cacheStatus: "miss",
  });

  assert.ok(capturedPoint, "Analytics Engine data point captured");
  assert.equal(capturedPoint.blobs[0], "dns.alidns.com", "blob 0 is hostname");
  assert.equal(capturedPoint.blobs[1], "domestic", "blob 1 is group");
  assert.equal(capturedPoint.blobs[2], "A", "blob 2 is qtype");
  assert.equal(capturedPoint.blobs[3], "NOERROR", "blob 3 is rcode");
  assert.equal(capturedPoint.blobs[4], "miss", "blob 4 is cacheStatus");
  assert.equal(capturedPoint.doubles[0], 14.8, "double 0 is durationMs");
  assert.equal(capturedPoint.indexes[0], "dns.alidns.com", "index 0 is hostname");
  console.log("  ok - Analytics Engine writeDataPoint matches schema");

  // 3. /api/stats endpoint
  const statsReq = new Request("https://doh.example.com/api/stats", { method: "GET" });
  const statsResp = await worker.fetch(statsReq, {});
  assert.equal(statsResp.status, 200);
  assert.ok(statsResp.headers.get("Content-Type").includes("application/json"));
  assert.equal(statsResp.headers.get("Access-Control-Allow-Origin"), "*");
  const statsJson = await statsResp.json();
  assert.equal(statsJson.service, "cf-doh");
  assert.ok(statsJson.latency.domestic);
  assert.ok(statsJson.upstreams.domestic);
  console.log("  ok - /api/stats returns 200 with structured metrics JSON");

  // 4. /healthz includes stats snapshot
  const healthReq = new Request("https://doh.example.com/healthz", { method: "GET" });
  const healthResp = await worker.fetch(healthReq, {});
  assert.equal(healthResp.status, 200);
  const healthJson = await healthResp.json();
  assert.ok(healthJson.stats, "health response contains stats field");
  assert.ok(healthJson.counters, "health response contains counters field");
  console.log("  ok - /healthz response includes embedded stats and counters");

  console.log("\n4 passed, 0 failed\n");
}

testAnalyticsAndStats();
