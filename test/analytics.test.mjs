import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { metrics } from "../src/metrics.js";
import { raceGroup } from "../src/resolver.js";

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

  // 5. raceGroup aborts slower in-flight upstream when fastest wins
  const originalFetch = globalThis.fetch;
  let slowAborted = false;
  globalThis.fetch = async (url, init) => {
    if (url.includes("fast")) {
      const resp = new Uint8Array(16);
      resp[2] = 0x81; resp[3] = 0x80; // NOERROR response
      return new Response(resp, { headers: { "content-type": "application/dns-message" } });
    }
    // Slow upstream
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        resolve(new Response(new Uint8Array(16), { headers: { "content-type": "application/dns-message" } }));
      }, 1000);
      if (init.signal) {
        init.signal.addEventListener("abort", () => {
          clearTimeout(timer);
          slowAborted = true;
          const err = new Error("aborted");
          err.name = "AbortError";
          reject(err);
        });
      }
    });
  };

  const dummyQuery = new Uint8Array(16);
  const raceResult = await raceGroup(["https://slow.com/dns", "https://fast.com/dns"], dummyQuery, null, {
    timeoutMs: 2000,
    maxResponseBytes: 4096,
  });
  assert.equal(raceResult.from, "https://fast.com/dns");
  // Give a small tick for signal propagation
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(slowAborted, true, "slower upstream request was successfully aborted");
  console.log("  ok - raceGroup cancels slow in-flight upstreams when fastest wins");
  globalThis.fetch = originalFetch;

  console.log("\n5 passed, 0 failed\n");
}

testAnalyticsAndStats();
