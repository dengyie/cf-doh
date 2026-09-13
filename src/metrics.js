/**
 * Lightweight structured metrics for the DoH worker.
 *
 * A small in-memory counter object, exposed both as individual functions and as
 * a namespaced object so the single-file bundle can reference `metrics.inc`
 * without a namespace import. For production you can sink these to a log/metrics
 * backend (Workers Analytics / R2) without touching the query path.
 */

const COUNTERS = {
  requests: 0,
  get: 0,
  post: 0,
  ok: 0,
  formerr: 0,
  servfail: 0,
  upstream_timeouts: 0,
  upstream_errors: 0,
  upstream_ok: 0,
  upstream_servfail: 0,
  cache_hit: 0,
  cache_miss: 0,
  rules_fetch: 0,
  rules_unchanged: 0,
  rules_fetch_fail: 0,
  filter_blocked: 0,
};

let startedAt = Date.now();

// Upstream win tracker: hostname -> win count
const UPSTREAM_WINS = {};

// Fixed-capacity ring buffers for latency percentiles (P50, P90, P95)
const MAX_SAMPLES = 300;
const LATENCY_SAMPLES = {
  domestic: [],
  global: [],
};

export function inc(name, n = 1) {
  COUNTERS[name] = (COUNTERS[name] || 0) + n;
}

export function snapshot() {
  return { ...COUNTERS };
}

export function recordUpstreamRace(group, winnerUrl, durationMs) {
  let host = "unknown";
  if (winnerUrl) {
    try {
      host = new URL(winnerUrl).hostname;
    } catch {
      host = String(winnerUrl);
    }
  }
  UPSTREAM_WINS[host] = (UPSTREAM_WINS[host] || 0) + 1;

  const key = group === "domestic" ? "domestic" : "global";
  if (typeof durationMs === "number" && durationMs >= 0) {
    const arr = LATENCY_SAMPLES[key];
    if (arr.length >= MAX_SAMPLES) arr.shift();
    arr.push(Math.round(durationMs * 10) / 10);
  }
}

export function recordAnalyticsPoint(env, { group, winnerUrl, durationMs, qtype, rcode, cacheStatus }) {
  if (env && env.DOH_ANALYTICS && typeof env.DOH_ANALYTICS.writeDataPoint === "function") {
    let host = "cache";
    if (winnerUrl && winnerUrl !== "cache") {
      try {
        host = new URL(winnerUrl).hostname;
      } catch {
        host = String(winnerUrl);
      }
    }
    try {
      env.DOH_ANALYTICS.writeDataPoint({
        blobs: [
          host,
          group || "unknown",
          qtype ? String(qtype) : "A",
          rcode ? String(rcode) : "NOERROR",
          cacheStatus || "miss",
        ],
        doubles: [typeof durationMs === "number" ? durationMs : 0],
        indexes: [host],
      });
    } catch {
      /* best-effort Analytics Engine write */
    }
  }
}

function computePercentiles(samples) {
  if (!samples || samples.length === 0) {
    return { count: 0, avgMs: 0, p50Ms: 0, p90Ms: 0, p95Ms: 0, minMs: 0, maxMs: 0 };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = samples.reduce((acc, v) => acc + v, 0);
  return {
    count: samples.length,
    avgMs: Math.round((sum / samples.length) * 10) / 10,
    p50Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.5))],
    p90Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.9))],
    p95Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))],
    minMs: sorted[0],
    maxMs: sorted[sorted.length - 1],
  };
}

export function statsSnapshot(config = {}) {
  const domesticUrls = config.domesticUrls || [
    config.domesticUrl || "https://dns.alidns.com/dns-query",
    config.domesticFallbackUrl || "https://doh.pub/dns-query",
  ];
  const globalUrls = config.globalUrls || [
    config.globalUrl || "https://dns.google/dns-query",
    config.globalFallbackUrl || "https://cloudflare-dns.com/dns-query",
  ];

  function buildGroupStats(urls) {
    const list = urls.map((u) => {
      let host = u;
      try {
        host = new URL(u).hostname;
      } catch {}
      return { url: u, host, wins: UPSTREAM_WINS[host] || 0 };
    });
    const totalWins = list.reduce((acc, item) => acc + item.wins, 0);
    const result = {};
    for (const item of list) {
      result[item.host] = {
        wins: item.wins,
        winRate: totalWins > 0 ? `${((item.wins / totalWins) * 100).toFixed(1)}%` : "0.0%",
      };
    }
    return { upstreams: result, totalWins };
  }

  const domesticStats = buildGroupStats(domesticUrls);
  const globalStats = buildGroupStats(globalUrls);

  const totalCacheRequests = COUNTERS.cache_hit + COUNTERS.cache_miss;
  const cacheHitRate =
    totalCacheRequests > 0
      ? `${((COUNTERS.cache_hit / totalCacheRequests) * 100).toFixed(1)}%`
      : "0.0%";

  return {
    service: "cf-doh",
    version: "1.1.0",
    uptimeSec: Math.round((Date.now() - startedAt) / 1000),
    totalRequests: COUNTERS.requests,
    cache: {
      hits: COUNTERS.cache_hit,
      misses: COUNTERS.cache_miss,
      hitRate: cacheHitRate,
    },
    latency: {
      domestic: computePercentiles(LATENCY_SAMPLES.domestic),
      global: computePercentiles(LATENCY_SAMPLES.global),
    },
    upstreams: {
      domestic: domesticStats,
      global: globalStats,
    },
    rawWins: { ...UPSTREAM_WINS },
  };
}

export function statsResponse(config) {
  const body = JSON.stringify(statsSnapshot(config), null, 2);
  return new Response(body, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

export function healthResponse(config) {
  const body = JSON.stringify(
    {
      status: "ok",
      service: "cf-doh",
      version: "1.1.0",
      uptimeSec: Math.round((Date.now() - startedAt) / 1000),
      counters: snapshot(),
      stats: statsSnapshot(config),
      config: {
        path: config.path,
        upstreams: { domestic: config.domesticUrls, global: config.globalUrls },
        ecs: { v4: config.ecsV4Prefix, v6: config.ecsV6Prefix },
      },
    },
    null,
    2
  );
  return new Response(body, {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" },
  });
}

export function resetMetrics() {
  for (const k of Object.keys(COUNTERS)) COUNTERS[k] = 0;
  for (const k of Object.keys(UPSTREAM_WINS)) delete UPSTREAM_WINS[k];
  LATENCY_SAMPLES.domestic.length = 0;
  LATENCY_SAMPLES.global.length = 0;
  startedAt = Date.now();
}

// Namespaced alias so worker.js can use `metrics.inc(...)` directly.
export const metrics = {
  inc,
  snapshot,
  recordUpstreamRace,
  recordAnalyticsPoint,
  statsSnapshot,
  statsResponse,
  healthResponse,
  resetMetrics,
};