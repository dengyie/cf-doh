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
};

let startedAt = Date.now();

export function inc(name, n = 1) {
  COUNTERS[name] = (COUNTERS[name] || 0) + n;
}

export function snapshot() {
  return { ...COUNTERS };
}

export function healthResponse(config) {
  const body = JSON.stringify(
    {
      status: "ok",
      service: "cf-doh",
      version: "1.0.0",
      uptimeSec: Math.round((Date.now() - startedAt) / 1000),
      counters: snapshot(),
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

// Namespaced alias so worker.js can use `metrics.inc(...)` directly.
export const metrics = { inc, snapshot, healthResponse };