/**
 * Environment-variable configuration with centralized defaults and validation.
 *
 * All tunables live here so the worker is extended/adjusted from `wrangler.jsonc`
 * without touching logic. Invalid values fall back to sane defaults.
 */

const DEFAULT = {
  path: "/doh",
  domesticPrimary: "https://dns.alidns.com/dns-query",
  domesticFallback: "https://doh.pub/dns-query",
  globalPrimary: "https://dns.google/dns-query",
  globalFallback: "https://cloudflare-dns.com/dns-query",
  ecsV4Prefix: 24,
  ecsV6Prefix: 56,
  upstreamTimeoutMs: 3000,
  maxQueryBytes: 4096,
  maxResponseBytes: 65535,
  maxTtlSeconds: 3600,
  cacheTtlSeconds: 300,
  rulesRefreshMin: 15,
};

function asSingle(s, fallback) {
  if (!s) return fallback;
  const v = String(s).trim();
  return v ? v : fallback;
}

function parseUint(val, fallback, min = 0, max = Infinity) {
  const n = Number(val);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.floor(n)));
}

export function readConfig(env) {
  const path = asSingle(env.DOH_PATH, DEFAULT.path);
  const config = {
    path: path.startsWith("/") ? path : `/${path}`,
    domesticUrls: [
      asSingle(env.DOMESTIC_DOH_URL, DEFAULT.domesticPrimary),
      asSingle(env.DOMESTIC_FALLBACK_DOH_URL, DEFAULT.domesticFallback),
    ],
    globalUrls: [
      asSingle(env.GLOBAL_DOH_URL, DEFAULT.globalPrimary),
      asSingle(env.GLOBAL_FALLBACK_DOH_URL, DEFAULT.globalFallback),
    ],
    ecsV4Prefix: parseUint(env.ECS_IPV4_PREFIX, DEFAULT.ecsV4Prefix, 8, 32),
    ecsV6Prefix: parseUint(env.ECS_IPV6_PREFIX, DEFAULT.ecsV6Prefix, 8, 128),
    upstreamTimeoutMs: parseUint(env.UPSTREAM_TIMEOUT_MS, DEFAULT.upstreamTimeoutMs, 500, 10000),
    maxQueryBytes: parseUint(env.MAX_QUERY_BYTES, DEFAULT.maxQueryBytes, 512, 8192),
    maxResponseBytes: parseUint(env.MAX_RESPONSE_BYTES, DEFAULT.maxResponseBytes, 512, 65535),
    maxTtlSeconds: parseUint(env.MAX_TTL_SECONDS, DEFAULT.maxTtlSeconds, 0, 86400),
    cacheTtlSeconds: parseUint(env.CACHE_TTL_SECONDS, DEFAULT.cacheTtlSeconds, 0, 86400),
    rulesUrl: asSingle(env.RULES_URL, DEFAULT.rulesUrl),
    rulesCacheMin: parseUint(env.RULES_CACHE_MIN, DEFAULT.rulesMin, 1, 1440),
    token: asSingle(env.DOH_TOKEN, ""),
    pageUrl: asSingle(env.PAGE_URL, ""),
  };
  return config;
}

export { DEFAULT };