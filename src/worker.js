/**
 * Cloudflare Worker — self-hosted DNS-over-HTTPS (DoH) resolver.
 *
 * Features:
 *   - RFC 8484 (GET ?dns=base64url + POST application/dns-message)
 *   - Domestic/global domain split (github outlets via Aliyun + ECS)
 *   - EDNS Client Subnet (ECS) injection from the trusted Cloudflare client IP
 *   - Concurrent upstream fan-out with failover (high availability)
 *   - Cron rules refresh, KV-backed durability
 *   - /healthz and /metrics
 *
 * Zero-build module worker. Used directly by Wrangler or bundled into
 * `dists/worker-single.js` (still dependency-free).
 */

import { readConfig } from "./config.js";
import { buildErrorResponse, DNS_CONTENT_TYPE, parseDnsMessage } from "./dns.js";
import { encodeEcsRdata, wrapEcsOption } from "./ecs.js";
import { subnetForEcs } from "./ip.js";
import { ensureRules, isDomestic, refreshRules, resetRules } from "./rules.js";
import { raceGroup, serverFailure } from "./resolver.js";
import { metrics } from "./metrics.js";
import { createCache } from "./cache.js";
import { answerTtlSeconds } from "./dns.js";

export { parseDnsMessage, DNS_CONTENT_TYPE };

// ---- request body helpers -------------------------------------------------

function decodeBase64Url(value) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]*$/.test(value)) return null;
  let v = value.replace(/-/g, "+").replace(/_/g, "/");
  while (v.length % 4 !== 0) v += "=";
  try {
    const bin = atob(v);
    if (bin.length === 0) return null;
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

function dnsResponse(body, extraHeaders) {
  return new Response(body, {
    status: 200,
    headers: {
      "Content-Type": DNS_CONTENT_TYPE,
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...(extraHeaders || {}),
    },
  });
}

/** Return { query } or { error }. */
async function readDnsQuery(request, config) {
  const url = new URL(request.url);
  if (url.pathname !== config.path) return { error: "not_found" };
  if (request.method === "GET") {
    const values = url.searchParams.getAll("dns");
    if (values.length !== 1) return { error: "bad_get" };
    const decoded = decodeBase64Url(values[0]);
    if (!decoded || decoded.byteLength === 0) return { error: "bad_get" };
    if (decoded.byteLength > config.maxQueryBytes) return { error: "too_large" };
    return { query: decoded };
  }
  if (request.method === "POST") {
    const type = (request.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
    if (type !== DNS_CONTENT_TYPE) return { error: "unsupported_media" };
    const body = await request.arrayBuffer();
    if (body.byteLength === 0) return { error: "empty" };
    if (body.byteLength > config.maxQueryBytes) return { error: "too_large" };
    return { query: new Uint8Array(body) };
  }
  return { error: "method_not_allowed" };
}

// ---- ECS query splicing ----------------------------------------------------

/** Append an EDNS0 OPT record carrying an ECS option, bumping ARCOUNT. */
function appendEcsOpt(query, subnet) {
  const rdata = encodeEcsRdata(subnet.family, subnet.network, subnet.prefixLength);
  const option = wrapEcsOption(rdata); // 4-byte header + rdata
  const opt = new Uint8Array(1 + 2 + 2 + 4 + 2 + option.length);
  opt[0] = 0; // root name
  opt[1] = 0;
  opt[2] = 41; // type OPT
  opt[3] = 0x04;
  opt[4] = 0xd0; // class = UDP payload 1232
  opt[5] = 0;
  opt[6] = 0;
  opt[7] = 0;
  opt[8] = 0; // ttl 0
  opt[9] = (option.length >> 8) & 0xff;
  opt[10] = option.length & 0xff;
  opt.set(option, 11);

  const out = new Uint8Array(query.length + opt.length);
  out.set(query, 0);
  out.set(opt, query.length);
  const oldAr = ((query[10] << 8) | query[11]) & 0xffff;
  const newAr = oldAr + 1;
  out[10] = (newAr >> 8) & 0xff;
  out[11] = newAr & 0xff;
  return out;
}

// ---- main handler -----------------------------------------------------------

export async function handleRequest(request, env) {
  const config = readConfig(env);
  metrics.inc("requests");
  const url = new URL(request.url);

  if (url.pathname === "/healthz" || url.pathname === "/metrics") {
    return metrics.healthResponse(config);
  }
  if (url.pathname === "/" && request.method === "GET") {
    return new Response(
      "Cloudflare Workers DoH resolver. Query path: " +
        `${url.origin}${config.path} (RFC 8484).`,
      { headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" } }
    );
  }

  // Optional secret-path / token guard.
  if (config.token) {
    const submitted = url.searchParams.get("token") || request.headers.get("x-doh-token") || "";
    if (submitted !== config.token) return new Response("Forbidden", { status: 403 });
  }

  const read = await readDnsQuery(request, config);
  if (read.error) {
    metrics.inc("formerr");
    const code =
      read.error === "not_found" ? 404 :
      read.error === "method_not_allowed" ? 405 :
      read.error === "too_large" ? 413 :
      read.error === "unsupported_media" ? 415 : 400;
    return new Response(code === 400 ? "Bad Request" : "", { status: code });
  }

  metrics.inc(request.method === "GET" ? "get" : "post");

  // Parse the wire-format query.
  let parsed;
  try {
    parsed = parseDnsMessage(read.query);
  } catch {
    metrics.inc("formerr");
    return dnsResponse(buildErrorResponse(read.query, 1, null));
  }

  // Route by rules: domestic (China-direct) vs global.
  let rules = null;
  try {
    rules = await ensureRules(env);
  } catch {
    rules = null;
  }
  const domestic = isDomestic(parsed.question.name, rules);

  // Attach ECS (client subnet) using the trusted CF client IP.
  const subnet = subnetForEcs(
    request.headers.get("cf-connecting-ip"),
    config.ecsV4Prefix,
    config.ecsV6Prefix
  );
  const ecsKey = subnet ? `${subnet.family}:${subnet.network.join(".")}` : "none";
  const result = await resolveWithCache(parsed, read.query, subnet, ecsKey, url, domestic, config);

  if (!result) {
    metrics.inc("servfail");
    return dnsResponse(serverFailure(read.query, parsed.question));
  }
  metrics.inc("ok");
  return dnsResponse(result.answer);
}

const dnsCache = createCache();

async function resolveWithCache(parsed, query, subnet, ecsKey, url, domestic, config) {
  const qname = parsed.question.name;
  const qtype = parsed.question.qtype;

  // 1) Cache hit?
  if (config.cacheTtlSeconds > 0) {
    const cached = dnsCache.get(qname, qtype, ecsKey);
    if (cached) {
      metrics.inc("cache_hit");
      return { answer: cached };
    }
    metrics.inc("cache_miss");
  }

  const forwarded = subnet ? appendEcsOpt(query, subnet) : query;
  const urls = domestic ? config.domesticUrls : config.globalUrls;
  const result = await raceGroup(urls, forwarded, parsed, {
    timeoutMs: config.upstreamTimeoutMs,
    maxResponseBytes: config.maxResponseBytes,
    on: ({ kind }) => {
      if (kind === "ok") metrics.inc("upstream_ok");
      else if (kind === "timeout") metrics.inc("upstream_timeouts");
      else if (kind === "servfail") metrics.inc("upstream_servfail");
      else metrics.inc("upstream_errors");
    },
  });

  if (!result) return null;
  if (config.cacheTtlSeconds > 0) {
    // Cache for min(answer TTL, config TTL).
    let ttl = answerTtlSeconds(result.answer, parsed);
    if (ttl <= 0) ttl = config.cacheTtlSeconds;
    dnsCache.set(qname, qtype, ecsKey, result.answer, Math.min(ttl, config.cacheTtlSeconds));
  }
  return result;
}

export default {
  async fetch(request, env) {
    return handleRequest(request, env);
  },
  async scheduled(_ctrl, env) {
    try {
      const updated = await refreshRules(env);
      metrics.inc(updated ? "rules_fetch" : "rules_unchanged");
    } catch {
      metrics.inc("rules_fetch_fail");
    }
  },
};

export { resetRules, readConfig };