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
import {
  applyRelayedDnssec,
  answerTtlSeconds,
  buildErrorResponse,
  buildZeroResponse,
  clientRequestedDnssec,
  DNS_CONTENT_TYPE,
  parseDnsMessage,
} from "./dns.js";
import { encodeEcsRdata, wrapEcsOption } from "./ecs.js";
import { subnetForEcs } from "./ip.js";
import { ensureRules, isDomestic, refreshRules, resetRules, adoptRawRules } from "./rules.js";
import { ensureBlock, isBlocked, refreshBlock, resetBlock as resetBlockFn } from "./filter.js";
import { jsonResponse, toJsonResponse } from "./jsonapi.js";
import { raceGroup, serverFailure } from "./resolver.js";
import { metrics } from "./metrics.js";
import { createCache } from "./cache.js";
import { renderLandingHtml } from "./landing.js";

export { parseDnsMessage, DNS_CONTENT_TYPE };

// Type name → QTYPE number, for the DoH JSON API (?type=..).
const QTYPE_STR = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  HTTPS: 65,
};

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
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, Accept, X-DoH-Token",
      ...(extraHeaders || {}),
    },
  });
}

/** Validate a DNS name for the JSON API: per-label length <= 63, total <= 253,
 *  no empty/leading-dot labels, ASCII allowed charset. */
function isValidQname(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 253) return false;
  if (name.endsWith(".")) return false; // we normalize names without trailing dot
  const labels = name.split(".");
  if (labels.some((l) => l.length === 0 || l.length > 63)) return false;
  return /^[a-zA-Z0-9_.-]+$/.test(name) && !name.includes("..");
}

/** Build a minimal DNS wire query (one question, RD=1) from a name + type. */
function buildWireQuery(name, type) {
  const qname = name.toLowerCase();
  const labels = qname
    .split(".")
    .filter((l) => l.length > 0)
    .map((l) => new TextEncoder().encode(l));
  const qnameLen = labels.reduce((n, b) => n + 1 + b.length, 0) + 1; // + trailing root
  const out = new Uint8Array(12 + qnameLen + 4);
  out[2] = 0x01; // RD=1
  out[5] = 1; // QDCOUNT=1 (one question)
  let o = 12;
  for (const bytes of labels) {
    out[o] = bytes.length;
    out.set(bytes, o + 1);
    o += 1 + bytes.length;
  }
  out[o] = 0; // root
  o += 1;
  out[o] = (type >> 8) & 0xff; // QTYPE
  out[o + 1] = type & 0xff;
  out[o + 2] = 0; // QCLASS IN
  out[o + 3] = 1;
  return out;
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

  // Handle CORS preflight options request
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept, X-DoH-Token, Authorization, X-Rules-Secret",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  if (url.pathname === "/healthz" || url.pathname === "/metrics") {
    return metrics.healthResponse(config);
  }
  if (url.pathname === "/api/stats" || url.pathname === "/stats") {
    return metrics.statsResponse(config);
  }
  if (url.pathname === "/api/rules/sync" || url.pathname === "/rules/sync") {
    return handleRulesSync(request, url, env, config);
  }
  if (url.pathname === "/" && request.method === "GET") {
    const accept = (request.headers.get("accept") || "").toLowerCase();
    if (accept.includes("text/html") || accept.includes("*/*") || !accept) {
      return new Response(renderLandingHtml(url.origin, config), {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
        },
      });
    }
    return new Response(
      `cf-doh — Self-hosted DNS-over-HTTPS Resolver\n\n` +
        `Endpoints:\n` +
        `  • RFC 8484 DoH Query : ${url.origin}${config.path}\n` +
        `  • DoH JSON API       : ${url.origin}${config.jsonPath}?name=example.com&type=A\n` +
        `  • Health Check       : ${url.origin}/healthz\n` +
        `  • Web Console        : ${url.origin}/\n\n` +
        `GitHub: https://github.com/dengyie/cf-doh\n`,
      { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } }
    );
  }

  // Optional secret-path / token guard.
  if (config.token) {
    const submitted = url.searchParams.get("token") || request.headers.get("x-doh-token") || "";
    if (submitted !== config.token) return new Response("Forbidden", { status: 403 });
  }

  // ---- DoH JSON API (?name=..&type=..) -------------------------------------
  if (url.pathname === config.jsonPath) {
    return handleJsonQuery(request, url, env, config);
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

  const outcome = await resolveAndRelay(read.query, parsed, request, env, config);
  if (!outcome.ok) {
    metrics.inc("servfail");
    return dnsResponse(serverFailure(read.query, parsed.question));
  }
  metrics.inc("ok");
  return dnsResponse(outcome.answer, outcome.meta);
}

/**
 * Resolve a DNS query (given as raw wire bytes + parsed info) through the full
 * pipeline and return the final answer buffer:
 *   rule-based domestic/global routing → ECS injection → concurrent upstream
 *   fan-out → blocklist filter → DNSSEC AD masking.
 * Returns { ok:true, answer } or { ok:false }. `wireOnlyQuery` is the client's
 * raw query to echo in synthetic (filtered/SERVFAIL) responses; for a query we
 * synthesize ourselves (JSON API) it equals the built wire query.
 */
async function resolveAndRelay(wireQuery, parsed, request, env, config) {
  const qname = parsed.question.name;

  // Rule-based routing: domestic (China-direct) vs global.
  let rules = null;
  try {
    rules = await ensureRules(env);
  } catch {
    rules = null;
  }
  const domestic = isDomestic(qname, rules);

  // Blocklist filter.
  if (env.BLOCK_URL || env.BLOCK_KV) {
    const blockRule = await ensureBlock(env);
    if (isBlocked(qname, blockRule)) {
      metrics.inc("filter_blocked");
      const action = config.blockAction;
      const meta = { "X-DoH-Filter": "blocked" };
      if (action === "nxdomain") {
        return { ok: true, answer: buildErrorResponse(wireQuery, 3, parsed.question), meta };
      }
      if (action === "zero") {
        return { ok: true, answer: buildZeroResponse(wireQuery, parsed), meta };
      }
      // "passthrough": fall through to upstream.
    }
  }

  // ECS injection from the trusted CF client IP.
  const subnet = subnetForEcs(
    request.headers.get("cf-connecting-ip"),
    config.ecsV4Prefix,
    config.ecsV6Prefix
  );
  const ecsKey = subnet ? `${subnet.family}:${subnet.network.join(".")}` : "none";
  const result = await resolveWithCache(parsed, wireQuery, subnet, ecsKey, domestic, config, env);
  if (!result) return { ok: false };

  // DNSSEC AD masking: pass upstream AD to DNSSEC-capable clients only.
  let answer = result.answer;
  if (config.dnssec) {
    answer = answer.slice();
    applyRelayedDnssec(answer, clientRequestedDnssec(parsed));
  }
  return { ok: true, answer };
}

/** DoH JSON API: GET ?name=<qname>&type=<A|AAAA|..>. */
async function handleJsonQuery(request, url, env, config) {
  if (request.method !== "GET" && request.method !== "OPTIONS") {
    return new Response("Method Not Allowed", { status: 405 });
  }
  const qname = url.searchParams.get("name");
  const typeName = (url.searchParams.get("type") || "A").toUpperCase();
  const qtype = QTYPE_STR[typeName] ?? 1;
  if (!qname || !isValidQname(qname)) {
    return jsonResponse({ Status: 2, Question: [{ name: qname || "", type: typeName }] });
  }

  const wireQuery = buildWireQuery(qname, qtype);
  let parsed;
  try {
    parsed = parseDnsMessage(wireQuery);
  } catch {
    return jsonResponse({ Status: 2, Question: [{ name: qname, type: typeName }] });
  }

  const outcome = await resolveAndRelay(wireQuery, parsed, request, env, config);
  if (!outcome.ok) {
    return jsonResponse({ Status: 2, Question: [{ name: qname, type: typeName }] });
  }

  // min TTL for client caching.
  let minTtl = 0;
  try {
    minTtl = answerTtlSeconds(outcome.answer, parsed);
  } catch {
    minTtl = 0;
  }
  // AD reflects whatever the masked wire answer carries (JSON clients don't send
  // EDNS DO, so resolveAndRelay already cleared AD — nothing to override here).
  const json = toJsonResponse(outcome.answer, qname, typeName);
  const resp = jsonResponse(json, minTtl);
  if (outcome.meta) {
    for (const [k, v] of Object.entries(outcome.meta)) resp.headers.set(k, v);
  }
  return resp;
}

async function handleRulesSync(request, url, env, config) {
  if (request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method Not Allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }
  const secret = env.RULES_SYNC_SECRET || config.token;
  if (!secret) {
    return new Response(
      JSON.stringify({ error: "RULES_SYNC_SECRET is not configured on server" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
  const authHeader = request.headers.get("Authorization") || "";
  const bearerMatch = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : null;
  const xSecret = request.headers.get("X-Rules-Secret");
  const querySecret = url.searchParams.get("secret");
  const tokenMatch = bearerMatch || xSecret || querySecret;
  if (tokenMatch !== secret) {
    return new Response(JSON.stringify({ error: "Unauthorized" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  const ct = (request.headers.get("content-type") || "").toLowerCase();
  const text = await request.text();
  let ruleText = text;
  if (ct.includes("application/json") && text.trim().length > 0) {
    try {
      const json = JSON.parse(text);
      if (typeof json.rules === "string") {
        ruleText = json.rules;
      }
    } catch {
      return new Response(JSON.stringify({ error: "Invalid JSON payload" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }
  }

  if (ruleText && ruleText.trim().length > 0) {
    try {
      const adopted = await adoptRawRules(ruleText, env);
      return new Response(
        JSON.stringify({
          ok: true,
          mode: "push",
          rulesCount: adopted.ruleCount,
          bytes: adopted.bytes,
          updatedAt: new Date().toISOString(),
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        }
      );
    } catch (err) {
      return new Response(
        JSON.stringify({ error: err.message || "Failed to adopt rules" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  } else {
    // Pull mode: trigger remote fetch and KV update
    const updated = await refreshRules(env);
    return new Response(
      JSON.stringify({
        ok: updated,
        mode: "pull",
        updatedAt: new Date().toISOString(),
      }),
      {
        status: updated ? 200 : 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        },
      }
    );
  }
}

const dnsCache = createCache();

async function resolveWithCache(parsed, query, subnet, ecsKey, domestic, config, env) {
  const qname = parsed.question.name;
  const qtype = parsed.question.qtype;

  // 1) Cache hit?
  if (config.cacheTtlSeconds > 0) {
    const cached = dnsCache.get(qname, qtype, ecsKey);
    if (cached) {
      metrics.inc("cache_hit");
      metrics.recordAnalyticsPoint(env, {
        group: domestic ? "domestic" : "global",
        winnerUrl: "cache",
        durationMs: 0,
        qtype,
        rcode: "NOERROR",
        cacheStatus: "hit",
      });
      return { answer: cached, from: "cache", durationMs: 0, cached: true };
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

  metrics.recordUpstreamRace(domestic ? "domestic" : "global", result.from, result.durationMs);
  metrics.recordAnalyticsPoint(env, {
    group: domestic ? "domestic" : "global",
    winnerUrl: result.from,
    durationMs: result.durationMs,
    qtype,
    rcode: "NOERROR",
    cacheStatus: "miss",
  });

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
    try {
      const updated = await refreshBlock(env);
      metrics.inc(updated ? "block_fetch" : "block_unchanged");
    } catch {
      metrics.inc("block_fetch_fail");
    }
  },
};

export { resetRules, readConfig, isBlocked, resetBlockFn as resetBlock };