/**
 * Runtime-agnostic resolver pipeline.
 *
 * This module holds the full query pipeline shared by every entry point:
 *   rule-based domestic/global routing → blocklist filter → ECS injection →
 *   in-memory cache → concurrent upstream fan-out → DNSSEC AD masking.
 *
 * It depends only on standard Web-platform APIs (fetch, TextEncoder, Uint8Array),
 * so the same code runs inside the Cloudflare Workers runtime (worker.js) and on
 * plain Node.js 18+ (dot.js). Entry points differ only in how they obtain the
 * client IP and the `env` bindings:
 *   - Worker:  client IP from the trusted `cf-connecting-ip` header, env = bindings.
 *   - Node:    client IP from the TLS socket address, env = process.env.
 */

import {
  applyRelayedDnssec,
  answerTtlSeconds,
  buildErrorResponse,
  buildZeroResponse,
  clientRequestedDnssec,
} from "./dns.js";
import { encodeEcsRdata, wrapEcsOption } from "./ecs.js";
import { subnetForEcs } from "./ip.js";
import { ensureRules, isDomestic } from "./rules.js";
import { ensureBlock, isBlocked } from "./filter.js";
import { raceGroup } from "./resolver.js";
import { metrics } from "./metrics.js";
import { createCache } from "./cache.js";

/** Append an EDNS0 OPT record carrying an ECS option, bumping ARCOUNT. */
export function appendEcsOpt(query, subnet) {
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

const dnsCache = createCache();

/**
 * Resolve a DNS query (given as raw wire bytes + parsed info) through the full
 * pipeline and return the final answer buffer:
 *   rule-based domestic/global routing → ECS injection → concurrent upstream
 *   fan-out → blocklist filter → DNSSEC AD masking.
 * Returns { ok:true, answer, meta } or { ok:false }. `wireQuery` is the client's
 * raw query to echo in synthetic (filtered/SERVFAIL) responses; for a query we
 * synthesize ourselves (JSON API) it equals the built wire query.
 * `clientIp` is the trusted client address (never client-supplied headers);
 * pass null when no trustworthy IP is available (ECS injection is skipped).
 */
export async function resolveQuery(wireQuery, parsed, { clientIp, env, config }) {
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

  // ECS injection from the trusted client IP.
  const subnet = subnetForEcs(clientIp, config.ecsV4Prefix, config.ecsV6Prefix);
  const ecsKey = subnet ? `${subnet.family}:${subnet.network.join(".")}` : "none";
  const result = await resolveWithCache(parsed, wireQuery, subnet, ecsKey, domestic, config, env);
  if (!result) return { ok: false };

  // Cache hit or DNSSEC masking: clone answer buffer to avoid mutating the in-memory cache entry.
  let answer = result.answer;
  if (result.cached) {
    // RFC 1035 §4.1.1: stamp the current query's Transaction ID on cached responses
    answer = answer.slice();
    answer[0] = (parsed.id >> 8) & 0xff;
    answer[1] = parsed.id & 0xff;
  } else if (config.dnssec) {
    answer = answer.slice();
  }

  // DNSSEC AD masking: pass upstream AD to DNSSEC-capable clients only.
  if (config.dnssec) {
    applyRelayedDnssec(answer, clientRequestedDnssec(parsed));
  }
  return { ok: true, answer, meta: result.meta };
}

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
    const flags = (result.answer[2] << 8) | result.answer[3];
    const rcode = flags & 0x000f;
    const ancount = (result.answer[6] << 8) | result.answer[7];

    // RFC 2308: Clamp negative response TTL (NXDOMAIN or NODATA) to conservative limit (30s)
    if (rcode === 3 || ancount === 0) {
      const maxNegTtl = Math.min(config.cacheTtlSeconds, 30);
      ttl = ttl <= 0 ? maxNegTtl : Math.min(ttl, maxNegTtl);
    } else if (ttl <= 0) {
      ttl = config.cacheTtlSeconds;
    }
    dnsCache.set(qname, qtype, ecsKey, result.answer, Math.min(ttl, config.cacheTtlSeconds));
  }
  return result;
}
