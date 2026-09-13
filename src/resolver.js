/**
 * Upstream resolution with high availability: concurrent fan-out + failover.
 *
 * Instead of hitting upstreams serially (each waiting on its own timeout), we
 * fire the whole group at once and return the FIRST valid non-SERVFAIL answer.
 * This hides the latency of the slowest/lost upstream behind the fastest one —
 * the core "HA" improvement over the naive serial loop.
 *
 * Subtlety: SERVFAIL from one upstream is a genuine answer for that resolver,
 * but unusable for our client, so we keep racing until the group is exhausted;
 * only when every member fails (error, timeout, bad body, SERVFAIL) do we
 * synthesize a SERVFAIL for the client.
 *
 * Observability: an optional `on` callback is invoked once per upstream as it
 * settles, letting the caller tally outcomes without coupling this module to
 * any metrics backend.
 */

import {
  buildErrorResponse,
  DNS_CONTENT_TYPE,
  validateUpstreamResponse,
} from "./dns.js";

async function queryUpstream(url, query, { timeoutMs, maxResponseBytes }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = performance.now();
  try {
    const resp = await fetch(url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: DNS_CONTENT_TYPE,
        "Content-Type": DNS_CONTENT_TYPE,
      },
      body: query,
    });
    const durationMs = Math.round((performance.now() - start) * 10) / 10;
    if (!resp.ok) return { ok: false, reason: `http_${resp.status}`, durationMs };
    const ct = (resp.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
    if (ct !== DNS_CONTENT_TYPE) return { ok: false, reason: "bad_content_type", durationMs };
    const buf = await resp.arrayBuffer();
    if (buf.byteLength < 12 || buf.byteLength > maxResponseBytes) {
      return { ok: false, reason: "bad_size", durationMs };
    }
    return { ok: true, body: new Uint8Array(buf), durationMs };
  } catch {
    const durationMs = Math.round((performance.now() - start) * 10) / 10;
    return { ok: false, reason: controller.signal.aborted ? "timeout" : "network", durationMs };
  } finally {
    clearTimeout(timer);
  }
}

/** Classify a settled upstream outcome. */
function classify(r) {
  if (r.ok) {
    try {
      const flags = validateUpstreamResponse(r.body, null);
      return (flags & 0x000f) === 2 ? "servfail" : "ok";
    } catch {
      return "bad_response";
    }
  }
  return r.reason === "timeout" ? "timeout" : "error";
}

/**
 * Resolve by racing all upstreams in `urls`. Returns
 *   { answer, from } on the first valid (non-SERVFAIL, ID-matched) response,
 * else null (all failed). Never throws.
 * `on` (optional) is called with { kind, url } for each settled upstream.
 */
export async function raceGroup(urls, query, parsedInfo, { timeoutMs, maxResponseBytes, on }) {
  const settle = (r) => {
    if (on) on({ kind: classify(r), url: r.url, durationMs: r.durationMs ?? 0 });
  };
  const pending = urls.map(async (url) => {
    const res = await queryUpstream(url, query, { timeoutMs, maxResponseBytes });
    return { url, ...res };
  });

  const results = new Array(pending.length);
  let settled = 0;
  return new Promise((resolve) => {
    for (let i = 0; i < pending.length; i += 1) {
      // eslint-disable-next-line no-loop-func
      pending[i].then(
        (r) => {
          settled += 1;
          results[i] = r;
          settle(r);
          if (r.ok) {
            try {
              const flags = validateUpstreamResponse(r.body, parsedInfo ?? null);
              if ((flags & 0x000f) !== 2) {
                resolve({ answer: r.body, from: r.url, durationMs: r.durationMs ?? 0 });
                return;
              }
            } catch {
              /* invalid answer; keep waiting for others */
            }
          }
          if (settled === pending.length) resolve(null);
        },
        (err) => {
          settled += 1;
          settle({ ok: false, reason: "error", url: urls[i], durationMs: 0 });
          if (settled === pending.length) resolve(null);
        }
      );
    }
    if (pending.length === 0) resolve(null);
  });
}

/** Build a SERVFAIL response for a query we could or could not parse. */
export function serverFailure(fromQuery, question) {
  return buildErrorResponse(fromQuery, 2, question ?? null);
}