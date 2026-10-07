/**
 * Per-source-IP abuse control for the public DoT listener (src/dot.js).
 *
 * A DoT resolver that a roaming client (an Android phone on carrier IPs) must
 * reach cannot be restricted to a static IP allowlist — the client's address
 * changes arbitrarily. What we CAN do is bound how much any single source can
 * consume, so one abusive host cannot monopolize the resolver:
 *
 *   - per-IP concurrent connections (a phone keeps 1-2; the default is generous)
 *   - per-IP query rate (token bucket, burst = one second's worth of tokens)
 *
 * Unidentified sources (no socket address) are not per-IP limited — the global
 * `maxConnections` cap in dot.js still applies to them.
 *
 * State is bounded: stale idle entries are swept once the tracked-IP map grows
 * past `maxTrackedIps`, so a source-IP spray cannot grow our heap without bound.
 */

const DEFAULT_MAX_CONNECTIONS_PER_IP = 16;
const DEFAULT_MAX_QPS_PER_IP = 50;
const DEFAULT_MAX_TRACKED_IPS = 4096;
const IDLE_PRUNE_MS = 120_000;

export function createIpLimiter({
  maxConnectionsPerIp = DEFAULT_MAX_CONNECTIONS_PER_IP,
  maxQpsPerIp = DEFAULT_MAX_QPS_PER_IP,
  maxTrackedIps = DEFAULT_MAX_TRACKED_IPS,
  now = Date.now,
} = {}) {
  // ip -> { conns, tokens, lastRefill, lastSeen }
  const state = new Map();

  function entryFor(ip, ts) {
    let e = state.get(ip);
    if (e === undefined) {
      if (state.size >= maxTrackedIps) sweep(ts);
      e = { conns: 0, tokens: maxQpsPerIp > 0 ? maxQpsPerIp : 0, lastRefill: ts, lastSeen: ts };
      state.set(ip, e);
    }
    return e;
  }

  function sweep(ts) {
    for (const [ip, e] of state) {
      if (e.conns === 0 && ts - e.lastSeen > IDLE_PRUNE_MS) state.delete(ip);
    }
  }

  return {
    /** Try to admit one connection from `ip`. Returns false when over the cap. */
    acquireConnection(ip) {
      if (!ip || maxConnectionsPerIp <= 0) return true;
      const ts = now();
      const e = entryFor(ip, ts);
      e.lastSeen = ts;
      if (e.conns >= maxConnectionsPerIp) return false;
      e.conns += 1;
      return true;
    },

    /** Release a connection slot previously admitted for `ip`. */
    releaseConnection(ip) {
      if (!ip) return;
      const e = state.get(ip);
      if (e === undefined) return;
      e.conns = Math.max(0, e.conns - 1);
      e.lastSeen = now();
    },

    /** Consume one query token for `ip`; false when the bucket is empty. */
    allowQuery(ip) {
      if (!ip || maxQpsPerIp <= 0) return true;
      const ts = now();
      const e = entryFor(ip, ts);
      e.lastSeen = ts;
      const elapsedMs = ts - e.lastRefill;
      if (elapsedMs > 0) {
        const refill = (elapsedMs / 1000) * maxQpsPerIp;
        e.tokens = Math.min(maxQpsPerIp, e.tokens + refill);
        e.lastRefill = ts;
      }
      if (e.tokens < 1) return false;
      e.tokens -= 1;
      return true;
    },

    /** Number of tracked source IPs (metrics/diagnostics). */
    size() {
      return state.size;
    },
  };
}
