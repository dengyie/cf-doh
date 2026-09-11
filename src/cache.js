/**
 * In-memory DNS response cache with TTL-based expiry and a bounded size.
 *
 * Keyed by (qname, qtype, ecsSubnet) — ECS is part of the key because the same
 * name can resolve differently per client subnet; an answer cached for one /24
 * is never served to another.
 *
 * TTL: entries live at most `ttl` seconds provided to set(), and the caller
 * derives that from the answer's own minimum TTL (answerTtlSeconds) so we never
 * out-cache the authoritative freshness nor over-cache pathological TTLs.
 *
 * In a Worker, module state is per-isolate: this is a fast per-edge cache, not
 * durable across cold starts — correct for DNS (origin is always reachable).
 */

const DEFAULT_SIZE = 1024;

export function createCache({ size = DEFAULT_SIZE, now = Date.now } = {}) {
  const map = new Map(); // key -> { expiresAt, value }

  const key = (qname, qtype, ecs) => `${qname.toLowerCase()}|${qtype}|${ecs}`;

  return {
    /** Look up; returns answer bytes on fresh hit, else null. */
    get(qname, qtype, ecs, ts = now()) {
      const k = key(qname, qtype, ecs);
      const e = map.get(k);
      if (!e) return null;
      if (e.expiresAt <= ts) {
        map.delete(k);
        return null;
      }
      return e.value;
    },
    /** Store an answer for `ttl` seconds. ttl <= 0 skips caching. */
    set(qname, qtype, ecs, value, ttl, ts = now()) {
      if (ttl <= 0) return;
      const k = key(qname, qtype, ecs);
      map.set(k, { value, expiresAt: ts + ttl * 1000 });
      // Bound size (evict oldest = first inserted).
      while (map.size > size) {
        const oldest = map.keys().next().value;
        if (oldest === undefined) break;
        map.delete(oldest);
      }
    },
    /** Number of live entries (metrics). */
    size() {
      return map.size;
    },
  };
}