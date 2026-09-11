/**
 * Domain blocklist filtering for the DoH resolver.
 *
 * Uses the SAME matcher semantics as rules.js (plain / full: / regexp:) but for a
 * separate "blocked" set. A blocked qname is NOT forwarded upstream; instead we
 * synthesize a response chosen by `blockAction`:
 *   - nxdomain -> NXDOMAIN (honest "site does not exist")
 *   - zero     -> NOERROR with 0.0.0.0 (A) / :: (AAAA) blackhole answers
 *   - passthrough -> treat as not-blocked (proceed upstream)
 *
 * Lists load from env.BLOCK_URL (one pattern per line), durable in BLOCK_KV,
 * mirrored from rules.js (KV key "block:data").
 */

const DEC = new TextDecoder("latin1");
const ENC = new TextEncoder();
const KV_KEY = "block:data";

let live = null;
let coldInflight = null;

function parseRuleText(text) {
  const plain = [];
  const full = new Set();
  const regexp = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    if (line.startsWith("full:")) {
      full.add(line.slice(5).trim().toLowerCase());
    } else if (line.startsWith("regexp:")) {
      regexp.push(new RegExp(line.slice(7).trim(), "i"));
    } else {
      plain.push(line.toLowerCase());
    }
  }
  plain.sort();
  return { plain, full, regexp, version: text.length };
}

/** Load a rule object from literal text (tests / literal list). */
export function loadBlockFromText(text) {
  return { ...parseRuleText(text), data: text };
}

function matches(qname, rule) {
  const q = qname.toLowerCase();
  if (!rule) return false;
  if (rule.full.has(q)) return true;
  for (let i = 0; i < rule.plain.length; i += 1) {
    const p = rule.plain[i];
    if (q === p || q.endsWith(`.${p}`)) return true;
  }
  for (let i = 0; i < rule.regexp.length; i += 1) {
    if (rule.regexp[i].test(q)) return true;
  }
  return false;
}

/** Public matcher: should this qname be blocked? */
export function isBlocked(qname, rule) {
  return matches(qname, rule);
}

// Once true, no blocklist URL is configured; we remember this so we never re-read
// KV or attempt a fetch on later queries (the KV mirror can only be populated by
// an upstream BLOCK_URL, so a missing URL means it stays empty indefinitely).
let disabled = false;

/** ensureBlock: best-available blocklist (KV durable + cold-start fetch). */
export async function ensureBlock(env, fetcher = fetch) {
  if (live) return live;
  // If we already determined there's no source, bail out fast.
  if (!env.BLOCK_URL && disabled) return null;

  if (env.BLOCK_KV) {
    try {
      const raw = await env.BLOCK_KV.get(KV_KEY);
      if (raw) {
        const bytes = typeof raw === "string" ? ENC.encode(raw) : raw;
        const text = DEC.decode(bytes);
        live = { ...parseRuleText(text), data: text };
        return live;
      }
    } catch {
      /* ignore */
    }
  }

  const url = env.BLOCK_URL || "";
  if (!url) {
    disabled = true; // determined: no blocklist source
    return null;
  }

  if (!coldInflight) {
    coldInflight = (async () => {
      try {
        const resp = await fetcher(url, { method: "GET", redirect: "manual" });
        if (!resp.ok) return null;
        const ct = (resp.headers.get("content-type") || "").toLowerCase();
        if (ct.includes("text/html")) return null;
        const buf = await resp.arrayBuffer();
        const text = DEC.decode(buf);
        const rule = parseRuleText(text);
        live = { ...rule, data: text };
        if (env.BLOCK_KV) {
          try {
            await env.BLOCK_KV.put(KV_KEY, new Uint8Array(buf));
          } catch {
            /* best-effort */
          }
        }
        return live;
      } catch {
        return null;
      }
    })().finally(() => {
      coldInflight = null;
    });
  }
  return coldInflight;
}

/** Reset (tests). */
export function resetBlock() {
  live = null;
  coldInflight = null;
  disabled = false;
}

/** Cron handler: refresh the blocklist in background; keep old on any failure. */
export async function refreshBlock(env, fetcher = fetch) {
  const url = env.BLOCK_URL || "";
  if (!url) return false;
  try {
    const resp = await fetcher(url, { method: "GET", redirect: "manual" });
    if (!resp.ok) return false;
    const ct = (resp.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("text/html")) return false;
    const buf = await resp.arrayBuffer();
    const text = DEC.decode(buf);
    live = { ...parseRuleText(text), data: text };
    if (env.BLOCK_KV) {
      try {
        await env.BLOCK_KV.put(KV_KEY, new Uint8Array(buf));
      } catch {
        /* best-effort */
      }
    }
    return true;
  } catch {
    return false;
  }
}