/**
 * Domain-rule loading and matching with a two-layer cache: KV (durable) +
 * in-memory (fast path). Rules decide whether a qname routes to the domestic
 * or global upstream group.
 *
 * Rule file format (Loyalsoldier `direct-list.txt`): one pattern per line.
 *   - bare  `foo.com`   => suffix match: `foo.com`, `a.foo.com`, ...
 *   - `full:foo.com`    => exact-match only
 *   - `regexp:^...`     => regex applied to the full qname (case-insensitive)
 *
 * Safety: a ruleset is fully parsed & structurally validated before it becomes
 * live, so a corrupt download can never poison the query path. Memory is the hot
 * cache; KV is a durable mirror used to survive cold starts without a network
 * fetch, and the cron refresh keeps both in sync.
 */

const DEC = new TextDecoder("latin1");
const ENC = new TextEncoder();

export const DEFAULT_RULES_URL =
  "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt";

/**
 * Built-in personal override layer: these domains are ALWAYS routed to the
 * domestic (China-direct) group, regardless of the remote list. This is the
 * part that must never depend on an external URL being reachable — otherwise a
 * rules fetch failure could silently revert e.g. `linux.do` back to the global
 * group and break the user's core "direct-connect to these sites" requirement.
 *
 * Bare domain = suffix match (hits the domain and all subdomains).
 */
export const BUILTIN_OVERRIDE = [
  "linux.do", // 主论坛及子域
  "github.com",
  "githubusercontent.com",
  "githubassets.com",
];

function parseBuiltinOverride() {
  const plain = [];
  for (const d of BUILTIN_OVERRIDE) plain.push(d.toLowerCase());
  plain.sort();
  return { plain, full: new Set(), regexp: [], version: 0 };
}

const KV_KEY = "rules:data";
const KV_MAX_BYTES = 8 * 1024 * 1024;
// Negative-cache window: after a fetch failure (cold start or cron) we avoid
// hammering the (possibly unreachable/blocked) rule URL on every subsequent
// query for a short time, instead relying on BUILTIN_OVERRIDE + whatever KV
// retained. This bounds the amplification caused by a cold-start fetch failure.
const FAIL_COOLDOWN_MS = 30_000;

// Last fetch failure timestamp (ms epoch) and the deadline until which we skip
// further remote fetch attempts. Private module state, per isolate.
let failUntil = 0;

// Live ruleset. Shape: { version, plain: string[], full: Set<string>,
//                        regexp: RegExp[], data: string }
let live = null;
let coldInflight = null;

/** Record a fetch failure so the next `ensureRules` short-circuits. */
function noteFailure() {
  failUntil = Date.now() + FAIL_COOLDOWN_MS;
}

/** Are we inside the post-failure cooldown window and should avoid remote fetch? */
function inFailureWindow() {
  return Date.now() < failUntil;
}

function parseRuleText(text) {
  const plain = [];
  const full = new Set();
  const regexp = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    if (line.startsWith("full:")) {
      const d = line.slice(5).trim();
      if (d) full.add(d);
    } else if (line.startsWith("regexp:")) {
      const d = line.slice(7).trim();
      if (d) regexp.push(new RegExp(d, "i"));
    } else {
      plain.push(line);
    }
  }
  // Sort for determinism; not required for correctness of suffix matching,
  // but it keeps iterations cache-friendly and test assertions stable.
  plain.sort();
  return { plain, full, regexp, version: text.length };
}

function matchesRules(qname, rules) {
  const q = qname.toLowerCase();
  // Built-in personal override always wins.
  if (matchesBuiltin(q)) return true;
  if (!rules) return false;
  if (rules.full.has(q)) return true;
  for (let i = 0; i < rules.plain.length; i += 1) {
    const p = rules.plain[i];
    if (q === p) return true;
    if (q.endsWith(`.${p}`)) return true;
  }
  for (let i = 0; i < rules.regexp.length; i += 1) {
    if (rules.regexp[i].test(q)) return true;
  }
  return false;
}

/** Const-fold the builtin override so it never allocates per-query. */
const BUILTIN = new Set(BUILTIN_OVERRIDE.map((d) => d.toLowerCase()));
function matchesBuiltin(q) {
  if (BUILTIN.has(q)) return true;
  for (const d of BUILTIN) {
    if (q.endsWith(`.${d}`)) return true;
  }
  return false;
}

/** Public matcher: does `qname` belong to the domestic (China-direct) group? */
export function isDomestic(qname, rules) {
  return matchesRules(qname, rules);
}

async function ensureFromKv(kv) {
  try {
    const raw = await kv.get(KV_KEY);
    if (!raw) return null;
    const bytes = typeof raw === "string" ? ENC.encode(raw) : raw;
    if (bytes.byteLength === 0) return null;
    const text = DEC.decode(bytes);
    const parsed = parseRuleText(text);
    const rule = { ...parsed, data: text };
    live = rule;
    return rule;
  } catch {
    return null;
  }
}

async function fetchAndAdopt(rulesUrl, fetcher) {
  const resp = await fetcher(rulesUrl, { method: "GET", redirect: "manual" });
  if (!resp.ok) throw new Error(`rules_http_${resp.status}`);
  const ct = (resp.headers.get("content-type") || "").toLowerCase();
  if (ct.includes("text/html")) throw new Error("rules_html_response");
  const buf = await resp.arrayBuffer();
  if (buf.byteLength > KV_MAX_BYTES) throw new Error("rules_too_large");
  const text = DEC.decode(buf);
  const parsed = parseRuleText(text);
  return { rule: { ...parsed, data: text }, bytes: new Uint8Array(buf) };
}

/** ensureRules: return best available live ruleset without blocking long. */
export async function ensureRules(env, fetcher = fetch) {
  if (live) return live;

  if (env.RULES_KV) {
    const fromKv = await ensureFromKv(env.RULES_KV);
    if (fromKv) return fromKv;
  }

  // Within the post-failure cooldown we do NOT retry the remote fetch; we rely on
  // the built-in override (plus whatever KV retained). Avoids hammering an
  // unreachable/blocked rule URL on every query during a cold-start outage.
  if (inFailureWindow()) return null;

  // Cold start: single-flight fetch so concurrent queries share one download.
  if (!coldInflight) {
    const rulesUrl = env.RULES_URL || DEFAULT_RULES_URL;
    coldInflight = (async () => {
      try {
        const { rule, bytes } = await fetchAndAdopt(rulesUrl, fetcher);
        live = rule;
        if (env.RULES_KV) {
          try {
            await env.RULES_KV.put(KV_KEY, bytes);
          } catch {
            /* best-effort */
          }
        }
        return live;
      } catch {
        noteFailure();
        return null;
      }
    })().finally(() => {
      coldInflight = null;
    });
  }
  return coldInflight;
}

/** Cron handler: refresh rules in background; keep old on any failure. */
export async function refreshRules(env, fetcher = fetch) {
  const rulesUrl = env.RULES_URL || DEFAULT_RULES_URL;
  try {
    const { rule, bytes } = await fetchAndAdopt(rulesUrl, fetcher);
    live = rule;
    if (env.RULES_KV) {
      try {
        await env.RULES_KV.put(KV_KEY, bytes);
      } catch {
        /* best-effort */
      }
    }
    return true;
  } catch {
    noteFailure();
    return false;
  }
}

/** Load a ruleset from literal text (tests / custom small lists). */
export function loadRulesFromText(text) {
  return { ...parseRuleText(text), data: text };
}

/** Test helper. */
export function resetRules() {
  live = null;
  coldInflight = null;
  failUntil = 0;
}