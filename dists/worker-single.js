// src/config.js
var DEFAULT = {
  path: "/doh",
  domesticPrimary: "https://dns.alidns.com/dns-query",
  domesticFallback: "https://doh.pub/dns-query",
  globalPrimary: "https://dns.google/dns-query",
  globalFallback: "https://cloudflare-dns.com/dns-query",
  ecsV4Prefix: 24,
  ecsV6Prefix: 56,
  upstreamTimeoutMs: 3e3,
  maxQueryBytes: 4096,
  maxResponseBytes: 65535,
  maxTtlSeconds: 3600,
  cacheTtlSeconds: 300,
  rulesUrl: "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt",
  rulesCacheMin: 15,
  dnssec: true,
  // 感知/透传 DNSSEC（上游置 AD 且客户端请求过 DO 才回 AD 位）
  blockAction: "nxdomain",
  // 过滤命中响应: nxdomain|zero(null 0.0.0.0/::)|passthrough
  jsonPath: "/json"
  // 兼容 Google 风格的 DoH JSON API（GET ?name=&type=）
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
function readConfig(env) {
  const path = asSingle(env.DOH_PATH, DEFAULT.path);
  const config = {
    path: path.startsWith("/") ? path : `/${path}`,
    domesticUrls: [
      asSingle(env.DOMESTIC_DOH_URL, DEFAULT.domesticPrimary),
      asSingle(env.DOMESTIC_FALLBACK_DOH_URL, DEFAULT.domesticFallback)
    ],
    globalUrls: [
      asSingle(env.GLOBAL_DOH_URL, DEFAULT.globalPrimary),
      asSingle(env.GLOBAL_FALLBACK_DOH_URL, DEFAULT.globalFallback)
    ],
    ecsV4Prefix: parseUint(env.ECS_IPV4_PREFIX, DEFAULT.ecsV4Prefix, 8, 32),
    ecsV6Prefix: parseUint(env.ECS_IPV6_PREFIX, DEFAULT.ecsV6Prefix, 8, 128),
    upstreamTimeoutMs: parseUint(env.UPSTREAM_TIMEOUT_MS, DEFAULT.upstreamTimeoutMs, 500, 1e4),
    maxQueryBytes: parseUint(env.MAX_QUERY_BYTES, DEFAULT.maxQueryBytes, 512, 8192),
    maxResponseBytes: parseUint(env.MAX_RESPONSE_BYTES, DEFAULT.maxResponseBytes, 512, 65535),
    maxTtlSeconds: parseUint(env.MAX_TTL_SECONDS, DEFAULT.maxTtlSeconds, 0, 86400),
    cacheTtlSeconds: parseUint(env.CACHE_TTL_SECONDS, DEFAULT.cacheTtlSeconds, 0, 86400),
    rulesUrl: asSingle(env.RULES_URL, DEFAULT.rulesUrl),
    rulesCacheMin: parseUint(env.RULES_CACHE_MIN, DEFAULT.rulesCacheMin, 1, 1440),
    token: asSingle(env.DOH_TOKEN, ""),
    rulesSyncSecret: asSingle(env.RULES_SYNC_SECRET, ""),
    pageUrl: asSingle(env.PAGE_URL, ""),
    dnssec: String(env.DNSSEC ?? "").trim() === "" ? DEFAULT.dnssec : String(env.DNSSEC).trim() !== "0" && String(env.DNSSEC).trim().toLowerCase() !== "false",
    blockAction: (() => {
      const v = asSingle(env.BLOCK_ACTION, DEFAULT.blockAction).toLowerCase();
      return ["nxdomain", "zero", "passthrough"].includes(v) ? v : DEFAULT.blockAction;
    })(),
    jsonPath: (() => {
      const p = asSingle(env.JSON_PATH, DEFAULT.jsonPath);
      return p.startsWith("/") ? p : `/${p}`;
    })()
  };
  return config;
}

// src/dns.js
var DNS_CONTENT_TYPE = "application/dns-message";
var OPCODE_QUERY = 0;
var HDR_ID = 0;
var HDR_FLAGS = 2;
var HDR_QDCOUNT = 4;
var HDR_ARCOUNT = 10;
var HEADER_LEN = 12;
var DnsFormatError = class extends Error {
  constructor(message) {
    super(message);
    this.name = "DnsFormatError";
  }
};
function readU16(buf, off) {
  return buf[off] << 8 | buf[off + 1];
}
function writeU16(buf, off, value) {
  buf[off] = value >> 8 & 255;
  buf[off + 1] = value & 255;
}
function decodeName(buf, start) {
  let off = start;
  let name = "";
  let jumps = 0;
  while (true) {
    const len = buf[off];
    if (len === void 0) throw new DnsFormatError("name_truncated");
    if (len === 0) {
      off += 1;
      return { name, end: off };
    }
    if ((len & 192) === 192) {
      if (off + 1 >= buf.length) throw new DnsFormatError("name_pointer_truncated");
      off += 2;
      if (jumps++ > 4) throw new DnsFormatError("name_too_many_ptrs");
      return { name, end: off };
    }
    if ((len & 192) !== 0) throw new DnsFormatError("name_bad_label");
    if (off + 1 + len > buf.length) throw new DnsFormatError("name_label_truncated");
    let label = "";
    for (let i = 0; i < len; i += 1) {
      const c = buf[off + 1 + i] & 255;
      label += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : String.fromCharCode(c);
    }
    if (name !== "") name += ".";
    name += label;
    off += 1 + len;
  }
}
function parseDnsMessage(buf) {
  if (buf.length < HEADER_LEN) throw new DnsFormatError("too_short");
  const id = readU16(buf, HDR_ID);
  const flags = readU16(buf, HDR_FLAGS);
  const qdcount = readU16(buf, HDR_QDCOUNT);
  const arcount = readU16(buf, HDR_ARCOUNT);
  if (qdcount !== 1) {
    throw new DnsFormatError("qdcount_not_one");
  }
  if ((flags & 30720) !== OPCODE_QUERY << 11) {
    throw new DnsFormatError("not_a_query");
  }
  let off = HEADER_LEN;
  const nameStart = off;
  const { name, end } = decodeName(buf, off);
  const questionStart = nameStart;
  off = end;
  if (off + 4 > buf.length) throw new DnsFormatError("question_truncated");
  const qtype = readU16(buf, off);
  const qclass = readU16(buf, off + 2);
  const questionEnd = off + 4;
  off = questionEnd;
  const question = {
    name,
    // lower-cased qname, e.g. "github.com"
    qtype,
    qclass,
    nameOffset: nameStart,
    nameEnd: end,
    questionStart,
    questionEnd
  };
  const ancount = readU16(buf, 6);
  const nscount = readU16(buf, 8);
  const skipRRs = (start, count) => {
    let cursor2 = start;
    for (let i = 0; i < count; i += 1) {
      const { end: nEnd } = decodeName(buf, cursor2);
      cursor2 = nEnd;
      if (cursor2 + 10 > buf.length) throw new DnsFormatError("rr_truncated");
      const rdlength = readU16(buf, cursor2 + 8);
      cursor2 += 10 + rdlength;
      if (cursor2 > buf.length) throw new DnsFormatError("rr_rdata_truncated");
    }
    return cursor2;
  };
  let cursor = questionEnd;
  cursor = skipRRs(cursor, ancount);
  cursor = skipRRs(cursor, nscount);
  let opt = null;
  if (arcount >= 1) {
    let last = cursor;
    for (let i = 0; i < arcount - 1; i += 1) {
      const { end: nEnd } = decodeName(buf, last);
      last = nEnd;
      if (last + 10 > buf.length) throw new DnsFormatError("add_rr_truncated");
      last += 10 + readU16(buf, last + 8);
    }
    const { end: lastNameEnd } = decodeName(buf, last);
    const addStart = lastNameEnd;
    if (addStart + 10 <= buf.length) {
      const type = readU16(buf, addStart);
      const rdataLenOff = addStart + 8;
      const rdlength = readU16(buf, rdataLenOff);
      const rdataStart = addStart + 10;
      const rdataEnd = rdataStart + rdlength;
      if (rdataEnd <= buf.length && type === 41) {
        opt = {
          additionalIndex: arcount - 1,
          // 0-based index of last
          rdataStart,
          rdataEnd,
          rdataLenOff
        };
      }
    }
  }
  return { id, flags, question, opt, additionalCount: arcount };
}
function buildErrorResponse(fromBuf, rcode, question) {
  const out = new Uint8Array(HEADER_LEN);
  const id = readU16(fromBuf, HDR_ID);
  const reqFlags = readU16(fromBuf, HDR_FLAGS);
  writeU16(out, HDR_ID, id);
  const rd = reqFlags & 256;
  const flags = 32768 | reqFlags & 30720 | rd | 128 | rcode & 15;
  writeU16(out, HDR_FLAGS, flags);
  writeU16(out, HDR_QDCOUNT, 1);
  writeU16(out, 6, 0);
  writeU16(out, 8, 0);
  writeU16(out, HDR_ARCOUNT, 0);
  if (question) {
    const q = question.questionEnd - question.questionStart;
    const full = new Uint8Array(HEADER_LEN + q);
    full.set(out, 0);
    full.set(fromBuf.subarray(question.questionStart, question.questionEnd), HEADER_LEN);
    return full;
  }
  return out;
}
function writeU32(buf, off, value) {
  buf[off] = value >>> 24 & 255;
  buf[off + 1] = value >>> 16 & 255;
  buf[off + 2] = value >>> 8 & 255;
  buf[off + 3] = value & 255;
}
function validateUpstreamResponse(answerBuf, originalInfo) {
  if (answerBuf.length < 12) throw new DnsFormatError("answer_too_short");
  const answerId = answerBuf[0] << 8 | answerBuf[1];
  if (originalInfo && answerId !== originalInfo.id) {
    throw new DnsFormatError("id_mismatch");
  }
  const flags = answerBuf[2] << 8 | answerBuf[3];
  if ((flags & 32768) === 0) throw new DnsFormatError("not_response");
  if ((flags & 512) !== 0) throw new DnsFormatError("truncated");
  return flags;
}
var TYPE_A = 1;
var TYPE_AAAA = 28;
function buildZeroResponse(fromBuf, parsed) {
  const q = parsed.question;
  const qtype = q.qtype;
  const isAaaa = qtype === TYPE_AAAA;
  const keep = isAaaa ? TYPE_AAAA : TYPE_A;
  const addr = isAaaa ? new Uint8Array([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]) : new Uint8Array([0, 0, 0, 0]);
  const questionLen = q.questionEnd - q.questionStart;
  const ansNameLen = 2;
  const outLen = HEADER_LEN + questionLen + (2 + 10 + addr.length);
  const out = new Uint8Array(outLen);
  const id = readU16(fromBuf, HDR_ID);
  const reqFlags = readU16(fromBuf, HDR_FLAGS);
  const rd = reqFlags & 256;
  const flags = 32768 | reqFlags & 30720 | rd | 128;
  writeU16(out, HDR_ID, id);
  writeU16(out, HDR_FLAGS, flags);
  writeU16(out, HDR_QDCOUNT, 1);
  writeU16(out, 6, 1);
  writeU16(out, 8, 0);
  writeU16(out, HDR_ARCOUNT, 0);
  out.set(fromBuf.subarray(q.questionStart, q.questionEnd), HEADER_LEN);
  let o = HEADER_LEN + questionLen;
  out[o] = 192;
  out[o + 1] = 12;
  o += 2;
  writeU16(out, o, keep);
  writeU16(out, o + 2, 1);
  writeU32(out, o + 4, 60);
  writeU16(out, o + 8, addr.length);
  out.set(addr, o + 10);
  return out;
}
var FLAG_AD = 32;
function applyRelayedDnssec(answerBuf, clientRequestedDnssec2) {
  const cur = readU16(answerBuf, 2);
  let next = cur;
  if (!clientRequestedDnssec2) {
    next &= ~FLAG_AD;
  }
  writeU16(answerBuf, 2, next);
  return next;
}
function clientRequestedDnssec(parsed) {
  return Boolean(parsed && parsed.opt);
}
function answerTtlSeconds(buf, info) {
  const toU32At = (o) => o + 3 < buf.length ? (buf[o] & 255) << 24 | (buf[o + 1] & 255) << 16 | (buf[o + 2] & 255) << 8 | buf[o + 3] & 255 : 0;
  const skipRr = (start) => {
    const { end } = decodeName(buf, start);
    if (end + 10 > buf.length) return { next: buf.length, type: 0, ttl: 0, rdataOff: 0 };
    const type = readU16(buf, end);
    const ttl = toU32At(end + 4);
    const rdlen = readU16(buf, end + 8);
    const rdataOff = end + 10;
    return { next: rdataOff + rdlen, type, ttl, rdataOff };
  };
  const ancount = readU16(buf, 6);
  const nscount = readU16(buf, 8);
  let cursor = info.question.questionEnd;
  let minTtl = Infinity;
  let sawRecord = false;
  for (let s = 0; s < ancount + nscount; s += 1) {
    const { next, type, ttl, rdataOff } = skipRr(cursor);
    sawRecord = true;
    if (ttl < minTtl) minTtl = ttl;
    if (type === 6) {
      const minFieldOff = rdataOff + 2 + 2 + 16;
      const minimum = toU32At(minFieldOff);
      if (minimum < minTtl) minTtl = minimum;
    }
    cursor = next;
    if (cursor > buf.length) break;
  }
  if (!sawRecord) return 0;
  return minTtl === Infinity ? 0 : minTtl;
}

// src/ecs.js
var ECS_OPTION_CODE = 8;
function encodeEcsRdata(family, networkBytes, prefixLength) {
  const addrLen = Math.ceil(prefixLength / 8);
  const rdata = new Uint8Array(4 + addrLen);
  rdata[0] = family >> 8 & 255;
  rdata[1] = family & 255;
  rdata[2] = prefixLength;
  rdata[3] = 0;
  rdata.set(networkBytes.subarray(0, addrLen), 4);
  return rdata;
}
function wrapEcsOption(rdata) {
  const out = new Uint8Array(2 + 2 + rdata.length);
  out[0] = ECS_OPTION_CODE >> 8 & 255;
  out[1] = ECS_OPTION_CODE & 255;
  out[2] = rdata.length >> 8 & 255;
  out[3] = rdata.length & 255;
  out.set(rdata, 4);
  return out;
}

// src/ip.js
function isIpv4GlobalUnicast(b) {
  const a = b[0];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  const second = b[1];
  if (a === 100 && second >= 64 && second <= 127) return false;
  if (a === 169 && second === 254) return false;
  if (a === 172 && second >= 16 && second <= 31) return false;
  if (a === 192 && second === 168) return false;
  if (a === 192 && second === 0 && b[2] === 0) return false;
  if (a === 192 && second === 0 && b[2] === 2) return false;
  if (a === 192 && b[1] === 88 && b[2] === 99) return false;
  if (a === 198 && (second === 18 || second === 19)) return false;
  if (a === 198 && second === 51 && b[2] === 100) return false;
  if (a === 203 && second === 0 && b[2] === 113) return false;
  return true;
}
function isV6GlobalUnicast(b) {
  if ((b[0] & 224) !== 32) return false;
  if (b[0] === 32 && b[1] === 1 && b[2] === 13 && b[3] === 184) return false;
  return true;
}
function parseIpString(value) {
  const s = String(value || "").trim();
  if (s.includes(":")) {
    return parseIpv6(s);
  }
  return parseIpv4(s);
}
function parseIpv4(s) {
  const parts = s.split(".");
  if (parts.length !== 4) return null;
  const bytes = new Uint8Array(4);
  for (let i = 0; i < 4; i += 1) {
    const p = parts[i];
    if (!/^(0|[1-9][0-9]{0,2})$/.test(p)) return null;
    const n = Number(p);
    if (n > 255) return null;
    bytes[i] = n;
  }
  return { family: 1, bytes };
}
function parseIpv6(s) {
  if (s.length === 0 || s.includes("%")) return null;
  let address = s;
  const lastColon = address.lastIndexOf(":");
  const lastPart = lastColon >= 0 ? address.slice(lastColon + 1) : address;
  let ipv4Tail = null;
  let hasIpv4Tail = false;
  if (lastPart.includes(".")) {
    const v4 = parseIpv4(lastPart);
    if (v4 === null) return null;
    ipv4Tail = v4.bytes;
    hasIpv4Tail = true;
    address = `${address.slice(0, lastColon)}:v4`;
  }
  const halves = address.split("::");
  if (halves.length > 2) return null;
  const leftParts = halves[0] === "" ? [] : halves[0].split(":");
  const rightParts = halves.length === 1 || halves[1] === "" ? [] : halves[1].split(":");
  const parseParts = (arr) => {
    const out = [];
    for (const part of arr) {
      if (part === "v4") {
        if (!hasIpv4Tail) return null;
        out.push(ipv4Tail[0] << 8 | ipv4Tail[1], ipv4Tail[2] << 8 | ipv4Tail[3]);
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(part)) return null;
        out.push(parseInt(part, 16));
      }
    }
    return out;
  };
  const left = parseParts(leftParts);
  const right = parseParts(rightParts);
  if (left === null || right === null) return null;
  const hasCompression = halves.length === 2;
  const missing = 8 - left.length - right.length;
  if (!hasCompression && missing !== 0 || hasCompression && missing < 1) return null;
  const words = [...left, ...new Array(missing).fill(0), ...right];
  if (words.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i += 1) {
    bytes[i * 2] = words[i] >>> 8 & 255;
    bytes[i * 2 + 1] = words[i] & 255;
  }
  let mapped = true;
  for (let i = 0; i < 10; i += 1) if (bytes[i] !== 0) mapped = false;
  if (mapped && bytes[10] === 255 && bytes[11] === 255) {
    return { family: 1, bytes: bytes.slice(12) };
  }
  return { family: 2, bytes };
}
function isGlobalUnicast(ip) {
  return ip ? ip.family === 1 ? isIpv4GlobalUnicast(ip.bytes) : isV6GlobalUnicast(ip.bytes) : false;
}
function subnetForEcs(cfConnectingIp, ipv4Prefix, ipv6Prefix) {
  if (!cfConnectingIp) return null;
  const ip = parseIpString(cfConnectingIp);
  if (ip === null || !isGlobalUnicast(ip)) return null;
  const prefixLength = ip.family === 1 ? ipv4Prefix : ipv6Prefix;
  const network = ip.bytes.slice();
  const whole = Math.floor(prefixLength / 8);
  const rem = prefixLength % 8;
  if (rem !== 0) network[whole] = network[whole] & 255 << 8 - rem;
  network.fill(0, whole + (rem === 0 ? 0 : 1));
  return { family: ip.family, bytes: ip.bytes, network, prefixLength };
}

// src/rules.js
var DEC = new TextDecoder("latin1");
var ENC = new TextEncoder();
var DEFAULT_RULES_URL = "https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/direct-list.txt";
var BUILTIN_OVERRIDE = [
  "linux.do",
  // 主论坛及子域
  "github.com",
  "githubusercontent.com",
  "githubassets.com"
];
var KV_KEY = "rules:data";
var KV_MAX_BYTES = 8 * 1024 * 1024;
var FAIL_COOLDOWN_MS = 3e4;
var failUntil = 0;
var live = null;
var coldInflight = null;
function noteFailure() {
  failUntil = Date.now() + FAIL_COOLDOWN_MS;
}
function inFailureWindow() {
  return Date.now() < failUntil;
}
function parseRuleText(text) {
  const plain = [];
  const plainSet = /* @__PURE__ */ new Set();
  const full = /* @__PURE__ */ new Set();
  const regexp = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    if (line.startsWith("full:")) {
      const d = line.slice(5).trim().toLowerCase();
      if (d) full.add(d);
    } else if (line.startsWith("regexp:")) {
      const d = line.slice(7).trim();
      if (d) regexp.push(new RegExp(d, "i"));
    } else {
      const d = line.toLowerCase();
      plain.push(d);
      plainSet.add(d);
    }
  }
  plain.sort();
  return { plain, plainSet, full, regexp, version: text.length };
}
function matchesRules(qname, rules) {
  const q = qname.toLowerCase();
  if (matchesBuiltin(q)) return true;
  if (!rules) return false;
  if (rules.full && rules.full.has(q)) return true;
  if (rules.plainSet) {
    if (rules.plainSet.has(q)) return true;
    let dotIdx = q.indexOf(".");
    while (dotIdx !== -1) {
      const parent = q.slice(dotIdx + 1);
      if (rules.plainSet.has(parent)) return true;
      dotIdx = q.indexOf(".", dotIdx + 1);
    }
  } else if (rules.plain) {
    for (let i = 0; i < rules.plain.length; i += 1) {
      const p = rules.plain[i];
      if (q === p || q.endsWith(`.${p}`)) return true;
    }
  }
  if (rules.regexp) {
    for (let i = 0; i < rules.regexp.length; i += 1) {
      if (rules.regexp[i].test(q)) return true;
    }
  }
  return false;
}
var BUILTIN = new Set(BUILTIN_OVERRIDE.map((d) => d.toLowerCase()));
function matchesBuiltin(q) {
  if (BUILTIN.has(q)) return true;
  let dotIdx = q.indexOf(".");
  while (dotIdx !== -1) {
    const parent = q.slice(dotIdx + 1);
    if (BUILTIN.has(parent)) return true;
    dotIdx = q.indexOf(".", dotIdx + 1);
  }
  return false;
}
function isDomestic(qname, rules) {
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
async function ensureRules(env, fetcher = fetch) {
  if (live) return live;
  if (env.RULES_KV) {
    const fromKv = await ensureFromKv(env.RULES_KV);
    if (fromKv) return fromKv;
  }
  if (inFailureWindow()) return null;
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
async function refreshRules(env, fetcher = fetch) {
  const rulesUrl = env.RULES_URL || DEFAULT_RULES_URL;
  try {
    const { rule, bytes } = await fetchAndAdopt(rulesUrl, fetcher);
    live = rule;
    if (env.RULES_KV) {
      try {
        await env.RULES_KV.put(KV_KEY, bytes);
      } catch {
      }
    }
    return true;
  } catch {
    noteFailure();
    return false;
  }
}
async function adoptRawRules(text, env) {
  if (typeof text !== "string" || text.trim().length === 0) {
    throw new Error("rules_empty");
  }
  if (text.toLowerCase().includes("<html")) {
    throw new Error("rules_html_response");
  }
  const bytes = ENC.encode(text);
  if (bytes.byteLength > KV_MAX_BYTES) {
    throw new Error("rules_too_large");
  }
  const parsed = parseRuleText(text);
  const rule = { ...parsed, data: text };
  live = rule;
  failUntil = 0;
  if (env && env.RULES_KV) {
    await env.RULES_KV.put(KV_KEY, bytes);
  }
  return {
    ruleCount: parsed.plain.length + parsed.full.size + parsed.regexp.length,
    bytes: bytes.byteLength
  };
}
function resetRules() {
  live = null;
  coldInflight = null;
  failUntil = 0;
}

// src/filter.js
var DEC2 = new TextDecoder("latin1");
var ENC2 = new TextEncoder();
var KV_KEY2 = "block:data";
var live2 = null;
var coldInflight2 = null;
function parseRuleText2(text) {
  const plain = [];
  const plainSet = /* @__PURE__ */ new Set();
  const full = /* @__PURE__ */ new Set();
  const regexp = [];
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith("//")) continue;
    if (line.startsWith("full:")) {
      full.add(line.slice(5).trim().toLowerCase());
    } else if (line.startsWith("regexp:")) {
      regexp.push(new RegExp(line.slice(7).trim(), "i"));
    } else {
      const d = line.toLowerCase();
      plain.push(d);
      plainSet.add(d);
    }
  }
  plain.sort();
  return { plain, plainSet, full, regexp, version: text.length };
}
function matches(qname, rule) {
  const q = qname.toLowerCase();
  if (!rule) return false;
  if (rule.full && rule.full.has(q)) return true;
  if (rule.plainSet) {
    if (rule.plainSet.has(q)) return true;
    let dotIdx = q.indexOf(".");
    while (dotIdx !== -1) {
      const parent = q.slice(dotIdx + 1);
      if (rule.plainSet.has(parent)) return true;
      dotIdx = q.indexOf(".", dotIdx + 1);
    }
  } else if (rule.plain) {
    for (let i = 0; i < rule.plain.length; i += 1) {
      const p = rule.plain[i];
      if (q === p || q.endsWith(`.${p}`)) return true;
    }
  }
  if (rule.regexp) {
    for (let i = 0; i < rule.regexp.length; i += 1) {
      if (rule.regexp[i].test(q)) return true;
    }
  }
  return false;
}
function isBlocked(qname, rule) {
  return matches(qname, rule);
}
var disabled = false;
async function ensureBlock(env, fetcher = fetch) {
  if (live2) return live2;
  if (!env.BLOCK_URL && disabled) return null;
  if (env.BLOCK_KV) {
    try {
      const raw = await env.BLOCK_KV.get(KV_KEY2);
      if (raw) {
        const bytes = typeof raw === "string" ? ENC2.encode(raw) : raw;
        const text = DEC2.decode(bytes);
        live2 = { ...parseRuleText2(text), data: text };
        return live2;
      }
    } catch {
    }
  }
  const url = env.BLOCK_URL || "";
  if (!url) {
    disabled = true;
    return null;
  }
  if (!coldInflight2) {
    coldInflight2 = (async () => {
      try {
        const resp = await fetcher(url, { method: "GET", redirect: "manual" });
        if (!resp.ok) return null;
        const ct = (resp.headers.get("content-type") || "").toLowerCase();
        if (ct.includes("text/html")) return null;
        const buf = await resp.arrayBuffer();
        const text = DEC2.decode(buf);
        const rule = parseRuleText2(text);
        live2 = { ...rule, data: text };
        if (env.BLOCK_KV) {
          try {
            await env.BLOCK_KV.put(KV_KEY2, new Uint8Array(buf));
          } catch {
          }
        }
        return live2;
      } catch {
        return null;
      }
    })().finally(() => {
      coldInflight2 = null;
    });
  }
  return coldInflight2;
}
function resetBlock() {
  live2 = null;
  coldInflight2 = null;
  disabled = false;
}
async function refreshBlock(env, fetcher = fetch) {
  const url = env.BLOCK_URL || "";
  if (!url) return false;
  try {
    const resp = await fetcher(url, { method: "GET", redirect: "manual" });
    if (!resp.ok) return false;
    const ct = (resp.headers.get("content-type") || "").toLowerCase();
    if (ct.includes("text/html")) return false;
    const buf = await resp.arrayBuffer();
    const text = DEC2.decode(buf);
    live2 = { ...parseRuleText2(text), data: text };
    if (env.BLOCK_KV) {
      try {
        await env.BLOCK_KV.put(KV_KEY2, new Uint8Array(buf));
      } catch {
      }
    }
    return true;
  } catch {
    return false;
  }
}

// src/jsonapi.js
var DECODE = new TextDecoder("latin1");
var TYPE_STR = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  65: "HTTPS"
};
function readU162(b, o) {
  return b[o] << 8 | b[o + 1];
}
function toU32(b, o) {
  return (b[o] & 255) << 24 | (b[o + 1] & 255) << 16 | (b[o + 2] & 255) << 8 | b[o + 3] & 255;
}
function readName(b, o) {
  let out = "";
  let p = o;
  let jumped = false;
  let jumpTo = 0;
  while (true) {
    if (p >= b.length) break;
    const len = b[p];
    if (len === 0) {
      p += 1;
      break;
    }
    if ((len & 192) === 192) {
      if (!jumped) {
        jumpTo = p + 2;
        jumped = true;
      }
      p = (len & 63) << 8 | b[p + 1];
      continue;
    }
    if (out) out += ".";
    for (let i = 1; i <= len; i++) out += String.fromCharCode(b[p + i] & 255);
    p += len + 1;
  }
  return { name: out, end: jumped ? jumpTo : p };
}
function rdataString(type, wire, off, len) {
  switch (type) {
    case 1: {
      if (len < 4 || off + 4 > wire.length) return "";
      return `${wire[off]}.${wire[off + 1]}.${wire[off + 2]}.${wire[off + 3]}`;
    }
    case 28: {
      if (len < 16 || off + 16 > wire.length) return "";
      const h = [];
      for (let i = 0; i < 8; i++) {
        const idx = off + i * 2;
        h.push((wire[idx] << 8 | wire[idx + 1]).toString(16));
      }
      return h.join(":");
    }
    case 5:
    case 2:
    case 12: {
      const r = readName(wire, off);
      return r.name;
    }
    case 16: {
      if (len === 0 || off + len > wire.length) return "";
      let p = off;
      const end = off + len;
      const parts = [];
      while (p < end) {
        const slen = wire[p];
        p += 1;
        if (p + slen > end) {
          parts.push(DECODE.decode(wire.subarray(p, end)));
          break;
        }
        parts.push(DECODE.decode(wire.subarray(p, p + slen)));
        p += slen;
      }
      return JSON.stringify(parts.join(""));
    }
    case 15: {
      if (len < 2 || off + 2 > wire.length) return "";
      const pref = readU162(wire, off);
      const r = readName(wire, off + 2);
      return `${pref} ${r.name}`;
    }
    case 6: {
      if (len < 22 || off + len > wire.length) return "";
      const mname = readName(wire, off);
      const rname = readName(wire, mname.end);
      let p = rname.end;
      if (p + 20 > off + len) return `${mname.name} ${rname.name}`;
      const ser = toU32(wire, p);
      const refresh = toU32(wire, p + 4);
      const retry2 = toU32(wire, p + 8);
      const expire = toU32(wire, p + 12);
      const mini = toU32(wire, p + 16);
      return `${mname.name} ${rname.name} ${ser} ${refresh} ${retry2} ${expire} ${mini}`;
    }
    default:
      return Array.from(wire.subarray(off, Math.min(off + len, off + 64))).map((x) => x.toString(16).padStart(2, "0")).join("");
  }
}
function toJsonResponse(wire, qname, qtypeName) {
  if (!wire || wire.length < 12) {
    return { Status: 2, RA: false, Question: [{ name: qname, type: qtypeName }] };
  }
  const flags = readU162(wire, 2);
  const qd = readU162(wire, 4);
  const an = readU162(wire, 6);
  const ns = readU162(wire, 8);
  const ar = readU162(wire, 10);
  const rc = flags & 15;
  const rd = !!(flags & 256);
  const ra = !!(flags & 128);
  const ad = !!(flags & 32);
  const tc = !!(flags & 512);
  const cd = !!(flags & 16);
  const questions = [];
  let p = 12;
  for (let i = 0; i < qd; i++) {
    const { name, end } = readName(wire, p);
    const t = readU162(wire, end);
    questions.push({ name, type: TYPE_STR[t] || `TYPE${t}` });
    p = end + 4;
  }
  const collect = (count) => {
    const arr = [];
    for (let i = 0; i < count; i++) {
      if (p >= wire.length) break;
      const { name, end } = readName(wire, p);
      p = end;
      if (p + 10 > wire.length) break;
      const t = readU162(wire, p);
      const cl = readU162(wire, p + 2);
      const ttl = toU32(wire, p + 4);
      const len = readU162(wire, p + 8);
      p += 10;
      if (p + len > wire.length) break;
      const rdataOffset = p;
      p += len;
      const typeName = TYPE_STR[t] || `TYPE${t}`;
      arr.push({
        name,
        type: typeName,
        TTL: ttl,
        data: rdataString(t, wire, rdataOffset, len)
      });
    }
    return arr;
  };
  const answers = collect(an);
  const authority = collect(ns);
  const additional = collect(ar);
  return {
    Status: rc,
    TC: tc,
    RD: rd,
    RA: ra,
    AD: ad,
    CD: cd,
    Question: questions.length ? questions : [{ name: qname, type: qtypeName }],
    Answer: answers,
    Authority: authority,
    Additional: additional
  };
}
function jsonResponse(obj, minTtlSeconds = 0) {
  const cc = minTtlSeconds > 0 ? `max-age=${minTtlSeconds}` : "no-store";
  return new Response(JSON.stringify(obj), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": cc,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type"
    }
  });
}

// src/resolver.js
async function queryUpstream(url, query, { timeoutMs, maxResponseBytes, signal }) {
  const controller = new AbortController();
  const onParentAbort = () => controller.abort();
  if (signal) {
    if (signal.aborted) controller.abort();
    else signal.addEventListener("abort", onParentAbort, { once: true });
  }
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const start = performance.now();
  try {
    const resp = await fetch(url, {
      method: "POST",
      redirect: "manual",
      signal: controller.signal,
      headers: {
        Accept: DNS_CONTENT_TYPE,
        "Content-Type": DNS_CONTENT_TYPE
      },
      body: query
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
    if (signal) signal.removeEventListener("abort", onParentAbort);
  }
}
function classify(r) {
  if (r.ok) {
    try {
      const flags = validateUpstreamResponse(r.body, null);
      return (flags & 15) === 2 ? "servfail" : "ok";
    } catch {
      return "bad_response";
    }
  }
  return r.reason === "timeout" ? "timeout" : "error";
}
async function raceGroup(urls, query, parsedInfo, { timeoutMs, maxResponseBytes, on }) {
  const groupController = new AbortController();
  const settle = (r) => {
    if (on) on({ kind: classify(r), url: r.url, durationMs: r.durationMs ?? 0 });
  };
  const pending = urls.map(async (url) => {
    const res = await queryUpstream(url, query, { timeoutMs, maxResponseBytes, signal: groupController.signal });
    return { url, ...res };
  });
  const results = new Array(pending.length);
  let settled = 0;
  return new Promise((resolve) => {
    for (let i = 0; i < pending.length; i += 1) {
      pending[i].then(
        (r) => {
          settled += 1;
          results[i] = r;
          settle(r);
          if (r.ok) {
            try {
              const flags = validateUpstreamResponse(r.body, parsedInfo ?? null);
              if ((flags & 15) !== 2) {
                groupController.abort();
                resolve({ answer: r.body, from: r.url, durationMs: r.durationMs ?? 0 });
                return;
              }
            } catch {
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
function serverFailure(fromQuery, question) {
  return buildErrorResponse(fromQuery, 2, question ?? null);
}

// src/metrics.js
var COUNTERS = {
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
  filter_blocked: 0
};
var startedAt = Date.now();
var UPSTREAM_WINS = {};
var MAX_SAMPLES = 300;
var LATENCY_SAMPLES = {
  domestic: [],
  global: []
};
function inc(name, n = 1) {
  COUNTERS[name] = (COUNTERS[name] || 0) + n;
}
function snapshot() {
  return { ...COUNTERS };
}
function recordUpstreamRace(group, winnerUrl, durationMs) {
  let host = "unknown";
  if (winnerUrl) {
    try {
      host = new URL(winnerUrl).hostname;
    } catch {
      host = String(winnerUrl);
    }
  }
  UPSTREAM_WINS[host] = (UPSTREAM_WINS[host] || 0) + 1;
  const key = group === "domestic" ? "domestic" : "global";
  if (typeof durationMs === "number" && durationMs >= 0) {
    const arr = LATENCY_SAMPLES[key];
    if (arr.length >= MAX_SAMPLES) arr.shift();
    arr.push(Math.round(durationMs * 10) / 10);
  }
}
function recordAnalyticsPoint(env, { group, winnerUrl, durationMs, qtype, rcode, cacheStatus }) {
  if (env && env.DOH_ANALYTICS && typeof env.DOH_ANALYTICS.writeDataPoint === "function") {
    let host = "cache";
    if (winnerUrl && winnerUrl !== "cache") {
      try {
        host = new URL(winnerUrl).hostname;
      } catch {
        host = String(winnerUrl);
      }
    }
    try {
      env.DOH_ANALYTICS.writeDataPoint({
        blobs: [
          host,
          group || "unknown",
          qtype ? String(qtype) : "A",
          rcode ? String(rcode) : "NOERROR",
          cacheStatus || "miss"
        ],
        doubles: [typeof durationMs === "number" ? durationMs : 0],
        indexes: [host]
      });
    } catch {
    }
  }
}
function computePercentiles(samples) {
  if (!samples || samples.length === 0) {
    return { count: 0, avgMs: 0, p50Ms: 0, p90Ms: 0, p95Ms: 0, minMs: 0, maxMs: 0 };
  }
  const sorted = [...samples].sort((a, b) => a - b);
  const sum = samples.reduce((acc, v) => acc + v, 0);
  return {
    count: samples.length,
    avgMs: Math.round(sum / samples.length * 10) / 10,
    p50Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.5))],
    p90Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.9))],
    p95Ms: sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * 0.95))],
    minMs: sorted[0],
    maxMs: sorted[sorted.length - 1]
  };
}
function statsSnapshot(config = {}) {
  const domesticUrls = config.domesticUrls || [
    config.domesticUrl || "https://dns.alidns.com/dns-query",
    config.domesticFallbackUrl || "https://doh.pub/dns-query"
  ];
  const globalUrls = config.globalUrls || [
    config.globalUrl || "https://dns.google/dns-query",
    config.globalFallbackUrl || "https://cloudflare-dns.com/dns-query"
  ];
  function buildGroupStats(urls) {
    const list = urls.map((u) => {
      let host = u;
      try {
        host = new URL(u).hostname;
      } catch {
      }
      return { url: u, host, wins: UPSTREAM_WINS[host] || 0 };
    });
    const totalWins = list.reduce((acc, item) => acc + item.wins, 0);
    const result = {};
    for (const item of list) {
      result[item.host] = {
        wins: item.wins,
        winRate: totalWins > 0 ? `${(item.wins / totalWins * 100).toFixed(1)}%` : "0.0%"
      };
    }
    return { upstreams: result, totalWins };
  }
  const domesticStats = buildGroupStats(domesticUrls);
  const globalStats = buildGroupStats(globalUrls);
  const totalCacheRequests = COUNTERS.cache_hit + COUNTERS.cache_miss;
  const cacheHitRate = totalCacheRequests > 0 ? `${(COUNTERS.cache_hit / totalCacheRequests * 100).toFixed(1)}%` : "0.0%";
  return {
    service: "cf-doh",
    version: "1.1.0",
    uptimeSec: Math.round((Date.now() - startedAt) / 1e3),
    totalRequests: COUNTERS.requests,
    cache: {
      hits: COUNTERS.cache_hit,
      misses: COUNTERS.cache_miss,
      hitRate: cacheHitRate
    },
    latency: {
      domestic: computePercentiles(LATENCY_SAMPLES.domestic),
      global: computePercentiles(LATENCY_SAMPLES.global)
    },
    upstreams: {
      domestic: domesticStats,
      global: globalStats
    },
    rawWins: { ...UPSTREAM_WINS }
  };
}
function statsResponse(config) {
  const body = JSON.stringify(statsSnapshot(config), null, 2);
  return new Response(body, {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
function parseAnalyticsRows(rows, config = {}, dataset = "cf_doh_metrics") {
  const domesticUrls = config.domesticUrls || [
    config.domesticUrl || "https://dns.alidns.com/dns-query",
    config.domesticFallbackUrl || "https://doh.pub/dns-query"
  ];
  const globalUrls = config.globalUrls || [
    config.globalUrl || "https://dns.google/dns-query",
    config.globalFallbackUrl || "https://cloudflare-dns.com/dns-query"
  ];
  let totalRequests = 0;
  let cacheHits = 0;
  let cacheMisses = 0;
  const winCounts = {};
  const domesticLatencies = [];
  const globalLatencies = [];
  for (const row of rows || []) {
    const host = String(row.host || "unknown");
    const group = String(row.group_name || "unknown");
    const cacheStatus = String(row.cache_status || "miss");
    const count = Number(row.total_count || row.count || 0);
    const avg = Number(row.avg_duration || 0);
    const p50 = Number(row.p50 || 0);
    const p90 = Number(row.p90 || 0);
    const p95 = Number(row.p95 || 0);
    const min = Number(row.min_duration || 0);
    const max = Number(row.max_duration || 0);
    totalRequests += count;
    if (cacheStatus === "hit") {
      cacheHits += count;
    } else {
      cacheMisses += count;
      if (host !== "cache" && host !== "unknown") {
        winCounts[host] = (winCounts[host] || 0) + count;
      }
      if (group === "domestic") {
        domesticLatencies.push({ count, avg, p50, p90, p95, min, max });
      } else if (group === "global") {
        globalLatencies.push({ count, avg, p50, p90, p95, min, max });
      }
    }
  }
  function buildGroupStats(urls) {
    const list = urls.map((u) => {
      let host = u;
      try {
        host = new URL(u).hostname;
      } catch {
      }
      return { url: u, host, wins: winCounts[host] || 0 };
    });
    const totalWins = list.reduce((acc, item) => acc + item.wins, 0);
    const res = {};
    for (const item of list) {
      res[item.host] = {
        wins: item.wins,
        winRate: totalWins > 0 ? `${(item.wins / totalWins * 100).toFixed(1)}%` : "0.0%"
      };
    }
    return { upstreams: res, totalWins };
  }
  function aggregateLatency(list) {
    const total = list.reduce((sum, item) => sum + item.count, 0);
    if (total === 0) {
      return { count: 0, avgMs: 0, p50Ms: 0, p90Ms: 0, p95Ms: 0, minMs: 0, maxMs: 0 };
    }
    const weightedAvg = list.reduce((sum, item) => sum + item.avg * item.count, 0) / total;
    const weightedP50 = list.reduce((sum, item) => sum + item.p50 * item.count, 0) / total;
    const maxP90 = Math.max(...list.map((item) => item.p90));
    const maxP95 = Math.max(...list.map((item) => item.p95));
    const minVal = Math.min(...list.map((item) => item.min));
    const maxVal = Math.max(...list.map((item) => item.max));
    return {
      count: total,
      avgMs: Math.round(weightedAvg * 10) / 10,
      p50Ms: Math.round(weightedP50 * 10) / 10,
      p90Ms: Math.round(maxP90 * 10) / 10,
      p95Ms: Math.round(maxP95 * 10) / 10,
      minMs: Math.round(minVal * 10) / 10,
      maxMs: Math.round(maxVal * 10) / 10
    };
  }
  const cacheTotal = cacheHits + cacheMisses;
  const cacheHitRate = cacheTotal > 0 ? `${(cacheHits / cacheTotal * 100).toFixed(1)}%` : "0.0%";
  return {
    scope: "global",
    available: true,
    dataset,
    timespan: "24h",
    totalRequests,
    cache: {
      hits: cacheHits,
      misses: cacheMisses,
      hitRate: cacheHitRate
    },
    latency: {
      domestic: aggregateLatency(domesticLatencies),
      global: aggregateLatency(globalLatencies)
    },
    upstreams: {
      domestic: buildGroupStats(domesticUrls),
      global: buildGroupStats(globalUrls)
    },
    rawWins: { ...winCounts }
  };
}
async function queryGlobalStats(env = {}, config = {}, { interval = "1 DAY" } = {}) {
  const accountId = env.CF_ACCOUNT_ID || env.ACCOUNT_ID;
  const token = env.CF_ANALYTICS_READ_TOKEN || env.CLOUDFLARE_API_TOKEN;
  const dataset = env.ANALYTICS_DATASET || "cf_doh_metrics";
  if (!accountId || !token) {
    return {
      scope: "global",
      available: false,
      reason: "missing_credentials",
      message: "Global multi-PoP aggregation requires CF_ACCOUNT_ID and CF_ANALYTICS_READ_TOKEN (or CLOUDFLARE_API_TOKEN) environment variables.",
      fallback: statsSnapshot(config)
    };
  }
  const safeInterval = interval.replace(/[^0-9A-Za-z ]/g, "") || "1 DAY";
  const sql = `
SELECT
  blob1 AS host,
  blob2 AS group_name,
  blob5 AS cache_status,
  count() AS total_count,
  avg(double1) AS avg_duration,
  quantile(0.5)(double1) AS p50,
  quantile(0.9)(double1) AS p90,
  quantile(0.95)(double1) AS p95,
  min(double1) AS min_duration,
  max(double1) AS max_duration
FROM ${dataset}
WHERE timestamp >= NOW() - INTERVAL '${safeInterval}'
GROUP BY host, group_name, cache_status
FORMAT JSON
  `.trim();
  const url = `https://api.cloudflare.com/client/v4/accounts/${encodeURIComponent(accountId)}/analytics_engine/sql`;
  try {
    const resp = await fetch(url, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/sql"
      },
      body: sql
    });
    if (!resp.ok) {
      const errText = await resp.text();
      return {
        scope: "global",
        available: false,
        reason: `http_${resp.status}`,
        message: `Analytics Engine SQL API error (${resp.status}): ${errText.slice(0, 200)}`,
        fallback: statsSnapshot(config)
      };
    }
    const result = await resp.json();
    const rows = Array.isArray(result?.data) ? result.data : [];
    return parseAnalyticsRows(rows, config, dataset);
  } catch (err) {
    return {
      scope: "global",
      available: false,
      reason: "network_error",
      message: String(err?.message || err),
      fallback: statsSnapshot(config)
    };
  }
}
async function globalStatsResponse(config, env, options) {
  const stats = await queryGlobalStats(env, config, options);
  return new Response(JSON.stringify(stats, null, 2), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*"
    }
  });
}
function healthResponse(config) {
  const body = JSON.stringify(
    {
      status: "ok",
      service: "cf-doh",
      version: "1.1.0",
      uptimeSec: Math.round((Date.now() - startedAt) / 1e3),
      counters: snapshot(),
      stats: statsSnapshot(config),
      config: {
        path: config.path,
        upstreams: { domestic: config.domesticUrls, global: config.globalUrls },
        ecs: { v4: config.ecsV4Prefix, v6: config.ecsV6Prefix }
      }
    },
    null,
    2
  );
  return new Response(body, {
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store" }
  });
}
function resetMetrics() {
  for (const k of Object.keys(COUNTERS)) COUNTERS[k] = 0;
  for (const k of Object.keys(UPSTREAM_WINS)) delete UPSTREAM_WINS[k];
  LATENCY_SAMPLES.domestic.length = 0;
  LATENCY_SAMPLES.global.length = 0;
  startedAt = Date.now();
}
var metrics = {
  inc,
  snapshot,
  recordUpstreamRace,
  recordAnalyticsPoint,
  statsSnapshot,
  statsResponse,
  parseAnalyticsRows,
  queryGlobalStats,
  globalStatsResponse,
  healthResponse,
  resetMetrics
};

// src/cache.js
var DEFAULT_SIZE = 1024;
function createCache({ size = DEFAULT_SIZE, now = Date.now } = {}) {
  const map = /* @__PURE__ */ new Map();
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
      map.set(k, { value, expiresAt: ts + ttl * 1e3 });
      while (map.size > size) {
        const oldest = map.keys().next().value;
        if (oldest === void 0) break;
        map.delete(oldest);
      }
    },
    /** Number of live entries (metrics). */
    size() {
      return map.size;
    }
  };
}

// src/landing.js
function renderLandingHtml(origin, config) {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>cf-doh \u2014 \u9AD8\u6027\u80FD\u81EA\u7814 Cloudflare Workers DoH \u89E3\u6790\u7F51\u5173</title>
  <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>\u26A1</text></svg>">
  <style>
    :root {
      --bg: #0b0f19;
      --card-bg: rgba(23, 32, 54, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --text: #f3f4f6;
      --text-muted: #9ca3af;
      --primary: #3b82f6;
      --primary-hover: #2563eb;
      --accent: #10b981;
      --accent-orange: #f59e0b;
      --code-bg: #060911;
    }
    @media (prefers-color-scheme: light) {
      :root {
        --bg: #f8fafc;
        --card-bg: rgba(255, 255, 255, 0.9);
        --card-border: rgba(0, 0, 0, 0.08);
        --text: #0f172a;
        --text-muted: #64748b;
        --primary: #2563eb;
        --primary-hover: #1d4ed8;
        --accent: #059669;
        --accent-orange: #d97706;
        --code-bg: #f1f5f9;
      }
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 0;
      overflow-x: hidden;
    }
    .container {
      max-width: 1080px;
      margin: 0 auto;
      padding: 40px 20px 80px 20px;
    }
    header {
      text-align: center;
      margin-bottom: 48px;
    }
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 12px;
      border-radius: 9999px;
      font-size: 0.85rem;
      font-weight: 500;
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      border: 1px solid rgba(59, 130, 246, 0.3);
      margin-bottom: 16px;
    }
    h1 {
      font-size: 2.75rem;
      font-weight: 800;
      letter-spacing: -0.025em;
      margin-bottom: 12px;
      background: linear-gradient(135deg, #60a5fa 0%, #3b82f6 50%, #93c5fd 100%);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .subtitle {
      font-size: 1.15rem;
      color: var(--text-muted);
      max-width: 680px;
      margin: 0 auto 24px auto;
    }
    .tags {
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      gap: 8px;
    }
    .tag {
      background: var(--card-bg);
      border: 1px solid var(--card-border);
      padding: 4px 10px;
      border-radius: 6px;
      font-size: 0.8rem;
      color: var(--text-muted);
    }
    .grid {
      display: grid;
      grid-template-columns: 1fr;
      gap: 24px;
      margin-bottom: 32px;
    }
    @media (min-width: 768px) {
      .grid-2 { grid-template-columns: 1fr 1fr; }
    }
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--card-border);
      border-radius: 16px;
      padding: 24px;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
    }
    .card-title {
      display: flex;
      align-items: center;
      gap: 10px;
      font-size: 1.25rem;
      font-weight: 600;
      margin-bottom: 16px;
    }
    .input-group {
      display: flex;
      gap: 8px;
      margin-bottom: 16px;
    }
    input[type="text"] {
      flex: 1;
      padding: 10px 14px;
      border-radius: 8px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      transition: border-color 0.2s;
    }
    input[type="text"]:focus {
      border-color: var(--primary);
    }
    select {
      padding: 10px 12px;
      border-radius: 8px;
      border: 1px solid var(--card-border);
      background: var(--code-bg);
      color: var(--text);
      font-size: 0.95rem;
      outline: none;
      cursor: pointer;
    }
    button.btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 6px;
      padding: 10px 18px;
      background: var(--primary);
      color: #fff;
      border: none;
      border-radius: 8px;
      font-weight: 600;
      font-size: 0.95rem;
      cursor: pointer;
      transition: all 0.2s;
    }
    button.btn:hover { background: var(--primary-hover); transform: translateY(-1px); }
    .quick-chips {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
      margin-bottom: 16px;
    }
    .chip {
      background: var(--code-bg);
      border: 1px solid var(--card-border);
      padding: 3px 8px;
      border-radius: 6px;
      font-size: 0.8rem;
      color: var(--text-muted);
      cursor: pointer;
      transition: all 0.2s;
    }
    .chip:hover { color: var(--primary); border-color: var(--primary); }
    .result-box {
      background: var(--code-bg);
      border-radius: 10px;
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.88rem;
      border: 1px solid var(--card-border);
      min-height: 120px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-all;
    }
    .tabs {
      display: flex;
      gap: 6px;
      border-bottom: 1px solid var(--card-border);
      margin-bottom: 16px;
      overflow-x: auto;
      padding-bottom: 6px;
    }
    .tab-btn {
      padding: 6px 14px;
      border-radius: 6px;
      font-size: 0.88rem;
      background: transparent;
      border: none;
      color: var(--text-muted);
      cursor: pointer;
      font-weight: 500;
      white-space: nowrap;
    }
    .tab-btn.active {
      background: rgba(59, 130, 246, 0.15);
      color: #60a5fa;
      font-weight: 600;
    }
    .scope-btn {
      background: transparent;
      border: none;
      color: var(--text-muted);
      padding: 4px 10px;
      font-size: 0.78rem;
      border-radius: 6px;
      cursor: pointer;
      font-weight: 500;
      transition: all 0.2s;
    }
    .scope-btn.active {
      background: var(--primary);
      color: #fff;
    }
    .scope-btn:hover:not(.active) {
      color: var(--text);
    }
    .code-block {
      position: relative;
      background: var(--code-bg);
      border-radius: 10px;
      padding: 16px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
      font-size: 0.85rem;
      border: 1px solid var(--card-border);
      overflow-x: auto;
    }
    .copy-btn {
      position: absolute;
      top: 10px;
      right: 10px;
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.15);
      color: var(--text);
      border-radius: 6px;
      padding: 4px 8px;
      font-size: 0.75rem;
      cursor: pointer;
      transition: background 0.2s;
    }
    .copy-btn:hover { background: rgba(255, 255, 255, 0.2); }
    .feature-list {
      list-style: none;
      display: grid;
      grid-template-columns: 1fr;
      gap: 12px;
    }
    @media (min-width: 640px) {
      .feature-list { grid-template-columns: 1fr 1fr; }
    }
    .feature-item {
      display: flex;
      gap: 12px;
      align-items: flex-start;
    }
    .feature-icon {
      font-size: 1.25rem;
      background: rgba(59, 130, 246, 0.1);
      padding: 8px;
      border-radius: 8px;
      line-height: 1;
    }
    .footer {
      text-align: center;
      color: var(--text-muted);
      font-size: 0.9rem;
      margin-top: 48px;
      border-top: 1px solid var(--card-border);
      padding-top: 24px;
    }
    .footer a {
      color: var(--primary);
      text-decoration: none;
    }
    .footer a:hover { text-decoration: underline; }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="badge">\u{1F680} Cloudflare Workers \u2022 RFC 8484 \u2022 \u7EAF\u81EA\u7814</div>
      <h1>cf-doh \u89E3\u6790\u7F51\u5173</h1>
      <p class="subtitle">\u4E13\u4E3A\u56FD\u5185\u76F4\u8FDE\u52A0\u901F\u5B9A\u5236\u7684\u81EA\u7814 DNS-over-HTTPS \u89E3\u6790\u670D\u52A1\u3002\u5185\u7F6E\u56FD\u5185\u5916\u667A\u80FD\u5206\u6D41\u3001\u771F\u5B9E\u53EF\u4FE1 ECS \u6CE8\u5165\u4E0E\u5168\u4E0A\u6E38\u5E76\u53D1\u7ADE\u901F\u3002</p>
      <div class="tags">
        <span class="tag">\u26A1 \u5E76\u53D1\u7ADE\u4EF7 (Zero Wait)</span>
        <span class="tag">\u{1F6E1}\uFE0F \u53EF\u4FE1\u51FA\u53E3 ECS</span>
        <span class="tag">\u{1F1E8}\u{1F1F3} \u963F\u91CC\u4E91 / \u817E\u8BAF\u4E91 \u76F4\u8FDE</span>
        <span class="tag">\u{1F310} Google / CF \u5168\u7403\u515C\u5E95</span>
        <span class="tag">\u{1F512} DNSSEC \u900F\u4F20</span>
        <span class="tag">\u{1F4CA} JSON API \u517C\u5BB9</span>
      </div>
    </header>

    <div class="grid grid-2">
      <!-- \u5B9E\u65F6 DNS \u8C03\u8BD5\u5361\u7247 -->
      <div class="card">
        <div class="card-title">
          <span>\u{1F9EA}</span>
          <span>\u5728\u7EBF\u89E3\u6790\u6D4B\u8BD5\u53F0 (Live Playground)</span>
        </div>
        <p style="font-size:0.88rem; color:var(--text-muted); margin-bottom:12px;">
          \u5B9E\u65F6\u6D4B\u8BD5\u57DF\u540D\u5728\u5F53\u524D\u8282\u70B9\u7684\u5206\u6D41\u7B56\u7565\u3001\u89E3\u6790 IP \u4E0E\u54CD\u5E94\u8017\u65F6\uFF1A
        </p>
        <div class="quick-chips">
          <span class="chip" onclick="setQuery('linux.do')">linux.do (\u56FD\u5185\u7EC4)</span>
          <span class="chip" onclick="setQuery('github.com')">github.com (\u56FD\u5185\u7EC4)</span>
          <span class="chip" onclick="setQuery('bilibili.com')">bilibili.com (\u56FD\u5185\u7EC4)</span>
          <span class="chip" onclick="setQuery('google.com')">google.com (\u5168\u7403\u7EC4)</span>
          <span class="chip" onclick="setQuery('cloudflare.com')">cloudflare.com (\u5168\u7403\u7EC4)</span>
        </div>
        <div class="input-group">
          <input type="text" id="domainInput" placeholder="\u8F93\u5165\u5F85\u89E3\u6790\u57DF\u540D (\u5982 linux.do)" value="linux.do">
          <select id="typeSelect">
            <option value="A">A</option>
            <option value="AAAA">AAAA</option>
            <option value="TXT">TXT</option>
            <option value="HTTPS">HTTPS</option>
          </select>
          <button class="btn" id="queryBtn" onclick="runQuery()">\u67E5\u8BE2</button>
        </div>
        <div class="result-box" id="resultBox">\u70B9\u51FB\u300C\u67E5\u8BE2\u300D\u67E5\u770B\u771F\u5B9E\u89E3\u6790\u7ED3\u679C\u4E0E\u94FE\u8DEF\u65F6\u5EF6...</div>
      </div>

      <!-- \u7AEF\u70B9\u4FE1\u606F\u4E0E\u72B6\u6001\u5361\u7247 -->
      <div class="card">
        <div class="card-title">
          <span>\u{1F4E1}</span>
          <span>\u670D\u52A1\u63A5\u5165\u7AEF\u70B9</span>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">RFC 8484 \u6807\u51C6 DoH URL</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}${config.path}</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.path}')">\u590D\u5236</button>
          </div>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">Google \u98CE\u683C JSON API \u7AEF\u70B9</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}${config.jsonPath}?name=linux.do&type=A</code>
            <button class="copy-btn" onclick="copyText('${origin}${config.jsonPath}?name=linux.do&type=A')">\u590D\u5236</button>
          </div>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">\u5065\u5EB7\u68C0\u67E5\u4E0E\u7EDF\u8BA1\u6307\u6807</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}/healthz</code>
            <button class="copy-btn" onclick="copyText('${origin}/healthz')">\u590D\u5236</button>
          </div>
        </div>
        <div style="margin-bottom: 16px;">
          <div style="font-size: 0.85rem; color: var(--text-muted); margin-bottom: 4px;">\u7ADE\u901F\u7EDF\u8BA1 API (JSON)</div>
          <div class="code-block" style="padding: 10px 14px;">
            <code>${origin}/api/stats</code>
            <button class="copy-btn" onclick="copyText('${origin}/api/stats')">\u590D\u5236</button>
          </div>
        </div>
      </div>
    </div>

    <!-- \u{1F4CA} \u4E0A\u6E38\u7ADE\u901F\u4E0E\u5EA6\u91CF\u76D1\u63A7\u5361\u7247 -->
    <div class="card" style="margin-bottom: 32px;">
      <div class="card-title" style="justify-content: space-between; flex-wrap: wrap; gap: 10px;">
        <div style="display: flex; align-items: center; gap: 10px;">
          <span>\u{1F4CA}</span>
          <span>\u4E0A\u6E38\u5E76\u53D1\u7ADE\u901F\u4E0E\u5EF6\u8FDF\u76D1\u63A7 (Racing & P95 Metrics)</span>
        </div>
        <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
          <div style="display:inline-flex; background:rgba(255,255,255,0.06); border:1px solid var(--card-border); border-radius:8px; padding:2px; gap:2px;">
            <button id="scopeLocalBtn" class="scope-btn active" onclick="setStatsScope('local')">\u{1F4CD} \u672C\u5730 PoP \u8FB9\u7F18</button>
            <button id="scopeGlobalBtn" class="scope-btn" onclick="setStatsScope('global')">\u{1F310} \u5168\u7403\u591A\u5730\u57DF\u805A\u5408</button>
          </div>
          <button class="btn" style="padding: 5px 12px; font-size: 0.8rem;" onclick="loadStats()">
            <span>\u{1F504}</span><span>\u5237\u65B0\u6307\u6807</span>
          </button>
        </div>
      </div>
      <div id="scopeNotice" style="font-size:0.82rem; color:var(--text-muted); margin-bottom:12px; padding:6px 12px; background:rgba(255,255,255,0.03); border-radius:6px; border-left:3px solid var(--primary);">
        \u{1F4CD} \u7EDF\u8BA1\u8303\u56F4\uFF1A\u5F53\u524D Cloudflare \u8FB9\u7F18\u8282\u70B9\u5185\u5B58\u5B9E\u65F6\u91C7\u6837 (\u5355\u5B9E\u4F8B)
      </div>
      <p style="font-size:0.88rem; color:var(--text-muted); margin-bottom:16px;">
        \u6240\u6709\u4E0A\u6E38\u5E76\u53D1\u540C\u65F6\u53D1\u8D77\u8BF7\u6C42\uFF0C\u5EF6\u8FDF\u7531\u6700\u5FEB\u8282\u70B9\u51B3\u5B9A\u3002\u5B9E\u65F6\u7EDF\u8BA1\u5404\u4E0A\u6E38\u7684\u80DC\u51FA\u6BD4\u4F8B\u3001P50 / P95 \u89E3\u6790\u5EF6\u8FDF\u53CA\u8FB9\u7F18\u7F13\u5B58\u6548\u7387\u3002
      </p>

      <div class="grid grid-2" style="margin-bottom: 16px;">
        <!-- \u56FD\u5185\u7EC4\u5BF9\u6BD4 -->
        <div style="background:var(--code-bg); padding:16px; border-radius:10px; border:1px solid var(--card-border);">
          <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-weight:600; font-size:0.9rem;">
            <span>\u{1F1E8}\u{1F1F3} \u56FD\u5185\u7EC4\u7ADE\u901F (AliDNS vs DNSPod)</span>
            <span id="domesticTotalWins" style="color:var(--text-muted); font-size:0.8rem;">0 \u80DC\u51FA</span>
          </div>
          <div style="display:flex; height:10px; border-radius:9999px; overflow:hidden; background:rgba(255,255,255,0.1); margin-bottom:8px;">
            <div id="barAlidns" style="width:50%; background:#3b82f6; transition:width 0.4s;"></div>
            <div id="barDohpub" style="width:50%; background:#10b981; transition:width 0.4s;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.8rem; color:var(--text-muted);">
            <span><span style="color:#3b82f6;">\u25CF</span> \u963F\u91CC DNS: <b id="winAlidns">0 (0.0%)</b></span>
            <span><span style="color:#10b981;">\u25CF</span> \u817E\u8BAF DNSPod: <b id="winDohpub">0 (0.0%)</b></span>
          </div>
          <div style="margin-top:12px; padding-top:8px; border-top:1px dashed var(--card-border); font-size:0.8rem; display:flex; justify-content:space-between;">
            <span>P50: <b id="p50Domestic">- ms</b></span>
            <span>P95: <b id="p95Domestic" style="color:#f59e0b;">- ms</b></span>
            <span>Avg: <b id="avgDomestic">- ms</b></span>
          </div>
        </div>

        <!-- \u5168\u7403\u7EC4\u5BF9\u6BD4 -->
        <div style="background:var(--code-bg); padding:16px; border-radius:10px; border:1px solid var(--card-border);">
          <div style="display:flex; justify-content:space-between; margin-bottom:8px; font-weight:600; font-size:0.9rem;">
            <span>\u{1F310} \u5168\u7403\u7EC4\u7ADE\u901F (Google vs Cloudflare)</span>
            <span id="globalTotalWins" style="color:var(--text-muted); font-size:0.8rem;">0 \u80DC\u51FA</span>
          </div>
          <div style="display:flex; height:10px; border-radius:9999px; overflow:hidden; background:rgba(255,255,255,0.1); margin-bottom:8px;">
            <div id="barGoogle" style="width:50%; background:#8b5cf6; transition:width 0.4s;"></div>
            <div id="barCf" style="width:50%; background:#f97316; transition:width 0.4s;"></div>
          </div>
          <div style="display:flex; justify-content:space-between; font-size:0.8rem; color:var(--text-muted);">
            <span><span style="color:#8b5cf6;">\u25CF</span> Google DNS: <b id="winGoogle">0 (0.0%)</b></span>
            <span><span style="color:#f97316;">\u25CF</span> Cloudflare: <b id="winCf">0 (0.0%)</b></span>
          </div>
          <div style="margin-top:12px; padding-top:8px; border-top:1px dashed var(--card-border); font-size:0.8rem; display:flex; justify-content:space-between;">
            <span>P50: <b id="p50Global">- ms</b></span>
            <span>P95: <b id="p95Global" style="color:#f59e0b;">- ms</b></span>
            <span>Avg: <b id="avgGlobal">- ms</b></span>
          </div>
        </div>
      </div>

      <div style="display:flex; flex-wrap:wrap; gap:16px; font-size:0.82rem; color:var(--text-muted);">
        <span>\u{1F4E6} \u8FB9\u7F18\u7F13\u5B58\u547D\u4E2D\u7387: <b id="cacheHitRate" style="color:var(--accent);">0.0%</b></span>
        <span>\u{1F4C8} \u7D2F\u8BA1\u670D\u52A1\u8BF7\u6C42: <b id="totalRequests" style="color:var(--text);">0</b></span>
        <span id="uptimeWrap">\u23F1\uFE0F \u8282\u70B9\u8FD0\u884C\u65F6\u95F4: <b id="nodeUptime" style="color:var(--text);">0s</b></span>
        <span>\u2601\uFE0F Analytics Engine: <b id="analyticsStatus" style="color:var(--primary);">\u5DF2\u63A5\u5165 (Worker \u70B9\u4F4D\u5199\u5165)</b></span>
      </div>
    </div>

    <!-- \u5BA2\u6237\u7AEF\u4E00\u952E\u914D\u7F6E\u5361\u7247 -->
    <div class="card" style="margin-bottom: 32px;">
      <div class="card-title">
        <span>\u2699\uFE0F</span>
        <span>\u5168\u5E73\u53F0\u5BA2\u6237\u7AEF\u63A5\u5165\u6307\u5357</span>
      </div>
      <div class="tabs">
        <button class="tab-btn active" onclick="switchTab('clash')">Clash / Mihomo</button>
        <button class="tab-btn" onclick="switchTab('surge')">Surge</button>
        <button class="tab-btn" onclick="switchTab('shadowrocket')">Shadowrocket</button>
        <button class="tab-btn" onclick="switchTab('apple')">iOS / macOS</button>
        <button class="tab-btn" onclick="switchTab('android')">Android / Windows</button>
        <button class="tab-btn" onclick="switchTab('cli')">cURL / dig \u8C03\u8BD5</button>
      </div>

      <div id="tab-clash" class="tab-content">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-clash')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-clash"><code>dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  nameserver:
    - "${origin}${config.path}"
  default-nameserver:
    - 223.5.5.5
    - 119.29.29.29</code></pre>
        </div>
      </div>

      <div id="tab-surge" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-surge')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-surge"><code>[General]
dns-server = 223.5.5.5, 119.29.29.29
doh-server = ${origin}${config.path}
doh-format = wire</code></pre>
        </div>
      </div>

      <div id="tab-shadowrocket" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-shadowrocket')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-shadowrocket"><code># \u8FDB\u5165 Shadowrocket -> \u8BBE\u7F6E -> DNS -> \u542F\u7528 DNS-over-HTTPS
DNS \u670D\u52A1\u5668 URL:
${origin}${config.path}</code></pre>
        </div>
      </div>

      <div id="tab-apple" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-apple')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-apple"><code># iOS 14+ / macOS 11+ \u539F\u751F\u652F\u6301 DoH \u63CF\u8FF0\u6587\u4EF6 (.mobileconfig)
# \u5BF9\u5E94 DoH \u670D\u52A1\u5668\u5730\u5740:
${origin}${config.path}

# \u53EF\u4EE5\u5728 Safari \u6253\u5F00\uFF0C\u6216\u4F7F\u7528 Apple Configurator \u751F\u6210\u63CF\u8FF0\u6587\u4EF6\u3002</code></pre>
        </div>
      </div>

      <div id="tab-android" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-android')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-android"><code># Android 13+ (Private DNS / \u73B0\u4EE3\u6D4F\u89C8\u5668\u8BBE\u7F6E)
# Chrome / Edge: \u8BBE\u7F6E -> \u9690\u79C1\u548C\u5B89\u5168\u6027 -> \u4F7F\u7528\u5B89\u5168 DNS -> \u9009\u62E9\u63D0\u4F9B\u5546 -> \u81EA\u5B9A\u4E49:
${origin}${config.path}

# Windows 11: \u8BBE\u7F6E -> \u7F51\u7EDC\u548C Internet -> \u4EE5\u592A\u7F51/WLAN -> \u786C\u4EF6\u5C5E\u6027 -> DNS \u670D\u52A1\u5668\u5206\u914D:
# \u9009\u62E9\u624B\u52A8 -> IPv4/IPv6 \u5F00 -> \u586B\u5199 DNS \u5E76\u5F00\u542F\u300C\u4EC5\u52A0\u5BC6 (\u901A\u8FC7 HTTPS \u7684 DNS)\u300D
\u6A21\u677F URL: ${origin}${config.path}</code></pre>
        </div>
      </div>

      <div id="tab-cli" class="tab-content" style="display:none;">
        <div class="code-block">
          <button class="copy-btn" onclick="copyElement('code-cli')">\u590D\u5236\u4EE3\u7801</button>
          <pre id="code-cli"><code># 1. \u5FEB\u901F\u5065\u5EB7\u68C0\u67E5
curl -s "${origin}/healthz"

# 2. \u901A\u8FC7 JSON API \u5FEB\u901F\u89E3\u6790
curl -s "${origin}${config.jsonPath}?name=linux.do&type=A"

# 3. \u4F7F\u7528 kdig (knot-dnsutils) \u6D4B\u8BD5\u6807\u51C6 DoH
kdig -d @${new URL(origin).hostname} +https=${config.path} linux.do A</code></pre>
        </div>
      </div>
    </div>

    <!-- \u6838\u5FC3\u4F18\u52BF -->
    <div class="card">
      <div class="card-title">
        <span>\u{1F4A1}</span>
        <span>\u4E3A\u4EC0\u4E48\u9009\u62E9 cf-doh\uFF1F</span>
      </div>
      <div class="feature-list">
        <div class="feature-item">
          <div class="feature-icon">\u{1F3CE}\uFE0F</div>
          <div>
            <strong>\u5168\u5E76\u53D1\u7ADE\u4EF7 (Zero Penalty)</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u56FD\u5185\u7EC4\u4E0E\u5168\u7403\u7EC4\u5185\u6240\u6709\u4E0A\u6E38\u540C\u65F6\u5E76\u53D1\u8BF7\u6C42\uFF0C\u5EF6\u8FDF\u53D6\u6700\u5C0F\u503C\u3002\u5F7B\u5E95\u7EC8\u7ED3\u4F20\u7EDF\u65B9\u6848\u4E32\u884C\u8D85\u65F6\u5361\u987F\u3002
            </p>
          </div>
        </div>
        <div class="feature-item">
          <div class="feature-icon">\u{1F3AF}</div>
          <div>
            <strong>\u771F\u5B9E\u53EF\u4FE1 ECS \u6CE8\u5165</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u4E25\u683C\u4FE1\u4EFB Cloudflare \u8FB9\u7F18\u63D0\u53D6\u7684 client IP\uFF08/24 \u6216 /56\uFF09\uFF0C\u8FC7\u6EE4\u53EF\u4F2A\u9020\u7684 XFF\uFF0C\u8BA9 CDN \u8C03\u5EA6\u7CBE\u51C6\u9501\u5B9A\u6700\u8FD1\u8282\u70B9\u3002
            </p>
          </div>
        </div>
        <div class="feature-item">
          <div class="feature-icon">\u{1F6E1}\uFE0F</div>
          <div>
            <strong>\u89C4\u5219\u9632\u6BD2\u5316\u4E0E\u786C\u9694\u79BB</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u5185\u7F6E linux.do / github.com \u7EDD\u5BF9\u76F4\u8FDE\u786C\u7F16\u7801\u9632\u62A4\uFF0C\u5916\u90E8\u89C4\u5219\u5931\u6548\u6216\u683C\u5F0F\u5F02\u5E38\u5E73\u6ED1\u56DE\u9000\uFF0C\u4FDD\u969C\u670D\u52A1\u6C38\u8FDC\u53EF\u7528\u3002
            </p>
          </div>
        </div>
        <div class="feature-item">
          <div class="feature-icon">\u{1F4E6}</div>
          <div>
            <strong>\u96F6\u8FD0\u884C\u65F6\u4F9D\u8D56 & \u5F00\u7BB1\u5373\u7528</strong>
            <p style="font-size:0.85rem; color:var(--text-muted);">
              \u7EAF\u539F\u751F JavaScript ESM \u5B9E\u73B0\uFF0C\u65E0\u8BBA\u514D\u8D39\u7248\u8FD8\u662F\u4F01\u4E1A\u7248 Cloudflare Workers\uFF0C\u5355\u6587\u4EF6\u6216 Wrangler \u5747\u53EF\u79D2\u7EA7\u542F\u52A8\u3002
            </p>
          </div>
        </div>
      </div>
    </div>

    <footer class="footer">
      <p>\u5F00\u6E90\u9879\u76EE\uFF1A<a href="https://github.com/dengyie/cf-doh" target="_blank" rel="noopener">github.com/dengyie/cf-doh</a> \u2022 \u57FA\u4E8E MIT License \u5F00\u6E90</p>
      <p style="margin-top: 6px; font-size: 0.8rem;">Powered by Cloudflare Workers & Serverless Edge Computing</p>
    </footer>
  </div>

  <script>
    function escapeHtml(str) {
      if (str === null || str === undefined) return '';
      return String(str).replace(/[&<>"']/g, function(m) {
        switch (m) {
          case '&': return '&amp;';
          case '<': return '&lt;';
          case '>': return '&gt;';
          case '"': return '&quot;';
          case "'": return '&#39;';
          default: return m;
        }
      });
    }

    function setQuery(domain) {
      document.getElementById('domainInput').value = domain;
      runQuery();
    }

    async function runQuery() {
      const domain = document.getElementById('domainInput').value.trim();
      const type = document.getElementById('typeSelect').value;
      const box = document.getElementById('resultBox');
      const btn = document.getElementById('queryBtn');
      if (!domain) return;

      btn.disabled = true;
      btn.innerText = '\u67E5\u8BE2\u4E2D...';
      box.textContent = '\u6B63\u5728\u53D1\u8D77 DoH \u67E5\u8BE2...';

      const start = performance.now();
      try {
        const resp = await fetch('${config.jsonPath}?name=' + encodeURIComponent(domain) + '&type=' + encodeURIComponent(type));
        const data = await resp.json();
        const duration = Math.round(performance.now() - start);

        let html = '';
        html += '\u23F1\uFE0F \u89E3\u6790\u8017\u65F6: ' + duration + ' ms\\n';
        const statusNum = Number(data.Status);
        html += '\u{1F3AF} \u54CD\u5E94\u72B6\u6001: ' + (statusNum === 0 ? '<span style="color:#10b981">NOERROR (\u6210\u529F)</span>' : '<span style="color:#ef4444">Status ' + statusNum + '</span>') + '\\n';
        html += '\u{1F512} DNSSEC: ' + (data.AD ? '\u5DF2\u9A8C\u8BC1 (AD=1)' : '\u672A\u5F00\u542F/\u666E\u901A (AD=0)') + '\\n\\n';

        if (Array.isArray(data.Answer) && data.Answer.length > 0) {
          html += '\u{1F4CB} \u7B54\u6848\u8BB0\u5F55 (Answers):\\n';
          data.Answer.forEach(ans => {
            const safeName = escapeHtml(ans.name);
            const safeType = escapeHtml(ans.type);
            const safeData = escapeHtml(ans.data);
            const safeTtl = Number(ans.TTL) || 0;
            html += '  \u2022 ' + safeName + '  ' + safeType + '  ' + safeData + ' (TTL: ' + safeTtl + 's)\\n';
          });
        } else {
          html += '\u26A0\uFE0F \u672A\u67E5\u8BE2\u5230\u5BF9\u5E94\u8BB0\u5F55\u3002\\n';
        }

        if (Array.isArray(data.Authority) && data.Authority.length > 0) {
          html += '\\n\u{1F3DB}\uFE0F \u6743\u5A01\u8BB0\u5F55 (Authority):\\n';
          data.Authority.forEach(auth => {
            const safeName = escapeHtml(auth.name);
            const safeType = escapeHtml(auth.type);
            const safeData = escapeHtml(auth.data);
            html += '  \u2022 ' + safeName + '  ' + safeType + '  ' + safeData + '\\n';
          });
        }

        box.innerHTML = html;
        loadStats();
      } catch (err) {
        box.innerHTML = '<span style="color:#ef4444">\u67E5\u8BE2\u5931\u8D25: ' + escapeHtml(err.message) + '</span>';
      } finally {
        btn.disabled = false;
        btn.innerText = '\u67E5\u8BE2';
      }
    }

    let currentScope = 'local';

    function setStatsScope(scope) {
      currentScope = scope;
      const localBtn = document.getElementById('scopeLocalBtn');
      const globalBtn = document.getElementById('scopeGlobalBtn');
      if (scope === 'global') {
        localBtn.classList.remove('active');
        globalBtn.classList.add('active');
      } else {
        globalBtn.classList.remove('active');
        localBtn.classList.add('active');
      }
      loadStats(scope);
    }

    async function loadStats(scope = currentScope) {
      try {
        const url = scope === 'global' ? '/api/stats?scope=global' : '/api/stats';
        const resp = await fetch(url);
        if (!resp.ok) return;
        const rawData = await resp.json();
        const isGlobal = scope === 'global';
        const noticeEl = document.getElementById('scopeNotice');

        let data = rawData;
        if (isGlobal) {
          if (rawData.available) {
            noticeEl.innerHTML = '\u{1F310} <b>\u5168\u7403\u591A\u5730\u57DF\u805A\u5408\u6570\u636E (Cloudflare Analytics Engine)</b> \u2022 \u6700\u8FD1 24 \u5C0F\u65F6\u8DE8\u6240\u6709 PoP \u8FB9\u7F18\u8282\u70B9\u603B\u8BA1';
            noticeEl.style.borderLeftColor = '#10b981';
            document.getElementById('analyticsStatus').innerText = '\u5168\u5C40 SQL \u67E5\u8BE2\u5DF2\u6FC0\u6D3B';
            document.getElementById('analyticsStatus').style.color = '#10b981';
            document.getElementById('uptimeWrap').style.display = 'none';
          } else {
            noticeEl.innerHTML = '\u26A0\uFE0F <b>\u5168\u7403\u805A\u5408\u672A\u5F00\u542F\u6216\u672A\u914D\u7F6E\u8BFB\u53D6\u51ED\u636E</b>\uFF1A' + escapeHtml(rawData.message || '\u56DE\u9000\u5C55\u793A\u5F53\u524D\u672C\u5730 PoP \u6570\u636E') + '\u3002\u53EF\u81F3 Cloudflare \u63A7\u5236\u53F0\u6FC0\u6D3B Analytics Engine\u3002';
            noticeEl.style.borderLeftColor = '#f59e0b';
            document.getElementById('analyticsStatus').innerText = '\u672A\u6FC0\u6D3B\u5168\u5C40\u8BFB\u53D6 (\u5C55\u793A\u672C\u5730)';
            document.getElementById('analyticsStatus').style.color = '#f59e0b';
            document.getElementById('uptimeWrap').style.display = 'inline';
            if (rawData.fallback) data = rawData.fallback;
          }
        } else {
          noticeEl.innerHTML = '\u{1F4CD} \u7EDF\u8BA1\u8303\u56F4\uFF1A\u5F53\u524D Cloudflare \u8FB9\u7F18\u8282\u70B9\u5185\u5B58\u5B9E\u65F6\u91C7\u6837 (\u5355\u5B9E\u4F8B)';
          noticeEl.style.borderLeftColor = 'var(--primary)';
          document.getElementById('analyticsStatus').innerText = '\u5DF2\u63A5\u5165 (Worker \u70B9\u4F4D\u5199\u5165)';
          document.getElementById('analyticsStatus').style.color = 'var(--primary)';
          document.getElementById('uptimeWrap').style.display = 'inline';
        }

        // Domestic
        const dom = (data.upstreams && data.upstreams.domestic) ? data.upstreams.domestic : { upstreams: {}, totalWins: 0 };
        const ali = dom.upstreams['dns.alidns.com'] || { wins: 0, winRate: '0.0%' };
        const pod = dom.upstreams['doh.pub'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('domesticTotalWins').innerText = dom.totalWins + ' \u6B21\u80DC\u51FA';
        document.getElementById('winAlidns').innerText = ali.wins + ' (' + ali.winRate + ')';
        document.getElementById('winDohpub').innerText = pod.wins + ' (' + pod.winRate + ')';
        const domTotal = ali.wins + pod.wins;
        const aliPct = domTotal > 0 ? (ali.wins / domTotal) * 100 : 50;
        document.getElementById('barAlidns').style.width = aliPct + '%';
        document.getElementById('barDohpub').style.width = (100 - aliPct) + '%';

        if (data.latency && data.latency.domestic) {
          document.getElementById('p50Domestic').innerText = (data.latency.domestic.p50Ms || 0) + ' ms';
          document.getElementById('p95Domestic').innerText = (data.latency.domestic.p95Ms || 0) + ' ms';
          document.getElementById('avgDomestic').innerText = (data.latency.domestic.avgMs || 0) + ' ms';
        }

        // Global
        const glob = (data.upstreams && data.upstreams.global) ? data.upstreams.global : { upstreams: {}, totalWins: 0 };
        const ggl = glob.upstreams['dns.google'] || { wins: 0, winRate: '0.0%' };
        const cf = glob.upstreams['cloudflare-dns.com'] || { wins: 0, winRate: '0.0%' };
        document.getElementById('globalTotalWins').innerText = glob.totalWins + ' \u6B21\u80DC\u51FA';
        document.getElementById('winGoogle').innerText = ggl.wins + ' (' + ggl.winRate + ')';
        document.getElementById('winCf').innerText = cf.wins + ' (' + cf.winRate + ')';
        const globTotal = ggl.wins + cf.wins;
        const gglPct = globTotal > 0 ? (ggl.wins / globTotal) * 100 : 50;
        document.getElementById('barGoogle').style.width = gglPct + '%';
        document.getElementById('barCf').style.width = (100 - gglPct) + '%';

        if (data.latency && data.latency.global) {
          document.getElementById('p50Global').innerText = (data.latency.global.p50Ms || 0) + ' ms';
          document.getElementById('p95Global').innerText = (data.latency.global.p95Ms || 0) + ' ms';
          document.getElementById('avgGlobal').innerText = (data.latency.global.avgMs || 0) + ' ms';
        }

        if (data.cache) {
          document.getElementById('cacheHitRate').innerText = data.cache.hitRate || '0.0%';
        }
        if (typeof data.totalRequests !== 'undefined') {
          document.getElementById('totalRequests').innerText = data.totalRequests;
        }
        if (typeof data.uptimeSec !== 'undefined') {
          document.getElementById('nodeUptime').innerText = data.uptimeSec + 's';
        }
      } catch (err) {
        console.warn('Failed to load stats:', err);
      }
    }

    window.addEventListener('DOMContentLoaded', () => {
      loadStats();
    });

    function switchTab(name) {
      const contents = document.querySelectorAll('.tab-content');
      contents.forEach(c => c.style.display = 'none');
      const btns = document.querySelectorAll('.tab-btn');
      btns.forEach(b => b.classList.remove('active'));

      const target = document.getElementById('tab-' + name);
      if (target) target.style.display = 'block';
      event.target.classList.add('active');
    }

    function copyText(txt) {
      navigator.clipboard.writeText(txt).then(() => {
        alert('\u5DF2\u590D\u5236\u5230\u526A\u8D34\u677F: ' + txt);
      });
    }

    function copyElement(id) {
      const el = document.getElementById(id);
      if (el) {
        copyText(el.innerText);
      }
    }
  <\/script>
</body>
</html>`;
}

// src/worker.js
var QTYPE_STR = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  HTTPS: 65
};
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
      ...extraHeaders || {}
    }
  });
}
function isValidQname(name) {
  if (typeof name !== "string" || name.length === 0 || name.length > 253) return false;
  if (name.endsWith(".")) return false;
  const labels = name.split(".");
  if (labels.some((l) => l.length === 0 || l.length > 63)) return false;
  return /^[a-zA-Z0-9_.-]+$/.test(name) && !name.includes("..");
}
function buildWireQuery(name, type) {
  const qname = name.toLowerCase();
  const labels = qname.split(".").filter((l) => l.length > 0).map((l) => new TextEncoder().encode(l));
  const qnameLen = labels.reduce((n, b) => n + 1 + b.length, 0) + 1;
  const out = new Uint8Array(12 + qnameLen + 4);
  out[2] = 1;
  out[5] = 1;
  let o = 12;
  for (const bytes of labels) {
    out[o] = bytes.length;
    out.set(bytes, o + 1);
    o += 1 + bytes.length;
  }
  out[o] = 0;
  o += 1;
  out[o] = type >> 8 & 255;
  out[o + 1] = type & 255;
  out[o + 2] = 0;
  out[o + 3] = 1;
  return out;
}
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
function appendEcsOpt(query, subnet) {
  const rdata = encodeEcsRdata(subnet.family, subnet.network, subnet.prefixLength);
  const option = wrapEcsOption(rdata);
  const opt = new Uint8Array(1 + 2 + 2 + 4 + 2 + option.length);
  opt[0] = 0;
  opt[1] = 0;
  opt[2] = 41;
  opt[3] = 4;
  opt[4] = 208;
  opt[5] = 0;
  opt[6] = 0;
  opt[7] = 0;
  opt[8] = 0;
  opt[9] = option.length >> 8 & 255;
  opt[10] = option.length & 255;
  opt.set(option, 11);
  const out = new Uint8Array(query.length + opt.length);
  out.set(query, 0);
  out.set(opt, query.length);
  const oldAr = (query[10] << 8 | query[11]) & 65535;
  const newAr = oldAr + 1;
  out[10] = newAr >> 8 & 255;
  out[11] = newAr & 255;
  return out;
}
async function handleRequest(request, env) {
  const config = readConfig(env);
  metrics.inc("requests");
  const url = new URL(request.url);
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept, X-DoH-Token, Authorization, X-Rules-Secret",
        "Access-Control-Max-Age": "86400"
      }
    });
  }
  if (url.pathname === "/healthz" || url.pathname === "/metrics") {
    return metrics.healthResponse(config);
  }
  if (url.pathname === "/api/stats" || url.pathname === "/stats" || url.pathname === "/api/stats/global" || url.pathname === "/stats/global") {
    const scope = url.searchParams.get("scope") || (url.pathname.endsWith("/global") ? "global" : "local");
    if (scope === "global") {
      const interval = url.searchParams.get("interval") || "1 DAY";
      return metrics.globalStatsResponse(config, env, { interval });
    }
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
          "Cache-Control": "no-store"
        }
      });
    }
    return new Response(
      `cf-doh \u2014 Self-hosted DNS-over-HTTPS Resolver

Endpoints:
  \u2022 RFC 8484 DoH Query : ${url.origin}${config.path}
  \u2022 DoH JSON API       : ${url.origin}${config.jsonPath}?name=example.com&type=A
  \u2022 Health Check       : ${url.origin}/healthz
  \u2022 Web Console        : ${url.origin}/

GitHub: https://github.com/dengyie/cf-doh
`,
      { headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } }
    );
  }
  if (config.token) {
    const submitted = url.searchParams.get("token") || request.headers.get("x-doh-token") || "";
    if (submitted !== config.token) return new Response("Forbidden", { status: 403 });
  }
  if (url.pathname === config.jsonPath) {
    return handleJsonQuery(request, url, env, config);
  }
  const read = await readDnsQuery(request, config);
  if (read.error) {
    metrics.inc("formerr");
    const code = read.error === "not_found" ? 404 : read.error === "method_not_allowed" ? 405 : read.error === "too_large" ? 413 : read.error === "unsupported_media" ? 415 : 400;
    return new Response(code === 400 ? "Bad Request" : "", { status: code });
  }
  metrics.inc(request.method === "GET" ? "get" : "post");
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
async function resolveAndRelay(wireQuery, parsed, request, env, config) {
  const qname = parsed.question.name;
  let rules = null;
  try {
    rules = await ensureRules(env);
  } catch {
    rules = null;
  }
  const domestic = isDomestic(qname, rules);
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
    }
  }
  const subnet = subnetForEcs(
    request.headers.get("cf-connecting-ip"),
    config.ecsV4Prefix,
    config.ecsV6Prefix
  );
  const ecsKey = subnet ? `${subnet.family}:${subnet.network.join(".")}` : "none";
  const result = await resolveWithCache(parsed, wireQuery, subnet, ecsKey, domestic, config, env);
  if (!result) return { ok: false };
  let answer = result.answer;
  if (config.dnssec) {
    answer = answer.slice();
    applyRelayedDnssec(answer, clientRequestedDnssec(parsed));
  }
  return { ok: true, answer };
}
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
  let minTtl = 0;
  try {
    minTtl = answerTtlSeconds(outcome.answer, parsed);
  } catch {
    minTtl = 0;
  }
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
      headers: { "Content-Type": "application/json" }
    });
  }
  const secret = config.rulesSyncSecret || env.RULES_SYNC_SECRET;
  if (!secret) {
    return new Response(
      JSON.stringify({ error: "RULES_SYNC_SECRET is not configured on server" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json" }
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
      headers: { "Content-Type": "application/json" }
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
        headers: { "Content-Type": "application/json" }
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
          updatedAt: (/* @__PURE__ */ new Date()).toISOString()
        }),
        {
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*"
          }
        }
      );
    } catch (err) {
      return new Response(
        JSON.stringify({ error: err.message || "Failed to adopt rules" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  } else {
    const updated = await refreshRules(env);
    return new Response(
      JSON.stringify({
        ok: updated,
        mode: "pull",
        updatedAt: (/* @__PURE__ */ new Date()).toISOString()
      }),
      {
        status: updated ? 200 : 502,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        }
      }
    );
  }
}
var dnsCache = createCache();
async function resolveWithCache(parsed, query, subnet, ecsKey, domestic, config, env) {
  const qname = parsed.question.name;
  const qtype = parsed.question.qtype;
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
        cacheStatus: "hit"
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
    }
  });
  if (!result) return null;
  metrics.recordUpstreamRace(domestic ? "domestic" : "global", result.from, result.durationMs);
  metrics.recordAnalyticsPoint(env, {
    group: domestic ? "domestic" : "global",
    winnerUrl: result.from,
    durationMs: result.durationMs,
    qtype,
    rcode: "NOERROR",
    cacheStatus: "miss"
  });
  if (config.cacheTtlSeconds > 0) {
    let ttl = answerTtlSeconds(result.answer, parsed);
    if (ttl <= 0) ttl = config.cacheTtlSeconds;
    dnsCache.set(qname, qtype, ecsKey, result.answer, Math.min(ttl, config.cacheTtlSeconds));
  }
  return result;
}
var worker_default = {
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
  }
};
export {
  DNS_CONTENT_TYPE,
  worker_default as default,
  handleRequest,
  isBlocked,
  parseDnsMessage,
  readConfig,
  resetBlock,
  resetRules
};
