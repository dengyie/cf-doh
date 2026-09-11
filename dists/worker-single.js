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
  rulesRefreshMin: 15,
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
    rulesCacheMin: parseUint(env.RULES_CACHE_MIN, DEFAULT.rulesMin, 1, 1440),
    token: asSingle(env.DOH_TOKEN, ""),
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
var live = null;
var coldInflight = null;
function parseRuleText(text) {
  const plain = [];
  const full = /* @__PURE__ */ new Set();
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
  plain.sort();
  return { plain, full, regexp, version: text.length };
}
function matchesRules(qname, rules) {
  const q = qname.toLowerCase();
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
var BUILTIN = new Set(BUILTIN_OVERRIDE.map((d) => d.toLowerCase()));
function matchesBuiltin(q) {
  if (BUILTIN.has(q)) return true;
  for (const d of BUILTIN) {
    if (q.endsWith(`.${d}`)) return true;
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
    return false;
  }
}
function resetRules() {
  live = null;
  coldInflight = null;
}

// src/filter.js
var DEC2 = new TextDecoder("latin1");
var ENC2 = new TextEncoder();
var KV_KEY2 = "block:data";
var live2 = null;
var coldInflight2 = null;
function parseRuleText2(text) {
  const plain = [];
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
      plain.push(line.toLowerCase());
    }
  }
  plain.sort();
  return { plain, full, regexp, version: text.length };
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
function isBlocked(qname, rule) {
  return matches(qname, rule);
}
async function ensureBlock(env, fetcher = fetch) {
  if (live2) return live2;
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
  if (!url) return null;
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
function rdataString(type, rd, off, len, nameReader) {
  switch (type) {
    case 1:
      return rd.length >= 4 ? `${rd[0]}.${rd[1]}.${rd[2]}.${rd[3]}` : "";
    case 28: {
      if (rd.length < 16) return "";
      const h = [];
      for (let i = 0; i < 8; i++) h.push((rd[i * 2] << 8 | rd[i * 2 + 1]).toString(16));
      return h.join(":");
    }
    case 5:
    case 2:
    case 12: {
      const r = readName(rd, 0);
      return r.name;
    }
    case 16:
      return rd.length ? JSON.stringify(DECODE.decode(rd)) : "";
    case 15: {
      if (rd.length < 2) return "";
      const pref = readU162(rd, 0);
      const r = readName(rd, 2);
      return `${pref} ${r.name}`;
    }
    case 6: {
      if (rd.length < 40) return "";
      const mname = readName(rd, 0);
      const rname = readName(rd, mname.end);
      const ser = toU32(rd, rname.end);
      const refresh = toU32(rd, rname.end + 4);
      const retry2 = toU32(rd, rname.end + 8);
      const expire = toU32(rd, rname.end + 12);
      const mini = toU32(rd, rname.end + 16);
      return `${mname.name} ${rname.name} ${ser} ${refresh} ${retry2} ${expire} ${mini}`;
    }
    default:
      return Array.from(rd).slice(0, Math.min(rd.length, 64)).map((x) => x.toString(16).padStart(2, "0")).join("");
  }
}
function toJsonResponse(wire, qname, qtypeName, clientAd) {
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
      const { name, end } = readName(wire, p);
      p = end;
      if (p + 10 > wire.length) break;
      const t = readU162(wire, p);
      const cl = readU162(wire, p + 2);
      const ttl = toU32(wire, p + 4);
      const len = readU162(wire, p + 8);
      p += 10;
      if (p + len > wire.length) break;
      const rd2 = Array.from(wire.subarray(p, p + len));
      p += len;
      const typeName = TYPE_STR[t] || `TYPE${t}`;
      arr.push({
        name,
        type: typeName,
        ...t === 1 || t === 28 ? { TTL: ttl, data: rdataString(t, rd2, p, len, readName) } : {}
      });
      if (t !== 1 && t !== 28) {
        arr[arr.length - 1].TTL = ttl;
        arr[arr.length - 1].data = rdataString(t, rd2, p, len, readName);
      }
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
async function queryUpstream(url, query, { timeoutMs, maxResponseBytes }) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
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
    if (!resp.ok) return { ok: false, reason: `http_${resp.status}` };
    const ct = (resp.headers.get("content-type") || "").split(";", 1)[0].trim().toLowerCase();
    if (ct !== DNS_CONTENT_TYPE) return { ok: false, reason: "bad_content_type" };
    const buf = await resp.arrayBuffer();
    if (buf.byteLength < 12 || buf.byteLength > maxResponseBytes) {
      return { ok: false, reason: "bad_size" };
    }
    return { ok: true, body: new Uint8Array(buf) };
  } catch {
    return { ok: false, reason: controller.signal.aborted ? "timeout" : "network" };
  } finally {
    clearTimeout(timer);
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
  const settle = (r) => {
    if (on) on({ kind: classify(r), url: r.url });
  };
  const pending = urls.map(async (url) => {
    const res = await queryUpstream(url, query, { timeoutMs, maxResponseBytes });
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
                resolve({ answer: r.body, from: r.url });
                return;
              }
            } catch {
            }
          }
          if (settled === pending.length) resolve(null);
        },
        (err) => {
          settled += 1;
          settle({ ok: false, reason: "error", url: urls[i] });
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
  rules_fetch_fail: 0
};
var startedAt = Date.now();
function inc(name, n = 1) {
  COUNTERS[name] = (COUNTERS[name] || 0) + n;
}
function snapshot() {
  return { ...COUNTERS };
}
function healthResponse(config) {
  const body = JSON.stringify(
    {
      status: "ok",
      service: "cf-doh",
      version: "1.0.0",
      uptimeSec: Math.round((Date.now() - startedAt) / 1e3),
      counters: snapshot(),
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
var metrics = { inc, snapshot, healthResponse };

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
      ...extraHeaders || {}
    }
  });
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
  if (url.pathname === "/healthz" || url.pathname === "/metrics") {
    return metrics.healthResponse(config);
  }
  if (url.pathname === "/" && request.method === "GET") {
    return new Response(
      `Cloudflare Workers DoH resolver. Query path: ${url.origin}${config.path} (RFC 8484).`,
      { headers: { "Content-Type": "text/plain", "Cache-Control": "no-store" } }
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
  const result = await resolveWithCache(parsed, wireQuery, subnet, ecsKey, domestic, config);
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
  if (!qname || !/^[a-zA-Z0-9_.-]+$/.test(qname)) {
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
  const clientAd = false;
  const json = toJsonResponse(outcome.answer, qname, typeName, clientAd);
  const resp = jsonResponse(json, minTtl);
  if (outcome.meta) {
    for (const [k, v] of Object.entries(outcome.meta)) resp.headers.set(k, v);
  }
  return resp;
}
var dnsCache = createCache();
async function resolveWithCache(parsed, query, subnet, ecsKey, domestic, config) {
  const qname = parsed.question.name;
  const qtype = parsed.question.qtype;
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
    }
  });
  if (!result) return null;
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
