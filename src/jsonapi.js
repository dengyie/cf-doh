/**
 * DoH JSON API (Google `?name=..&type=..` style) for the resolver.
 *
 * Accepts GET /json?name=example.com&type=A and returns RFC-8427-ish JSON:
 *   { Status, TC, RD, RA, AD, CD, Question:[{name,type}], Answer:[{name,type,TTL,data}], Authority:[...] }
 *
 * The DoH wire response is produced by the normal resolution path and handed to
 * `toJsonResponse` here. Status maps RC→code (0=NOERROR..), AD comes from the
 * DNS flags (only when client requested DNSSEC is decided by caller).
 *
 * We parse just enough of the wire answer RRs to build JSON Answer/Authority.
 */

const DECODE = new TextDecoder("latin1");

const TYPE_STR = {
  1: "A",
  2: "NS",
  5: "CNAME",
  6: "SOA",
  12: "PTR",
  15: "MX",
  16: "TXT",
  28: "AAAA",
  33: "SRV",
  65: "HTTPS",
};

function readU16(b, o) {
  return (b[o] << 8) | b[o + 1];
}
function toU32(b, o) {
  return ((b[o] & 0xff) << 24) | ((b[o + 1] & 0xff) << 16) | ((b[o + 2] & 0xff) << 8) | (b[o + 3] & 0xff);
}
function readName(b, o) {
  // support compression pointers (<=2 jumps)
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
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) {
        jumpTo = p + 2;
        jumped = true;
      }
      p = ((len & 0x3f) << 8) | b[p + 1];
      continue;
    }
    if (out) out += ".";
    for (let i = 1; i <= len; i++) out += String.fromCharCode(b[p + i] & 0xff);
    p += len + 1;
  }
  return { name: out, end: jumped ? jumpTo : p };
}

/** Render answer/authority record RDATA as a string (common types). */
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
        h.push(((wire[idx] << 8) | wire[idx + 1]).toString(16));
      }
      return h.join(":");
    }
    case 5:
    case 2:
    case 12: {
      // CNAME, NS, PTR: domain name (RFC 1035 §4.1.4 allows compression relative to wire)
      const r = readName(wire, off);
      return r.name;
    }
    case 16: {
      // TXT: one or more <character-string> = 1 byte length + string
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
      // MX: 2-byte preference + exchange (domain name)
      if (len < 2 || off + 2 > wire.length) return "";
      const pref = readU16(wire, off);
      const r = readName(wire, off + 2);
      return `${pref} ${r.name}`;
    }
    case 6: {
      // SOA RDATA: MNAME RNAME SERIAL REFRESH RETRY EXPIRE MINIMUM
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
      return Array.from(wire.subarray(off, Math.min(off + len, off + 64)))
        .map((x) => x.toString(16).padStart(2, "0"))
        .join("");
  }
}

/**
 * Convert a DoH wire response to JSON object per the Google-style schema.
 * `qname`/`qtype` are from the original request (client-facing, preserves case).
 * The AD field is derived from the wire answer's flag bits — the caller is
 * responsible for masking AD (see worker's applyRelayedDnssec) so it only ever
 * reflects data the client actually requested.
 */
export function toJsonResponse(wire, qname, qtypeName) {
  if (!wire || wire.length < 12) {
    return { Status: 2, RA: false, Question: [{ name: qname, type: qtypeName }] };
  }
  const flags = readU16(wire, 2);
  const qd = readU16(wire, 4);
  const an = readU16(wire, 6);
  const ns = readU16(wire, 8);
  const ar = readU16(wire, 10);
  const rc = flags & 0x000f;
  const rd = !!(flags & 0x0100);
  const ra = !!(flags & 0x0080);
  const ad = !!(flags & 0x0020);
  const tc = !!(flags & 0x0200);
  const cd = !!(flags & 0x0010);

  // Question section(s)
  const questions = [];
  let p = 12;
  for (let i = 0; i < qd; i++) {
    const { name, end } = readName(wire, p);
    const t = readU16(wire, end);
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
      const t = readU16(wire, p);
      const cl = readU16(wire, p + 2);
      const ttl = toU32(wire, p + 4);
      const len = readU16(wire, p + 8);
      p += 10;
      if (p + len > wire.length) break;
      const rdataOffset = p;
      p += len;
      const typeName = TYPE_STR[t] || `TYPE${t}`;
      arr.push({
        name,
        type: typeName,
        TTL: ttl,
        data: rdataString(t, wire, rdataOffset, len),
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
    Additional: additional,
  };
}

/** Convert a JSON object to a Response with cache-control honoring TTLs. */
export function jsonResponse(obj, minTtlSeconds = 0) {
  const cc = minTtlSeconds > 0 ? `max-age=${minTtlSeconds}` : "no-store";
  return new Response(JSON.stringify(obj), {
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": cc,
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
    },
  });
}