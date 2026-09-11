/**
 * Minimal, dependency-free DNS wire-format helpers for the Cloudflare Worker DoH resolver.
 *
 * We parse just enough of a DNS message to:
 *  - validate it looks like a real query (header + question),
 *  - locate the question name (qname) for rule matching,
 *  - find / manipulate EDNS(0) OPT (to inject ECS / Client Subnet),
 *  - build a well-formed error response (FORMERR `1` / SERVFAIL `2`).
 *
 * All offsets are absolute byte offsets into the message. We never fully
 * decode records we do not need; unknown/irrelevant sections are passed
 * through byte-for-byte.
 */

export const DNS_CONTENT_TYPE = "application/dns-message";
export const OPCODE_QUERY = 0;
export const RCODE_FORMERR = 1;
export const RCODE_SERVFAIL = 2;

// DNS header (12 bytes) layout indexes
const HDR_ID = 0; // 2 bytes
const HDR_FLAGS = 2; // 2 bytes
const HDR_QDCOUNT = 4; // count of questions (3.2.1. / 4.2.1.)
const HDR_ARCOUNT = 10; // count of additional RRs (must be last for us)
const HEADER_LEN = 12;

export class DnsFormatError extends Error {
  constructor(message) {
    super(message);
    this.name = "DnsFormatError";
  }
}

function readU16(buf, off) {
  return (buf[off] << 8) | buf[off + 1];
}

function writeU16(buf, off, value) {
  buf[off] = (value >> 8) & 0xff;
  buf[off + 1] = value & 0xff;
}

/**
 * Decode a domain name starting at `start`. Returns { name, end } where `end`
 * is the offset just past the name (including any compression pointer). We stop
 * at a compression pointer so safe cloning/slicing can reuse the original.
 */
function decodeName(buf, start) {
  let off = start;
  let name = "";
  let jumps = 0;
  while (true) {
    const len = buf[off];
    if (len === undefined) throw new DnsFormatError("name_truncated");
    if (len === 0) {
      off += 1;
      return { name, end: off };
    }
    if ((len & 0xc0) === 0xc0) {
      // compression pointer: 2 bytes total
      if (off + 1 >= buf.length) throw new DnsFormatError("name_pointer_truncated");
      off += 2;
      // We do NOT follow the pointer for name extraction; we only need the
      // qname which for real client queries is always literal (no pointers).
      // A pointer in the question is unusual but legal; treat as end-of-name.
      if (jumps++ > 4) throw new DnsFormatError("name_too_many_ptrs");
      return { name, end: off };
    }
    if ((len & 0xc0) !== 0) throw new DnsFormatError("name_bad_label");
    if (off + 1 + len > buf.length) throw new DnsFormatError("name_label_truncated");
    // DNS labels are byte sequences; treat as ASCII/Latin-1 and lower-case for
    // case-insensitive matching (stub resolvers send ASCII qnames).
    let label = "";
    for (let i = 0; i < len; i += 1) {
      const c = buf[off + 1 + i] & 0xff;
      label += c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : String.fromCharCode(c);
    }
    if (name !== "") name += ".";
    name += label;
    off += 1 + len;
  }
}

/**
 * Parse a message enough to extract the question name + locate the OPT record.
 * Returns:
 *   { id, flags, question: { name, qtype, qclass, nameOffset, nameEnd, questionStart, questionEnd },
 *     opt: { additionalIndex, rdataStart, rdataEnd, rdataLenOff } | null,
 *     additionalCount }
 */
export function parseDnsMessage(buf) {
  if (buf.length < HEADER_LEN) throw new DnsFormatError("too_short");
  const id = readU16(buf, HDR_ID);
  const flags = readU16(buf, HDR_FLAGS);
  const qdcount = readU16(buf, HDR_QDCOUNT);
  const arcount = readU16(buf, HDR_ARCOUNT);

  if (qdcount !== 1) {
    // We only serve single-question queries (typical for every stub resolver).
    throw new DnsFormatError("qdcount_not_one");
  }
  // Standard checks: must be a QUERY (opcode 0); disallow responses as input.
  if ((flags & 0x7800) !== (OPCODE_QUERY << 11)) {
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
    name, // lower-cased qname, e.g. "github.com"
    qtype,
    qclass,
    nameOffset: nameStart,
    nameEnd: end,
    questionStart,
    questionEnd,
  };

  // Re-scan the question name for the rule matcher (we stored it above).
  // Find OPT in the additional section: the LAST additional RR, type 41.
  const ancount = readU16(buf, 6);
  const nscount = readU16(buf, 8);
  // Advance over answer / authority / additional RRs of length we must skip.
  // We only need the final answer offset: walk roots of each RR by decoding
  // names (with compression) then fixed 10 bytes, then rdata of length.
  const skipRRs = (start, count) => {
    let cursor = start;
    for (let i = 0; i < count; i += 1) {
      const { end: nEnd } = decodeName(buf, cursor);
      cursor = nEnd;
      if (cursor + 10 > buf.length) throw new DnsFormatError("rr_truncated");
      const rdlength = readU16(buf, cursor + 8);
      cursor += 10 + rdlength;
      if (cursor > buf.length) throw new DnsFormatError("rr_rdata_truncated");
    }
    return cursor;
  };

  let cursor = questionEnd;
  cursor = skipRRs(cursor, ancount);
  cursor = skipRRs(cursor, nscount);

  // additional: only the LAST RR, if it is an OPT(41), is the EDNS record.
  // Per RFC there is at most one OPT and it must be the last additional record.
  let opt = null;
  if (arcount >= 1) {
    // Find the offset of the LAST additional record so we can read its type.
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
        // OPT owner name is root (single zero byte); our decodeName handles it.
        opt = {
          additionalIndex: arcount - 1, // 0-based index of last
          rdataStart,
          rdataEnd,
          rdataLenOff,
        };
      }
    }
  }

  return { id, flags, question, opt, additionalCount: arcount };
}

/**
 * Build a minimal DNS error response for the original query.
 * `rcode` is 1 (FORMERR) or 2 (SERVFAIL).
 */
export function buildErrorResponse(fromBuf, rcode, question) {
  // Header is always 12 bytes; we append the echoed question when available.
  const out = new Uint8Array(HEADER_LEN);
  // Always echo the header from the request where possible (ID + existing flags).
  const id = readU16(fromBuf, HDR_ID);
  const reqFlags = readU16(fromBuf, HDR_FLAGS);
  writeU16(out, HDR_ID, id);
  // QR=1, opcode kept, AA=0, TC=0, RD from request, RA=1, Z=0, rcode
  const rd = reqFlags & 0x0100;
  const flags = 0x8000 | (reqFlags & 0x7800) | rd | 0x0080 | (rcode & 0x0f);
  writeU16(out, HDR_FLAGS, flags);
  writeU16(out, HDR_QDCOUNT, 1);
  writeU16(out, 6, 0); // ANCOUNT
  writeU16(out, 8, 0); // NSCOUNT
  writeU16(out, HDR_ARCOUNT, 0);
  // Re-emit the original question verbatim so the client can correlate.
  if (question) {
    const q = question.questionEnd - question.questionStart;
    const full = new Uint8Array(HEADER_LEN + q);
    full.set(out, 0);
    full.set(fromBuf.subarray(question.questionStart, question.questionEnd), HEADER_LEN);
    return full;
  }
  return out;
}

/**
 * Clone an incoming message, replacing/removing the EDNS OPT block with one
 * that carries a single ECS option. This is a small in-place technique: we
 * rebuild only the addional section. Since it is rare to have other EDNS
 * options, we drop them (they are not something a stub needs for resolution).
 * Returns a NEW message (does not mutate input).
 */
export function replaceOptWithEcs(buf, info, ecsOption) {
  // We rebuild the whole message up to questionEnd, then the opt.
  const prefix = buf.subarray(0, info.question.questionEnd);
  if (info.opt === null && ecsOption === null) return buf;

  const opt = buildOptRdata(ecsOption); // may be null if no ecs
  if (info.opt === null && opt === null) return buf;

  const optRecord = buildOptRecord(opt); // type 41 RR
  const newArCount = (info.opt === null ? 0 : info.additionalCount - 1) + 1;
  const out = new Uint8Array(prefix.length + optRecord.length);
  out.set(prefix, 0);
  out.set(optRecord, prefix.length);
  writeU16(out, HDR_ARCOUNT, newArCount);
  return out;
}

/** Build the full OPT RR (name=root 0x00, type 41, class=UDP size, ttl, rdata). */
function buildOptRecord(rdata) {
  const rd = rdata ?? new Uint8Array(0);
  const len = 1 + 2 + 2 + 4 + 2 + rd.length; // 0x00 + type + class + ttl + rdlength + rdata
  const out = new Uint8Array(len);
  out[0] = 0; // root name
  writeU16(out, 1, 41); // type OPT
  writeU16(out, 3, 1232); // class = max UDP payload
  writeU32(out, 5, 0); // extended rcode / version = 0
  writeU16(out, 9, rd.length);
  out.set(rd, 11);
  return out;
}

function writeU32(buf, off, value) {
  buf[off] = (value >>> 24) & 0xff;
  buf[off + 1] = (value >>> 16) & 0xff;
  buf[off + 2] = (value >>> 8) & 0xff;
  buf[off + 3] = value & 0xff;
}

/**
 * Validate an upstream answer against the original query (IDs must match).
 * Returns the raw 16-bit flags of the answer on success; throws on mismatch.
 * We permit mismatched IDs to fail closed — a broken upstream must not deliver
 * an answer for a different query to our client.
 */
export function validateUpstreamResponse(answerBuf, originalInfo) {
  if (answerBuf.length < 12) throw new DnsFormatError("answer_too_short");
  const answerId = (answerBuf[0] << 8) | answerBuf[1];
  if (originalInfo && answerId !== originalInfo.id) {
    throw new DnsFormatError("id_mismatch");
  }
  const flags = (answerBuf[2] << 8) | answerBuf[3];
  // Must be a response (QR=1). Also reject truncated (TC) responses — we don't
  // resend over the same channel, so a truncated answer is unusable.
  if ((flags & 0x8000) === 0) throw new DnsFormatError("not_response");
  if ((flags & 0x0200) !== 0) throw new DnsFormatError("truncated");
  return flags;
}

export { readU16, writeU16, writeU32 };

/**
 * Compute the minimum TTL (seconds) across answer + authority records, using
 * the SOA MINIMUM field for negative (NXDOMAIN / NODATA) answers per RFC 2308.
 *
 * Used to derive a safe DNS cache lifetime: we never serve a cached answer
 * longer than the response's own minimum TTL. Falls back to 0 (do not cache)
 * when the message has no records.
 */
export function answerTtlSeconds(buf, info) {
  const toU32At = (o) =>
    o + 3 < buf.length
      ? ((buf[o] & 0xff) << 24) |
        ((buf[o + 1] & 0xff) << 16) |
        ((buf[o + 2] & 0xff) << 8) |
        (buf[o + 3] & 0xff)
      : 0;

  // Walk one RR at `start`. Returns { next, type, ttl, rdataOff }.
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
      // SOA RDATA layout: MNAME (name, usually a compression pointer, 2 bytes)
      // RNAME (name, pointer, 2 bytes) SERIAL(4) REFRESH(4) RETRY(4)
      // EXPIRE(4) MINIMUM(4). MINIMUM ends at rdataOff + 2 + 2 + 20 - 4.
      // = rdataOff + 20, reading 4 bytes.
      const minFieldOff = rdataOff + 2 + 2 + 16; // after the two names + 16 bytes
      const minimum = toU32At(minFieldOff);
      if (minimum < minTtl) minTtl = minimum;
    }
    cursor = next;
    if (cursor > buf.length) break;
  }
  if (!sawRecord) return 0;
  return minTtl === Infinity ? 0 : minTtl;
}
