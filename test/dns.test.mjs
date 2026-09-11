/**
 * Local correctness tests for the DoH worker's binary logic.
 * Run with: node test/run.mjs
 * These run WITHOUT the Cloudflare runtime (only pro plans use fetch/Response),
 * so we test only the pure wire-format + rule + IP + ECS building.
 */

import { parseDnsMessage, buildErrorResponse } from "../src/dns.js";
import { encodeEcsRdata, wrapEcsOption } from "../src/ecs.js";
import { parseIpString, subnetForEcs } from "../src/ip.js";
import { loadRulesFromText, isDomestic } from "../src/rules.js";

let passed = 0;
let failed = 0;
function assert(cond, name) {
  if (cond) {
    passed += 1;
    console.log(`  ok - ${name}`);
  } else {
    failed += 1;
    console.error(`  FAIL - ${name}`);
  }
}

/** Build a minimal DNS query: header + one question, no additional. */
function buildQuery(name, qtype = 1, qclass = 1, id = 0x1234) {
  const header = new Uint8Array(12);
  header[0] = id >> 8;
  header[1] = id & 0xff;
  header[2] = 0x01; // RD=1
  header[3] = 0;
  header[4] = 0;
  header[5] = 1; // QDCOUNT=1
  // encode name
  const labels = name.split(".");
  const parts = [];
  for (const lab of labels) {
    parts.push(lab.length);
    for (let i = 0; i < lab.length; i += 1) parts.push(lab.charCodeAt(i));
  }
  parts.push(0);
  parts.push((qtype >> 8) & 0xff, qtype & 0xff, (qclass >> 8) & 0xff, qclass & 0xff);
  const buf = new Uint8Array(header.length + parts.length);
  buf.set(header, 0);
  parts.forEach((v, i) => {
    buf[12 + i] = v;
  });
  return buf;
}

// --- parseDnsMessage tests -------------------------------------------------
{
  const q = buildQuery("github.com");
  const info = parseDnsMessage(q);
  assert(info.question.name === "github.com", "parses qname github.com");
  assert(info.question.qtype === 1, "qtype=1 (A)");
  assert(info.question.qclass === 1, "qclass=1 (IN)");
  assert(info.opt === null, "no OPT in plain query");
  assert(info.id === 0x1234, "id preserved");
}

{
  const q = buildQuery("a.b.example.org");
  const info = parseDnsMessage(q);
  assert(info.question.name === "a.b.example.org", "parses multi-label qname");
}

{
  // mixed case should normalize to lower-case
  const q = buildQuery("GitHub.COM");
  const info = parseDnsMessage(q);
  assert(info.question.name === "github.com", "qname lower-cased");
}

// buildErrorResponse --------------------------------------------------------------
{
  const q = buildQuery("github.com");
  const err = buildErrorResponse(q, 2, null);
  assert(err.byteLength === 12, "SERVFAIL minimal is 12 bytes");
  const flags = (err[2] << 8) | err[3];
  assert((flags & 0x8000) !== 0, "QR set in error response");
  assert((flags & 0x000f) === 2, "rcode=2 (SERVFAIL)");
}

// ip --------------------------------------------------------------------------------
{
  const ip = parseIpString("1.2.3.4");
  assert(ip.family === 1 && ip.bytes[0] === 1, "parse v4 1.2.3.4");
  const subnet = subnetForEcs("1.2.3.4", 24, 56);
  assert(subnet.network[0] === 1 && subnet.network[1] === 2 && subnet.network[2] === 3, "ECS v4 /24 network");
  assert(subnet.network[3] === 0, "ECS v4 masks low byte");
  assert(subnet.family === 1, "ECS family v4");
}
{
  const ip = parseIpString("2001:db8::1");
  assert(ip.family === 2, "parse v6 2001:db8::1");
  const subnet = subnetForEcs("2606:4700:4700::1111", 24, 56); // real global (Cloudflare DNS)
  assert(subnet.family === 2 && subnet.prefixLength === 56, "ECS v6 /56");
}

// ecs encoding ----------------------------------------------------------------------
{
  const rdata = encodeEcsRdata(1, new Uint8Array([1, 2, 3, 4]), 24);
  assert(rdata[0] === 0 && rdata[1] === 1, "ECS family byte");
  assert(rdata[2] === 24, "ECS prefix 24");
  assert(rdata[3] === 0, "ECS scope 0");
  assert(rdata[4] === 1 && rdata[5] === 2, "ECS address starts at byte 4");
  const opt = wrapEcsOption(rdata);
  assert(opt[1] === 8, "ECS option code=8");
  assert(opt.length === 4 + rdata.length, "ECS option length wraps");
}

// rules -------------------------------------------------------------------------
{
  const rules = loadRulesFromText(`
github.com
full:super-exact.io
regexp:^spec\\.example\\.org$
`);
  assert(isDomestic("github.com", rules) === true, "plain suffix match github.com");
  assert(isDomestic("a.github.com", rules) === true, "plain suffix match subdomain");
  assert(isDomestic("evilgithub.com", rules) === false, "plain must not match prefix");
  assert(isDomestic("super-exact.io", rules) === true, "full match");
  assert(isDomestic("x.super-exact.io", rules) === false, "full must not match subdomain");
  assert(isDomestic("spec.example.org", rules) === true, "regexp matches");
  assert(isDomestic("github.org", rules) === false, "no match");
}

console.log(`\n${passed} passed, ${failed} failed`);
process.exitCode = failed > 0 ? 1 : 0;