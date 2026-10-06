/**
 * DoT (RFC 7858) entry-point tests.
 *
 *  1. DotFramer unit tests: split feeds, pipelined frames, oversized/malformed
 *     frame drop with stream resync.
 *  2. normalizeClientAddress: IPv4-mapped IPv6 → plain IPv4 for the ECS path.
 *  3. CLI: --help exits 0; missing cert/key exits 1 with guidance.
 *  4. End-to-end over real TLS (self-signed cert generated via openssl):
 *     handshake + verification, framed query/answer, pipelining, oversize-frame
 *     recovery, idle timeout.
 *  5. Acceptance (issue #1): the SAME wire query routed through the DoT entry
 *     and the DoH (Worker) entry hits the same domestic/global upstream group
 *     and returns a byte-identical answer.
 *
 * Run: node test/dot.test.mjs   (part of npm test)
 */

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import tls from "node:tls";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const dir = dirname(fileURLToPath(import.meta.url));
const here = (p) => join(dir, p);

let passed = 0;
let failed = 0;
const check = (cond, label) => {
  if (cond) {
    passed += 1;
    console.log(`  ok - ${label}`);
  } else {
    failed += 1;
    console.error(`  FAIL - ${label}`);
  }
};

// ---- shared helpers ----------------------------------------------------------

/** Minimal wire query: one question, RD=1 (same shape as test/routing.mjs). */
function buildQuery(name, qtype = 1, id = 0x3333) {
  const header = new Uint8Array(12);
  header[0] = id >> 8;
  header[1] = id & 0xff;
  header[2] = 0x01;
  header[5] = 1;
  const parts = [];
  for (const lab of name.split(".")) {
    parts.push(lab.length);
    for (let i = 0; i < lab.length; i += 1) parts.push(lab.charCodeAt(i));
  }
  parts.push(0, (qtype >> 8) & 0xff, qtype & 0xff, 0, 1);
  return new Uint8Array([...header, ...parts]);
}

function dotFrame(message) {
  const frame = new Uint8Array(2 + message.length);
  frame[0] = message.length >> 8;
  frame[1] = message.length & 0xff;
  frame.set(message, 2);
  return frame;
}

function fakeKv(ruleText) {
  return {
    async get(k) {
      if (k === "rules:data") return ruleText;
      return null;
    },
    async put() {},
  };
}

// ---- 1) DotFramer unit tests ---------------------------------------------------

console.log("=== dot framer (unit) ===");
{
  const { DotFramer } = await import("../src/dot.js");
  const q = buildQuery("github.com", 1, 0x0102);

  // Whole frame in one chunk.
  const f1 = new DotFramer(4096);
  const got1 = f1.push(dotFrame(q));
  check(got1.length === 1 && Buffer.compare(Buffer.from(got1[0]), Buffer.from(q)) === 0, "single complete frame yields the message");

  // Byte-by-byte feed must produce exactly one message at the end.
  const f2 = new DotFramer(4096);
  const frame = dotFrame(q);
  let emitted = [];
  for (const b of frame) emitted.push(...f2.push(new Uint8Array([b])));
  check(emitted.length === 1 && Buffer.compare(Buffer.from(emitted[0]), Buffer.from(q)) === 0, "byte-by-byte feed reassembles one message");

  // Pipelined frames in a single chunk.
  const q2 = buildQuery("example.net", 28, 0x4444);
  const f3 = new DotFramer(4096);
  const both = new Uint8Array([...dotFrame(q), ...dotFrame(q2)]);
  const got3 = f3.push(both);
  check(got3.length === 2 && Buffer.compare(Buffer.from(got3[0]), Buffer.from(q)) === 0 && Buffer.compare(Buffer.from(got3[1]), Buffer.from(q2)) === 0, "two pipelined frames yield both messages in order");

  // Oversized frame is dropped whole and the stream resyncs.
  const f4 = new DotFramer(512);
  const big = new Uint8Array(2 + 600); // header says 600 > cap 512
  big[0] = 600 >> 8;
  big[1] = 600 & 0xff;
  const mixed = new Uint8Array([...big, ...dotFrame(q)]);
  const got4 = f4.push(mixed);
  check(got4.length === 1 && Buffer.compare(Buffer.from(got4[0]), Buffer.from(q)) === 0, "oversized frame dropped, following frame intact");

  // Oversized frame split across feeds (drop completes only after all bytes arrive).
  const f5 = new DotFramer(512);
  check(f5.push(big.subarray(0, 100)).length === 0, "partial oversized frame emits nothing");
  const got5 = f5.push(new Uint8Array([...big.subarray(100), ...dotFrame(q)]));
  check(got5.length === 1 && Buffer.compare(Buffer.from(got5[0]), Buffer.from(q)) === 0, "oversized frame fully skipped across chunks, next frame intact");

  // Sub-DNS-header frame (declared length < 12) is dropped.
  const f6 = new DotFramer(4096);
  const tiny = new Uint8Array([0, 5, 1, 2, 3, 4, 5]);
  const got6 = f6.push(new Uint8Array([...tiny, ...dotFrame(q)]));
  check(got6.length === 1 && Buffer.compare(Buffer.from(got6[0]), Buffer.from(q)) === 0, "malformed tiny frame dropped, stream resyncs");
}

// ---- 2) normalizeClientAddress --------------------------------------------------

console.log("=== normalizeClientAddress (unit) ===");
{
  const { normalizeClientAddress } = await import("../src/dot.js");
  check(normalizeClientAddress("::ffff:203.0.113.7") === "203.0.113.7", "IPv4-mapped IPv6 collapses to IPv4");
  check(normalizeClientAddress("2001:db8::1") === "2001:db8::1", "plain IPv6 passes through");
  check(normalizeClientAddress("127.0.0.1") === "127.0.0.1", "IPv4 passes through");
  check(normalizeClientAddress(undefined) === null, "missing address → null (no ECS)");
}

// ---- 3) CLI behavior -------------------------------------------------------------

console.log("=== dot CLI ===");
{
  const help = spawnSync(process.execPath, [here("../src/dot.js"), "--help"], { encoding: "utf8" });
  check(help.status === 0 && help.stdout.includes("RFC 7858"), "--help prints usage and exits 0");

  const noCert = spawnSync(process.execPath, [here("../src/dot.js")], { encoding: "utf8" });
  check(
    noCert.status === 1 && noCert.stderr.includes("public CA"),
    "missing cert/key exits 1 and explains the public-CA requirement"
  );
}

// ---- 4/5) Live TLS server --------------------------------------------------------

// Self-signed cert (valid 1 day) as its own CA; SAN must cover "localhost".
const certDir = mkdtempSync(join(tmpdir(), "cf-doh-dot-"));
const certPath = join(certDir, "cert.pem");
const keyPath = join(certDir, "key.pem");
const openssl = spawnSync(
  "openssl",
  [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes",
    "-keyout", keyPath, "-out", certPath,
    "-days", "1", "-subj", "/CN=localhost",
    "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
  ],
  { encoding: "utf8" }
);

if (openssl.status !== 0) {
  console.log(`SKIP live TLS tests: openssl unavailable (${openssl.error?.message ?? openssl.stderr})`);
  rmSync(certDir, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exitCode = failed > 0 ? 1 : 0;
} else {
  await runLiveTests();
  rmSync(certDir, { recursive: true, force: true });
  console.log(`\n${passed} passed, ${failed} failed`);
  process.exitCode = failed > 0 ? 1 : 0;
}

async function runLiveTests() {
  console.log("=== dot over real TLS ===");

  // Mock upstreams that echo the forwarded query back with QR|RD|RA|NOERROR,
  // recording which group (domestic/global) was contacted — same trick as
  // test/routing.mjs. Installed BEFORE importing the resolver modules.
  const seen = { domestic: new Set(), global: new Set() };
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (u.includes("alidns") || u.includes("doh.pub")) seen.domestic.add(u);
    else seen.global.add(u);
    const body = Buffer.from(init.body);
    const ans = Buffer.alloc(body.length + 4);
    body.copy(ans, 0);
    ans[2] = 0x81;
    ans[3] = 0x80; // QR=1 RD=1 RA=1, rcode 0
    return new Response(ans, { headers: { "content-type": "application/dns-message" } });
  };

  const { createDotServer } = await import("../src/dot.js");
  const { readConfig } = await import("../src/config.js");

  const env = {
    RULES_KV: fakeKv("\ngithub.com\n"),
    DOMESTIC_DOH_URL: "https://dns.alidns.com/dns-query",
    DOMESTIC_FALLBACK_DOH_URL: "https://doh.pub/dns-query",
    GLOBAL_DOH_URL: "https://dns.google/dns-query",
    GLOBAL_FALLBACK_DOH_URL: "https://cloudflare-dns.com/dns-query",
    CACHE_TTL_SECONDS: "0", // keep both entry points racing upstreams for comparability
  };

  const server = createDotServer({
    config: readConfig(env),
    env,
    cert: readFileSync(certPath, "utf8"),
    key: readFileSync(keyPath, "utf8"),
    idleTimeoutMs: 250,
    logger: () => {},
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = server.address().port;

  function connect({ rejectUnauthorized = true } = {}) {
    return new Promise((resolve, reject) => {
      const s = tls.connect(
        { host: "127.0.0.1", port, ca: [readFileSync(certPath)], servername: "localhost", rejectUnauthorized },
        () => resolve(s)
      );
      s.once("error", reject);
    });
  }

  /** Send one framed query; resolve with the first framed response payload. */
  function queryOnce(socket, query, timeoutMs = 3000) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        socket.off("data", onData);
        reject(new Error("dot response timeout"));
      }, timeoutMs);
      const onData = (chunk) => {
        if (chunk.length < 2) return;
        const len = chunk.readUInt16BE(0);
        clearTimeout(timer);
        socket.off("data", onData);
        resolve(chunk.subarray(2, 2 + len));
      };
      socket.once("data", onData);
      socket.write(dotFrame(query));
    });
  }

  try {
    // TLS handshake with full certificate verification against our self-signed CA.
    const verified = await connect();
    check(verified.authorized && verified.remotePort === port, "TLS handshake verifies against the served certificate");

    // Single query → framed answer with QR=1 and matching transaction ID.
    const q1 = buildQuery("github.com", 1, 0x1234);
    const a1 = await queryOnce(verified, q1);
    check(a1.length >= 12 && (a1[2] & 0x80) !== 0, "answer frame carries QR=1");
    check(((a1[0] << 8) | a1[1]) === 0x1234, "answer echoes the transaction ID");
    verified.destroy();

    // Pipelining: two queries written back-to-back on one connection.
    const pipeSock = await connect();
    const qp1 = buildQuery("github.com", 1, 0x0a01);
    const qp2 = buildQuery("example.net", 1, 0x0a02);
    pipeSock.write(Buffer.concat([dotFrame(qp1), dotFrame(qp2)]));
    const ids = [];
    for (let i = 0; i < 2; i += 1) {
      const a = await queryOnce(pipeSock, qp1);
      ids.push((a[0] << 8) | a[1]);
    }
    ids.sort();
    check(
      ids[0] === 0x0a01 && ids[1] === 0x0a02,
      "pipelined queries on one connection yield both answers (out-of-order tolerated)"
    );
    pipeSock.destroy();

    // Acceptance (issue #1): DoT and DoH behave identically for the same query —
    // same domestic/global group and byte-identical answer bytes.
    const workerMod = await import("../src/worker.js");

    async function dohAnswerFor(name) {
      const req = new Request("https://doh.test/doh", {
        method: "POST",
        headers: { "content-type": "application/dns-message" },
        body: buildQuery(name),
      });
      const resp = await workerMod.handleRequest(req, env);
      return new Uint8Array(await resp.arrayBuffer());
    }

    for (const [name, group] of [
      ["github.com", "domestic"],
      ["example.net", "global"],
    ]) {
      seen.domestic.clear();
      seen.global.clear();
      const wire = buildQuery(name);

      const dotSock = await connect();
      const fromDot = await queryOnce(dotSock, wire);
      dotSock.destroy();
      const dotGroup = seen.domestic.size > 0 ? "domestic" : "global";

      seen.domestic.clear();
      seen.global.clear();
      const fromDoh = await dohAnswerFor(name);
      const dohGroup = seen.domestic.size > 0 ? "domestic" : "global";

      check(dotGroup === group && dohGroup === group, `${name}: both entries route to ${group} (dot=${dotGroup}, doh=${dohGroup})`);
      check(Buffer.compare(Buffer.from(fromDot), Buffer.from(fromDoh)) === 0, `${name}: answer bytes identical across DoT and DoH`);
    }

    // Oversized frame on a live connection: skipped, connection stays usable.
    const resyncSock = await connect();
    const big = Buffer.alloc(2 + 5000);
    big.writeUInt16BE(5000, 0);
    resyncSock.write(big);
    const aResync = await queryOnce(resyncSock, buildQuery("github.com", 1, 0x0b0b));
    check(((aResync[0] << 8) | aResync[1]) === 0x0b0b, "oversized frame skipped on live socket, later query still answered");
    resyncSock.destroy();

    // Idle timeout closes the connection when no query arrives.
    const idleSock = await connect();
    const closed = await new Promise((resolve) => {
      idleSock.once("close", () => resolve(true));
      setTimeout(() => resolve(false), 1500);
    });
    check(closed && idleSock.destroyed, "idle connection closed by server timeout");
  } finally {
    server.close();
    await new Promise((r) => server.closeAllConnections?.() || r());
    server.unref();
  }
}
