/**
 * DoT (RFC 7858) entry-point tests.
 *
 *  1. DotFramer unit tests: split feeds, pipelined frames, oversized/malformed
 *     frame drop with stream resync.
 *  2. normalizeClientAddress: IPv4-mapped IPv6 → plain IPv4 for the ECS path.
 *  3. parseUint: shared numeric env convention (no NaN leaks into timers/limits).
 *  4. CLI: --help exits 0; missing cert/key exits 1 with guidance; DOH_TOKEN
 *     set → startup warning that DoT cannot enforce it.
 *  5. End-to-end over real TLS (self-signed cert generated via openssl):
 *     handshake + verification, framed query/answer, pipelining (any answer
 *     order), FORMERR/SERVFAIL paths, oversize-frame recovery, idle timeout.
 *  6. Acceptance (issue #1): the SAME wire query routed through the DoT entry
 *     and the DoH (Worker) entry hits the same domestic/global upstream group
 *     and returns a byte-identical answer.
 *  7. Flow control: saturating a connection pauses reads and resumes on drain;
 *     ECS injection from the socket-derived client address.
 *  8. CLI regression: a listener failure (EADDRINUSE) exits 1 instead of
 *     hanging, so a systemd Restart=always unit can recover.
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

/** Poll until fn() is true or the deadline passes; returns fn()'s last value. */
async function waitFor(fn, timeoutMs, stepMs = 20) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (fn()) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return fn();
}

/** Fake socket for driving handleDotConnection without a network. */
function makeFakeSocket() {
  const state = { written: [], pauseCalls: 0, resumeCalls: 0, handlers: {} };
  const socket = {
    destroyed: false,
    writableEnded: false,
    bufferSize: 0,
    on(ev, fn) {
      state.handlers[ev] = fn;
    },
    setTimeout() {},
    pause() {
      state.pauseCalls += 1;
    },
    resume() {
      state.resumeCalls += 1;
    },
    write(frame) {
      state.written.push(frame);
      return true;
    },
    destroy() {
      socket.destroyed = true;
    },
  };
  return { socket, state };
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

// ---- 3) parseUint (shared numeric env convention) --------------------------------

console.log("=== parseUint (unit) ===");
{
  const { parseUint } = await import("../src/config.js");
  check(parseUint("abc", 30) === 30, "non-numeric value → fallback (no NaN propagation)");
  check(parseUint(undefined, 853) === 853, "missing value → fallback");
  check(parseUint("12", 30) === 12, "valid value parsed");
  check(parseUint("1", 30, 5) === 5, "below min clamps to min");
  check(parseUint("999", 30, 5, 20) === 20, "above max clamps to max");
}

// ---- 4) CLI behavior -------------------------------------------------------------

console.log("=== dot CLI ===");
{
  const help = spawnSync(process.execPath, [here("../src/dot.js"), "--help"], { encoding: "utf8" });
  check(help.status === 0 && help.stdout.includes("RFC 7858"), "--help prints usage and exits 0");

  const noCert = spawnSync(process.execPath, [here("../src/dot.js")], { encoding: "utf8" });
  check(
    noCert.status === 1 && noCert.stderr.includes("public CA"),
    "missing cert/key exits 1 and explains the public-CA requirement"
  );

  const tokenWarn = spawnSync(process.execPath, [here("../src/dot.js")], {
    encoding: "utf8",
    env: { ...process.env, DOH_TOKEN: "secret" },
  });
  check(
    tokenWarn.status === 1 && tokenWarn.stdout.includes("no way to carry a token"),
    "DOH_TOKEN set → warns that DoT cannot enforce it"
  );
}

// ---- 5-8) Live TLS server --------------------------------------------------------

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
  const upstreamMock = { failAll: false, lastForwardedBody: null };
  globalThis.fetch = async (url, init) => {
    const u = String(url);
    if (u.includes("alidns") || u.includes("doh.pub")) seen.domestic.add(u);
    else seen.global.add(u);
    if (upstreamMock.failAll) return new Response("upstream down", { status: 502 });
    const body = Buffer.from(init.body);
    upstreamMock.lastForwardedBody = body;
    const ans = Buffer.alloc(body.length + 4);
    body.copy(ans, 0);
    ans[2] = 0x81;
    ans[3] = 0x80; // QR=1 RD=1 RA=1, rcode 0
    return new Response(ans, { headers: { "content-type": "application/dns-message" } });
  };

  const { createDotServer, handleDotConnection, DotFramer } = await import("../src/dot.js");
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

  function connect() {
    return new Promise((resolve, reject) => {
      const s = tls.connect(
        { host: "127.0.0.1", port, ca: [readFileSync(certPath)], servername: "localhost", rejectUnauthorized: true },
        () => resolve(s)
      );
      s.once("error", reject);
    });
  }

  /**
   * Stream-accumulating test client: response frames are parsed from the byte
   * stream exactly like the server parses its input, so assertions never
   * depend on TCP chunk boundaries. `next()` matches answers by arrival order
   * only — correctness is asserted on content (transaction IDs), which is what
   * RFC 7766 clients must tolerate anyway.
   */
  function createDotClient(socket) {
    const framer = new DotFramer(65535);
    const waiters = [];
    socket.on("data", (chunk) => {
      for (const message of framer.push(chunk)) {
        const waiter = waiters.shift();
        if (waiter) {
          clearTimeout(waiter.timer);
          waiter.resolve(message);
        }
      }
    });
    socket.on("close", () => {
      while (waiters.length) {
        const waiter = waiters.shift();
        clearTimeout(waiter.timer);
        waiter.reject(new Error("connection closed"));
      }
    });
    socket.on("error", () => {});
    return {
      send(query) {
        socket.write(Buffer.from(dotFrame(query)));
      },
      next(timeoutMs = 3000) {
        return new Promise((resolve, reject) => {
          const waiter = { resolve, reject, timer: null };
          waiter.timer = setTimeout(() => {
            const i = waiters.indexOf(waiter);
            if (i !== -1) waiters.splice(i, 1);
            reject(new Error("dot response timeout"));
          }, timeoutMs);
          waiters.push(waiter);
        });
      },
    };
  }

  try {
    // TLS handshake with full certificate verification against our self-signed CA.
    const verifiedSock = await connect();
    check(verifiedSock.authorized && verifiedSock.remotePort === port, "TLS handshake verifies against the served certificate");

    // Single query → framed answer with QR=1 and matching transaction ID.
    const first = createDotClient(verifiedSock);
    first.send(buildQuery("github.com", 1, 0x1234));
    const a1 = await first.next();
    check((a1[2] & 0x80) !== 0, "answer frame carries QR=1");
    check(((a1[0] << 8) | a1[1]) === 0x1234, "answer echoes the transaction ID");
    verifiedSock.destroy();

    // Pipelining: two queries written back-to-back on one connection; answers
    // may arrive in any order (RFC 7766) and both must be present.
    {
      const sock = await connect();
      const c = createDotClient(sock);
      c.send(buildQuery("github.com", 1, 0x0a01));
      c.send(buildQuery("example.net", 1, 0x0a02));
      const ids = [];
      for (let i = 0; i < 2; i += 1) {
        const a = await c.next();
        ids.push((a[0] << 8) | a[1]);
      }
      check(
        ids.includes(0x0a01) && ids.includes(0x0a02),
        "pipelined queries yield both answers (out-of-order tolerated)"
      );
      sock.destroy();
    }

    // Malformed DNS message inside a valid frame → FORMERR (rcode 1).
    {
      const sock = await connect();
      const c = createDotClient(sock);
      c.send(Buffer.alloc(12)); // header-only, QDCOUNT=0 → parseDnsMessage throws
      const a = await c.next();
      check((a[2] & 0x80) !== 0 && (a[3] & 0x0f) === 1, "malformed DNS message answered with FORMERR");
      sock.destroy();
    }

    // All upstreams failing → SERVFAIL (rcode 2) instead of silence.
    upstreamMock.failAll = true;
    try {
      const sock = await connect();
      const c = createDotClient(sock);
      c.send(buildQuery("example.net", 1, 0x0d0d));
      const a = await c.next();
      check((a[2] & 0x80) !== 0 && (a[3] & 0x0f) === 2, "all-upstream-failure answered with SERVFAIL");
      sock.destroy();
    } finally {
      upstreamMock.failAll = false;
    }

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

      const sock = await connect();
      const c = createDotClient(sock);
      c.send(wire);
      const fromDot = await c.next();
      sock.destroy();
      const dotGroup = seen.domestic.size > 0 ? "domestic" : "global";

      seen.domestic.clear();
      seen.global.clear();
      const fromDoh = await dohAnswerFor(name);
      const dohGroup = seen.domestic.size > 0 ? "domestic" : "global";

      check(dotGroup === group && dohGroup === group, `${name}: both entries route to ${group} (dot=${dotGroup}, doh=${dohGroup})`);
      check(Buffer.compare(Buffer.from(fromDot), Buffer.from(fromDoh)) === 0, `${name}: answer bytes identical across DoT and DoH`);
    }

    // Oversized frame on a live connection: skipped, connection stays usable.
    {
      const sock = await connect();
      const c = createDotClient(sock);
      const big = Buffer.alloc(2 + 5000);
      big.writeUInt16BE(5000, 0);
      sock.write(big); // raw oversized frame, dropped server-side
      c.send(buildQuery("github.com", 1, 0x0b0b));
      const a = await c.next();
      check(((a[0] << 8) | a[1]) === 0x0b0b, "oversized frame skipped on live socket, later query still answered");
      sock.destroy();
    }

    // Idle timeout closes the connection when no query arrives.
    {
      const idleSock = await connect();
      const closed = await new Promise((resolve) => {
        idleSock.once("close", () => resolve(true));
        setTimeout(() => resolve(false), 1500);
      });
      check(closed && idleSock.destroyed, "idle connection closed by server timeout");
    }

    // ECS injection: drive the connection handler with a socket address that is
    // global unicast; the forwarded query must gain an EDNS0 OPT carrying the
    // /24-masked client subnet (the "ECS comes from the TLS socket" contract).
    {
      const { socket, state } = makeFakeSocket();
      handleDotConnection(socket, { config: readConfig(env), env, clientAddress: "93.184.216.34", idleTimeoutMs: 5000 });
      upstreamMock.lastForwardedBody = null;
      const original = buildQuery("github.com");
      state.handlers.data(Buffer.from(dotFrame(buildQuery("github.com", 1, 0x0c01))));
      await waitFor(() => upstreamMock.lastForwardedBody && state.written.length > 0, 2000);
      const fwd = upstreamMock.lastForwardedBody;
      const arcount = (fwd[10] << 8) | fwd[11];
      check(arcount === 1, "ECS: forwarded query carries exactly one additional OPT record");
      check(fwd.length > original.length, "ECS: OPT record appended to the forwarded query");
      check(fwd.indexOf(Buffer.from([93, 184, 216])) !== -1, "ECS: /24-masked client subnet (93.184.216.0) present");
      check(
        state.written.length === 1 && ((state.written[0][2] << 8) | state.written[0][3]) === 0x0c01,
        "ECS: answer delivered back to the socket"
      );
    }

    // Flow control: saturating one connection pauses reads (TCP backpressure to
    // the client) and resumes once the in-flight queries drain.
    {
      const { socket, state } = makeFakeSocket();
      handleDotConnection(socket, { config: readConfig(env), env, clientAddress: null, idleTimeoutMs: 5000 });
      const burst = [];
      for (let i = 0; i < 80; i += 1) burst.push(dotFrame(buildQuery("example.net", 1, 0x1000 + i)));
      state.handlers.data(Buffer.concat(burst));
      check(state.pauseCalls >= 1, "flow control: reading pauses once >=64 queries are in flight");
      await waitFor(() => state.written.length >= 80, 3000);
      check(state.written.length === 80, "flow control: every pipelined query still gets an answer");
      await waitFor(() => state.resumeCalls >= 1, 1000);
      check(state.resumeCalls >= 1, "flow control: reading resumes after the in-flight drain");
    }

    // CLI regression (review finding): a listener failure must exit non-zero so
    // a systemd Restart=always unit can recover — never hang as a zombie.
    {
      const net = await import("node:net");
      const blocker = net.createServer();
      await new Promise((r) => blocker.listen(0, "127.0.0.1", r));
      const bPort = blocker.address().port;
      const r = spawnSync(
        process.execPath,
        [here("../src/dot.js"), "--port", String(bPort), "--host", "127.0.0.1", "--cert", certPath, "--key", keyPath],
        { encoding: "utf8", timeout: 5000 }
      );
      const output = `${r.stdout}\n${r.stderr}`;
      check(
        r.status === 1 && output.includes("EADDRINUSE"),
        "listen failure (EADDRINUSE) exits 1 instead of hanging"
      );
      blocker.close();
    }
  } finally {
    server.close();
    await new Promise((r) => server.closeAllConnections?.() || r());
    server.unref();
  }
}
