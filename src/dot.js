#!/usr/bin/env node
/**
 * Standalone DNS-over-TLS (RFC 7858) server — plain Node.js 18+, zero dependencies.
 *
 * Why a separate entry point? Cloudflare Workers only expose HTTP(S) on 443 and
 * cannot listen on TCP/853 (Spectrum, the only CF product that could, is a paid
 * product). Android "Private DNS" speaks DoT exclusively and refuses DoH, so a
 * self-hostable DoT frontend is the only way to point an Android phone at this
 * resolver. This process reuses the exact same resolution core as the Worker
 * (src/core.js): rule-based split routing, blocklist, ECS injection, concurrent
 * upstream racing and DNSSEC AD masking — the two entry points cannot drift.
 *
 * Wire format: RFC 7858 §3.2 — every DNS message is prefixed with a 2-byte
 * big-endian length. Multiple queries per connection (RFC 7766 pipelining) are
 * answered as they complete, without head-of-line blocking.
 *
 * Client IP for ECS comes from the TLS socket itself (direct connection, no
 * spoofable headers) — loopback/private addresses are skipped by the same
 * global-unicast rules the Worker uses for `cf-connecting-ip`.
 *
 * Run:  node src/dot.js --cert /etc/letsencrypt/live/dns.example.com/fullchain.pem \
 *                       --key  /etc/letsencrypt/live/dns.example.com/privkey.pem
 * Env:  DOT_PORT (853), DOT_HOST (0.0.0.0), DOT_TLS_CERT, DOT_TLS_KEY,
 *       DOT_IDLE_TIMEOUT_SECONDS (30), DOT_MAX_CONNECTIONS (128),
 *       DOT_REFRESH_SECONDS (21600), DOT_MAX_QPS_PER_IP (50),
 *       DOT_MAX_CONNECTIONS_PER_IP (16), DOT_STATS_SECONDS (60) +
 *       every DOH_* variable read by config.js.
 */

import tls from "node:tls";
import { Buffer } from "node:buffer";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseUint, readConfig } from "./config.js";
import { buildErrorResponse, parseDnsMessage } from "./dns.js";
import { resolveQuery } from "./core.js";
import { serverFailure } from "./resolver.js";
import { metrics } from "./metrics.js";
import { refreshRules } from "./rules.js";
import { refreshBlock } from "./filter.js";
import { createIpLimiter } from "./ratelimit.js";

/** Stable JSON log-line builder for metrics (exported for tests). */
export function formatStatsLine(snapshot, extra = {}) {
  return `stats ${JSON.stringify({ ...snapshot, ...extra })}`;
}

const RCODE_FORMERR = 1;
const FRAME_HEADER_BYTES = 2; // RFC 7858 §3.2 length prefix
const MIN_DNS_MESSAGE_BYTES = 12; // DNS header
// RFC 7766 flow control: stop reading a connection once this many queries are
// in flight, and resume as they drain (same strategy as unbound's tcp queries).
const MAX_INFLIGHT_QUERIES_PER_CONNECTION = 64;
// A pipelining client that never reads its answers must not grow our heap
// without bound; past this buffered-output size we drop the connection.
const MAX_SOCKET_BUFFERED_BYTES = 1 << 20;
const TLS_HANDSHAKE_TIMEOUT_MS = 15_000; // Node default is 120s — too generous

/**
 * Incremental RFC 7858 deframer for a byte stream. Feed it raw socket chunks;
 * it returns the complete, in-frame DNS messages seen so far. Frames smaller
 * than a DNS header or larger than `maxMessageBytes` are dropped whole so the
 * stream stays in sync with subsequent frames.
 */
export class DotFramer {
  constructor(maxMessageBytes) {
    this.maxMessageBytes =
      Number.isInteger(maxMessageBytes) && maxMessageBytes >= MIN_DNS_MESSAGE_BYTES
        ? maxMessageBytes
        : 65535;
    this.pending = Buffer.alloc(0);
    this.skipping = 0; // remaining bytes of a dropped frame still to discard
  }

  /** @returns {Buffer[]} complete DNS messages (views into an internal buffer) */
  push(chunk) {
    if (this.skipping > 0) {
      const take = Math.min(this.skipping, chunk.length);
      this.skipping -= take;
      if (take === chunk.length) return [];
      chunk = chunk.subarray(take);
    }
    // Copy: socket 'data' buffers are only valid synchronously, and messages are
    // answered asynchronously after await points.
    this.pending =
      this.pending.length === 0 ? Buffer.from(chunk) : Buffer.concat([this.pending, chunk]);
    const messages = [];
    for (;;) {
      if (this.pending.length < FRAME_HEADER_BYTES) break;
      const declared = this.pending.readUInt16BE(0);
      const total = FRAME_HEADER_BYTES + declared;
      if (declared < MIN_DNS_MESSAGE_BYTES || declared > this.maxMessageBytes) {
        if (this.pending.length >= total) {
          metrics.inc("dot_frame_dropped");
          this.pending = this.pending.subarray(total);
          continue;
        }
        this.skipping = total - this.pending.length;
        this.pending = Buffer.alloc(0);
        break;
      }
      if (this.pending.length < total) break;
      messages.push(this.pending.subarray(FRAME_HEADER_BYTES, total));
      this.pending = this.pending.subarray(total);
    }
    return messages;
  }
}

/** Encode a DNS message into an RFC 7858 frame. */
export function encodeDotFrame(message) {
  if (message.length > 0xffff) throw new Error("dot_frame_too_large");
  const frame = Buffer.allocUnsafe(FRAME_HEADER_BYTES + message.length);
  frame.writeUInt16BE(message.length, 0);
  frame.set(message, FRAME_HEADER_BYTES);
  return frame;
}

/**
 * Normalize a Node socket address to a plain IP for the ECS pipeline:
 * IPv4-mapped IPv6 ("::ffff:1.2.3.4") collapses to "1.2.3.4"; anything else
 * (including "::1" and null) is passed through — ip.js rejects non-global
 * unicast addresses, so loopback/private clients get no ECS, exactly like on
 * the Worker where such addresses never reach `cf-connecting-ip`.
 */
export function normalizeClientAddress(remoteAddress) {
  if (typeof remoteAddress !== "string" || remoteAddress.length === 0) return null;
  const mapped = remoteAddress.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
  return mapped ? mapped[1] : remoteAddress;
}

function writeDotFrame(socket, message) {
  if (!socket || socket.destroyed || socket.writableEnded) return;
  try {
    if (socket.bufferSize > MAX_SOCKET_BUFFERED_BYTES) {
      socket.destroy();
      return;
    }
    socket.write(encodeDotFrame(message));
  } catch {
    metrics.inc("dot_write_errors");
    /* client vanished mid-write; the error handler destroys the socket */
  }
}

/** Resolve one wire-format query and write the framed answer. Never throws. */
async function answerQuery(socket, query, { config, env, clientAddress }) {
  metrics.inc("requests");
  let parsed;
  try {
    parsed = parseDnsMessage(query);
  } catch {
    metrics.inc("formerr");
    writeDotFrame(socket, buildErrorResponse(query, RCODE_FORMERR, null));
    return;
  }
  let outcome;
  try {
    outcome = await resolveQuery(query, parsed, {
      clientIp: clientAddress,
      env,
      config,
    });
  } catch {
    // resolveQuery is designed not to throw; if a future regression does,
    // degrade to SERVFAIL instead of leaving the client hanging.
    metrics.inc("servfail");
    writeDotFrame(socket, serverFailure(query, parsed.question));
    return;
  }
  if (!outcome.ok) {
    metrics.inc("servfail");
    writeDotFrame(socket, serverFailure(query, parsed.question));
    return;
  }
  metrics.inc("ok");
  writeDotFrame(socket, outcome.answer);
}

/**
 * Attach the DoT framing + answering logic to one connected (TLS) socket.
 * Exported for tests; the server below wires it automatically.
 */
export function handleDotConnection(socket, { config, env, clientAddress, idleTimeoutMs, limiter }) {
  const framer = new DotFramer(config.maxQueryBytes);
  let inFlight = 0;
  let paused = false;
  socket.on("data", (chunk) => {
    let messages;
    try {
      messages = framer.push(chunk);
    } catch {
      socket.destroy();
      return;
    }
    for (const message of messages) {
      // Per-source query budget: drop without answering when the bucket is empty.
      if (limiter && !limiter.allowQuery(clientAddress)) {
        metrics.inc("dot_rate_limited");
        continue;
      }
      // Pipelining (RFC 7766): resolve concurrently, never head-of-line block.
      inFlight += 1;
      answerQuery(socket, message, { config, env, clientAddress })
        .catch(() => {
          // answerQuery is designed never to reject; if a future regression does,
          // the connection is unhealthy — tear it down and count it so the
          // failure is not invisible.
          metrics.inc("dot_answer_errors");
          socket.destroy();
        })
        .finally(() => {
          inFlight -= 1;
          if (paused && inFlight < MAX_INFLIGHT_QUERIES_PER_CONNECTION) {
            paused = false;
            socket.resume();
          }
        });
    }
    // Saturated: apply TCP backpressure to the client instead of growing our
    // memory or amplifying upstream traffic.
    if (inFlight >= MAX_INFLIGHT_QUERIES_PER_CONNECTION && !paused) {
      paused = true;
      socket.pause();
    }
  });
  socket.setTimeout(idleTimeoutMs, () => {
    metrics.inc("dot_idle_timeouts");
    socket.destroy();
  });
  socket.on("error", () => {
    // A peer resetting an idle connection (ECONNRESET) is routine; count it and
    // tear the socket down. Never leave a socket error unhandled — that would
    // throw and take down the process.
    metrics.inc("dot_socket_errors");
    socket.destroy();
  });
}

/**
 * Create the TLS server. `cert`/`key` are PEM **contents** (a public CA must
 * have signed them — Android Private DNS rejects private CAs).
 */
export function createDotServer({
  config,
  env,
  cert,
  key,
  idleTimeoutMs = 30_000,
  maxConnections = 128,
  limiter,
  logger = () => {},
}) {
  let connections = 0;
  const server = tls.createServer(
    { cert, key, handshakeTimeout: TLS_HANDSHAKE_TIMEOUT_MS },
    (socket) => {
      connections += 1;
      if (connections > maxConnections) {
        metrics.inc("dot_rejected");
        logger(`connection limit reached (${maxConnections}), rejecting`);
        socket.destroy();
        connections -= 1;
        return;
      }
      metrics.inc("dot_connections");
      const clientAddress = normalizeClientAddress(socket.remoteAddress);
      // Per-source connection budget: a single abusive host cannot hold more
      // than its share of the pool.
      if (limiter && !limiter.acquireConnection(clientAddress)) {
        metrics.inc("dot_rejected");
        logger(`per-IP connection limit reached, rejecting ${clientAddress ?? socket.remoteAddress}`);
        socket.destroy();
        connections -= 1;
        return;
      }
      logger(`connection from ${clientAddress ?? socket.remoteAddress}:${socket.remotePort}`);
      handleDotConnection(socket, { config, env, clientAddress, idleTimeoutMs, limiter });
      socket.on("close", () => {
        connections -= 1;
        limiter?.releaseConnection(clientAddress);
      });
    }
  );
  // Cap the total number of sockets — including those still mid-TLS-handshake.
  // The handler-level counter above only counts *validated* connections, so
  // without this an attacker could open unlimited slow handshakes (each held up
  // to handshakeTimeout) and exhaust descriptors.
  server.maxConnections = maxConnections + 32;
  server.on("tlsClientError", (err) => {
    metrics.inc("dot_tls_errors");
    logger(`tls handshake failed: ${err.message}`);
  });
  return server;
}

// ---- CLI entry ---------------------------------------------------------------

function parseArgs(argv) {
  const args = { help: false, port: undefined, host: undefined, cert: undefined, key: undefined };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (a === "--help" || a === "-h") args.help = true;
    else if (a.startsWith("--port=")) args.port = a.slice("--port=".length);
    else if (a === "--port") args.port = argv[++i];
    else if (a.startsWith("--host=")) args.host = a.slice("--host=".length);
    else if (a === "--host") args.host = argv[++i];
    else if (a.startsWith("--cert=")) args.cert = a.slice("--cert=".length);
    else if (a === "--cert") args.cert = argv[++i];
    else if (a.startsWith("--key=")) args.key = a.slice("--key=".length);
    else if (a === "--key") args.key = argv[++i];
    else if (a.startsWith("--")) {
      throw new Error(`unknown option: ${a}`);
    } else {
      throw new Error(`unexpected argument: ${a}`);
    }
  }
  return args;
}

function usage() {
  return [
    "cf-doh DoT server (RFC 7858) — Android Private DNS frontend for the shared resolver core.",
    "",
    "Usage: node src/dot.js --cert <PEM> --key <PEM> [--port 853] [--host 0.0.0.0]",
    "",
    "Options:",
    "  --cert <path>   TLS certificate PEM (public CA; Android rejects private CAs)",
    "  --key  <path>   TLS private key PEM",
    "  --port <n>      listen port (default 853 / $DOT_PORT)",
    "  --host <addr>   bind address (default 0.0.0.0 / $DOT_HOST)",
    "",
    "DoT-specific env: DOT_TLS_CERT, DOT_TLS_KEY, DOT_PORT, DOT_HOST,",
    "  DOT_IDLE_TIMEOUT_SECONDS (30), DOT_MAX_CONNECTIONS (128), DOT_REFRESH_SECONDS (21600),",
    "  DOT_MAX_QPS_PER_IP (50), DOT_MAX_CONNECTIONS_PER_IP (16),",
    "  DOT_STATS_SECONDS (60, 0=off). Each is independently disabled by setting to 0.",
    "  No client auth (RFC 7858): per-IP rate limiting is the primary guard.",
    "Resolver env (shared with the Worker): DOH_PATH is ignored here; see README —",
    "  DOMESTIC_DOH_URL, GLOBAL_DOH_URL, RULES_URL, ECS_IPV4_PREFIX, CACHE_TTL_SECONDS, ...",
  ].join("\n");
}

function defaultLogger(message) {
  console.log(`[cf-doh dot] ${new Date().toISOString()} ${message}`);
}

export function main(argv = process.argv.slice(2), env = process.env) {
  let args;
  try {
    args = parseArgs(argv);
  } catch (err) {
    console.error(`${err.message}\n\n${usage()}`);
    process.exitCode = 1;
    return;
  }
  if (args.help) {
    console.log(usage());
    return;
  }

  const config = readConfig(env);
  if (config.token) {
    defaultLogger(
      "WARNING: DOH_TOKEN is set, but DoT (RFC 7858) has no way to carry a token — " +
        "this port is open to anyone who can reach it. Restrict access at the network layer."
    );
  }
  const certPath = args.cert || env.DOT_TLS_CERT;
  const keyPath = args.key || env.DOT_TLS_KEY;
  if (!certPath || !keyPath) {
    console.error(
      "TLS certificate/key required (DoT is defined only over TLS).\n" +
        "Pass --cert/--key or set DOT_TLS_CERT/DOT_TLS_KEY. Use a public CA —\n" +
        "Android Private DNS only trusts system CAs (e.g. Let's Encrypt).\n\n" +
        usage()
    );
    process.exitCode = 1;
    return;
  }

  let cert;
  let key;
  try {
    cert = readFileSync(resolve(certPath), "utf8");
    key = readFileSync(resolve(keyPath), "utf8");
  } catch (err) {
    console.error(`cannot read TLS material: ${err.message}`);
    process.exitCode = 1;
    return;
  }

  // Same numeric-parsing convention as every DOH_* variable: invalid values
  // fall back to the default instead of leaking NaN into timers/limits.
  const port = parseUint(args.port ?? env.DOT_PORT, 853, 1, 65535);
  const host = args.host || env.DOT_HOST || "0.0.0.0";
  const idleTimeoutMs = parseUint(env.DOT_IDLE_TIMEOUT_SECONDS, 30, 5, 86400) * 1000;
  const maxConnections = parseUint(env.DOT_MAX_CONNECTIONS, 128, 1, 65536);
  const refreshSeconds = parseUint(env.DOT_REFRESH_SECONDS, 21600, 60, 7 * 86400);
  const maxQpsPerIp = parseUint(env.DOT_MAX_QPS_PER_IP, 50, 0, 10000);
  const maxConnPerIp = parseUint(env.DOT_MAX_CONNECTIONS_PER_IP, 16, 0, 1000);

  const limiter = maxQpsPerIp > 0 || maxConnPerIp > 0
    ? createIpLimiter({ maxQpsPerIp, maxConnectionsPerIp: maxConnPerIp })
    : null;

  // Periodic metrics summary for journalctl-based observability. Set
  // DOT_STATS_SECONDS=0 to disable. The timer is unref'd so it never keeps
  // the process alive; the final dump on shutdown covers the last interval.
  const statsSeconds = parseUint(env.DOT_STATS_SECONDS, 60, 0, 86400);
  const logStats = () => {
    const extra = limiter ? { dot_limiter_ips: limiter.size() } : {};
    defaultLogger(formatStatsLine(metrics.snapshot(), extra));
  };
  let statsTimer = null;
  if (statsSeconds > 0) {
    statsTimer = setInterval(logStats, statsSeconds * 1000);
    statsTimer.unref();
  }

  const server = createDotServer({
    config,
    env,
    cert,
    key,
    idleTimeoutMs,
    maxConnections,
    limiter,
    logger: defaultLogger,
  });
  server.on("error", (err) => {
    // A listener failure (EACCES on 853, EADDRINUSE, bad PEM) is unrecoverable
    // for a standalone server: exit non-zero so the supervisor (systemd
    // Restart=always) can retry, instead of hanging as a zombie that holds the
    // keep-alive timer open.
    defaultLogger(`server error: ${err.message}`);
    process.exit(1);
  });
  server.listen(port, host, () => {
    defaultLogger(
      `DoT listening on ${host}:${port} — upstreams domestic=[${config.domesticUrls.join(", ")}] global=[${config.globalUrls.join(", ")}]`
    );
  });

  // Warm the rule/block caches, then refresh periodically (the Worker does this
  // via its cron trigger; a long-lived Node process needs its own timer).
  const refreshAll = async () => {
    try {
      const ok = await refreshRules(env);
      defaultLogger(`rules refresh ${ok ? "updated" : "kept existing"}`);
    } catch {
      defaultLogger("rules refresh failed, keeping existing rules");
    }
    if (env.BLOCK_URL) {
      try {
        const ok = await refreshBlock(env);
        defaultLogger(`blocklist refresh ${ok ? "updated" : "kept existing"}`);
      } catch {
        defaultLogger("blocklist refresh failed, keeping existing blocklist");
      }
    }
  };
  void refreshAll();
  const refreshTimer = setInterval(() => void refreshAll(), refreshSeconds * 1000);

  const shutdown = (signal) => {
    defaultLogger(`${signal} received, closing listener...`);
    clearInterval(refreshTimer);
    if (statsTimer) { clearInterval(statsTimer); logStats(); }
    server.close(() => process.exit(0));
    // Don't hang on lingering client sockets; in-flight queries finish or the
    // process exits after the grace period.
    setTimeout(() => process.exit(0), 5000).unref();
  };
  process.on("SIGINT", () => shutdown("SIGINT"));
  process.on("SIGTERM", () => shutdown("SIGTERM"));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
