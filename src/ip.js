/**
 * IP parsing and ECS subnet derivation.
 *
 * Trust model: we only trust Cloudflare-provided headers for the client's own
 * IP. Arbitrary `X-Forwarded-For` sent by the client is IGNORED (it is spoofable);
 * we use `cf-connecting-ip`, or the left-most hop appended by Cloudflare's own
 * proxy only when the deployment is behind a trusted CDN. To keep it simple and
 * safe out of the box, the worker reads `cf-connecting-ip` (set by Cloudflare at
 * every edge hit) and explicitly refuses to let a client choose its ECS prefix.
 */

export function parseIp4(bytes) {
  // bytes: Uint8Array of 4
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

function isIpv4GlobalUnicast(b) {
  const a = b[0];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  const second = b[1];
  if (a === 100 && second >= 64 && second <= 127) return false; // CGNAT
  if (a === 169 && second === 254) return false; // link-local
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
  // First hextet must be 2000::/3 (global unicast).
  if ((b[0] & 0xe0) !== 0x20) return false;
  // Exclude documentation / example ranges.
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return false;
  // 2001:0::/32 won't worry, basic unicast check is enough.
  return true;
}

/**
 * Parse a dotted IPv4 or colon IPv6 string into { family, bytes }.
 * Returns null on any malformed/failed parse.
 */
export function parseIpString(value) {
  const s = String(value || "").trim();
  if (s.includes(":")) {
    // IPv6 — implement longhand parse (small, no deps).
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
  if ((!hasCompression && missing !== 0) || (hasCompression && missing < 1)) return null;
  const words = [...left, ...new Array(missing).fill(0), ...right];
  if (words.length !== 8) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i += 1) {
    bytes[i * 2] = (words[i] >>> 8) & 0xff;
    bytes[i * 2 + 1] = words[i] & 0xff;
  }
  // 1.0.1.1 -> IPv4-mapped check
  let mapped = true;
  for (let i = 0; i < 10; i += 1) if (bytes[i] !== 0) mapped = false;
  if (mapped && bytes[10] === 0xff && bytes[11] === 0xff) {
    return { family: 1, bytes: bytes.slice(12) };
  }
  return { family: 2, bytes };
}

export function isGlobalUnicast(ip) {
  return ip ? (ip.family === 1 ? isIpv4GlobalUnicast(ip.bytes) : isV6GlobalUnicast(ip.bytes)) : false;
}

/**
 * Derive the client subnet to advertise via ECS.
 * - Extracts a global-unicast IP from the trusted Cloudflare header.
 * - Masks it to a prefix (config: v4 and v6 prefixes, e.g. 24 and 56).
 * Returns { family, bytes, network, prefixLength } or null.
 */
export function subnetForEcs(cfConnectingIp, ipv4Prefix, ipv6Prefix) {
  if (!cfConnectingIp) return null;
  const ip = parseIpString(cfConnectingIp);
  if (ip === null || !isGlobalUnicast(ip)) return null;
  const prefixLength = ip.family === 1 ? ipv4Prefix : ipv6Prefix;
  const network = ip.bytes.slice();
  const whole = Math.floor(prefixLength / 8);
  const rem = prefixLength % 8;
  if (rem !== 0) network[whole] = network[whole] & (0xff << (8 - rem));
  network.fill(0, whole + (rem === 0 ? 0 : 1));
  return { family: ip.family, bytes: ip.bytes, network, prefixLength };
}