/**
 * EDNS Client Subnet (ECS) option construction per RFC 7871.
 *
 * We build the raw RDATA for option code 8:
 *   FAMILY(2) SOURCE-PREFIX-LENGTH(1) SCOPE-PREFIX-LENGTH(1) ADDRESS(variable)
 * ADDRESS carries the high-order `sourcePrefixLength` bits of the client IP.
 */

export const ECS_OPTION_CODE = 8;
export const DEFAULT_UDP_PAYLOAD_SIZE = 1232;

/** Build the RDATA bytes for an ECS option, or null when no subnet is usable. */
export function encodeEcsRdata(family, networkBytes, prefixLength) {
  const addrLen = Math.ceil(prefixLength / 8);
  const rdata = new Uint8Array(4 + addrLen);
  // FAMILY
  rdata[0] = (family >> 8) & 0xff;
  rdata[1] = family & 0xff;
  // SOURCE-PREFIX
  rdata[2] = prefixLength;
  // SCOPE 0 (meaning: resolver has no authoritative scope info)
  rdata[3] = 0;
  rdata.set(networkBytes.subarray(0, addrLen), 4);
  return rdata;
}

/** Wrap ECS RDATA into a full EDNS0 option entry (code + len + rdata). */
export function wrapEcsOption(rdata) {
  const out = new Uint8Array(2 + 2 + rdata.length);
  out[0] = (ECS_OPTION_CODE >> 8) & 0xff;
  out[1] = ECS_OPTION_CODE & 0xff;
  out[2] = (rdata.length >> 8) & 0xff;
  out[3] = rdata.length & 0xff;
  out.set(rdata, 4);
  return out;
}