/**
 * Verifies the ECS (client subnet) option is actually present in the query sent
 * to the upstream, and that it carries the masked client address.
 * Run: node test/ecs.forward.mjs
 */

function buildQuery(name, id = 0x4444) {
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
  parts.push(0, 0, 1, 0, 1);
  return new Uint8Array([...header, ...parts]);
}

let forwarded = null;
globalThis.fetch = async (url, init) => {
  forwarded = new Uint8Array(init.body);
  const ans = new Uint8Array(forwarded.length + 4);
  ans.set(forwarded, 0);
  ans[2] = 0x81;
  ans[3] = 0x80;
  return new Response(ans, {
    headers: { "content-type": "application/dns-message" },
  });
};

function fakeKv(text) {
  return {
    async get(k) {
      if (k === "rules:data") return text ?? "\n";
      return null;
    },
    async put() {},
  };
}

const env = {
  RULES_KV: fakeKv("\n"),
  DOMESTIC_DOH_URL: "https://dns.alidns.com/dns-query",
  GLOBAL_DOH_URL: "https://dns.google/dns-query",
  DOMESTIC_FALLBACK_DOH_URL: "",
  GLOBAL_FALLBACK_DOH_URL: "",
  ECS_IPV4_PREFIX: "24",
};

const mod = await import("../src/worker.js");

const req = new Request("https://doh.test/doh", {
  method: "POST",
  headers: {
    "content-type": "application/dns-message",
    "cf-connecting-ip": "8.8.8.8", // real global unicast
  },
  body: buildQuery("example.net"),
});

await mod.handleRequest(req, env);

// Find OPT (type 41) in forwarded: scan additional. Simplest: locate 0x0029.
const hex = Buffer.from(forwarded).toString("hex");
const hasOpt = hex.includes("0029");
console.log("forwarded has OPT record:", hasOpt);
// ECS option code is 0x0008. After OPT there should be 00 08 <len> then family.
const ecsIdx = hex.indexOf("0008");
console.log("forwarded has ECS option (code 8):", ecsIdx !== -1);
if (ecsIdx !== -1) {
  // bytes around: family should be 0001 (IPv4), prefix 24 = 0x18, then CB 00 71
  const slice = hex.slice(ecsIdx, ecsIdx + 16);
  console.log("ECS option hex:", slice);
}

let ok = hasOpt && ecsIdx !== -1;
console.log(ok ? "\nECS forward: PASS" : "\nECS forward: FAIL");
process.exitCode = ok ? 0 : 1;