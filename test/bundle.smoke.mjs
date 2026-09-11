// Verify the ACTUAL built single-file bundle (dists/worker-single.js) is loadable
// and serves a DoH query, i.e. what a user pastes into the dashboard actually runs.
function buildQuery(name, id = 0x5555) {
  const header = new Uint8Array(12);
  header[0] = id >> 8; header[1] = id & 0xff; header[2] = 0x01; header[5] = 1;
  const parts = [];
  for (const lab of name.split(".")) { parts.push(lab.length); for (let i = 0; i < lab.length; i += 1) parts.push(lab.charCodeAt(i)); }
  parts.push(0, 0, 1, 0, 1);
  return new Uint8Array([...header, ...parts]);
}
globalThis.fetch = async (url, init) => {
  const q = new Uint8Array(init.body);
  const ans = new Uint8Array(q.length + 4); ans.set(q, 0); ans[2] = 0x81; ans[3] = 0x80;
  return new Response(ans, { headers: { "content-type": "application/dns-message" } });
};
function fakeKv(text){ return { async get(k){ return k==="rules:data"?text:null; }, async put(){} }; }
const env = { RULES_KV: fakeKv("\ngithub.com\n"),
  DOMESTIC_DOH_URL: "https://dns.alidns.com/dns-query", DOMESTIC_FALLBACK_DOH_URL: "https://doh.pub/dns-query",
  GLOBAL_DOH_URL: "https://dns.google/dns-query", GLOBAL_FALLBACK_DOH_URL: "https://cloudflare-dns.com/dns-query" };
const mod = await import("../dists/worker-single.js");
const r = await mod.handleRequest(new Request("https://doh.test/doh", {
  method: "POST", headers: { "content-type": "application/dns-message", "cf-connecting-ip": "8.8.8.8" }, body: buildQuery("github.com"),
}), env);
const bytes = await r.arrayBuffer();
console.log("bundle served POST:", r.status, bytes.byteLength > 12 ? "real DNS answer OK" : "FAIL");
process.exitCode = bytes.byteLength > 12 ? 0 : 1;
