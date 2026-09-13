import assert from "node:assert/strict";
import worker from "../src/worker.js";

async function testLandingAndCors() {
  console.log("=== landing.cors.mjs ===");

  // 1. OPTIONS request to /doh
  const optReq = new Request("https://doh.example.com/doh", {
    method: "OPTIONS",
    headers: {
      Origin: "https://example.org",
      "Access-Control-Request-Method": "POST",
    },
  });
  const optResp = await worker.fetch(optReq, {});
  assert.equal(optResp.status, 204, "OPTIONS returns 204");
  assert.equal(optResp.headers.get("Access-Control-Allow-Origin"), "*", "CORS allow-origin *");
  assert.ok(optResp.headers.get("Access-Control-Allow-Methods").includes("POST"), "CORS methods include POST");
  console.log("  ok - OPTIONS preflight handles CORS with 204");

  // 2. Browser GET / returns HTML Landing Page
  const htmlReq = new Request("https://doh.example.com/", {
    method: "GET",
    headers: {
      Accept: "text/html,application/xhtml+xml",
    },
  });
  const htmlResp = await worker.fetch(htmlReq, {});
  assert.equal(htmlResp.status, 200, "Landing page returns 200");
  assert.ok(htmlResp.headers.get("Content-Type").includes("text/html"), "Content-type is text/html");
  const htmlText = await htmlResp.text();
  assert.ok(htmlText.includes("cf-doh"), "HTML contains cf-doh title");
  assert.ok(htmlText.includes("在线解析测试台"), "HTML contains playground");
  console.log("  ok - browser request to / serves rich HTML web console");

  // 3. CLI request (curl/text) to / returns formatted plaintext guide
  const cliReq = new Request("https://doh.example.com/", {
    method: "GET",
    headers: {
      Accept: "text/plain",
    },
  });
  const cliResp = await worker.fetch(cliReq, {});
  assert.equal(cliResp.status, 200, "CLI guide returns 200");
  assert.ok(cliResp.headers.get("Content-Type").includes("text/plain"), "Content-type is text/plain");
  const cliText = await cliResp.text();
  assert.ok(cliText.includes("RFC 8484 DoH Query"), "Plaintext contains endpoints");
  console.log("  ok - curl/plain request to / serves clean text instructions");

  console.log("\n3 passed, 0 failed\n");
}

testLandingAndCors();
