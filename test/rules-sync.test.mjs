import assert from "node:assert/strict";
import worker from "../src/worker.js";
import { isDomestic, resetRules, ensureRules } from "../src/rules.js";

async function testRulesSync() {
  console.log("=== rules-sync.test.mjs ===");
  resetRules();

  const mockKvStorage = new Map();
  const mockKv = {
    async get(key) {
      return mockKvStorage.get(key) || null;
    },
    async put(key, val) {
      mockKvStorage.set(key, val);
    },
  };

  const envWithSecret = {
    RULES_SYNC_SECRET: "test-secret-123",
    RULES_KV: mockKv,
  };

  // 1. GET /api/rules/sync is refused with 405
  const getReq = new Request("https://doh.example.com/api/rules/sync", { method: "GET" });
  const getResp = await worker.fetch(getReq, envWithSecret);
  assert.equal(getResp.status, 405);
  console.log("  ok - GET /api/rules/sync returns 405 Method Not Allowed");

  // 2. No RULES_SYNC_SECRET configured on server returns 403
  const noSecretReq = new Request("https://doh.example.com/api/rules/sync", { method: "POST" });
  const noSecretResp = await worker.fetch(noSecretReq, {});
  assert.equal(noSecretResp.status, 403);
  console.log("  ok - unconfigured secret returns 403 Forbidden");

  // 3. Wrong secret returns 401
  const wrongAuthReq = new Request("https://doh.example.com/api/rules/sync", {
    method: "POST",
    headers: { Authorization: "Bearer wrong-token" },
    body: "foo.com",
  });
  const wrongAuthResp = await worker.fetch(wrongAuthReq, envWithSecret);
  assert.equal(wrongAuthResp.status, 401);
  console.log("  ok - wrong secret token returns 401 Unauthorized");

  // 4. Corrupted/HTML content is rejected with 400
  const htmlReq = new Request("https://doh.example.com/api/rules/sync", {
    method: "POST",
    headers: { Authorization: "Bearer test-secret-123" },
    body: "<html><body>Error 404</body></html>",
  });
  const htmlResp = await worker.fetch(htmlReq, envWithSecret);
  assert.equal(htmlResp.status, 400);
  console.log("  ok - HTML rule payload rejected with 400 Bad Request");

  // 5. Valid push rule text updates KV and in-memory live ruleset
  const validRules = `
# Personal overrides
linux.do
full:custom-site.cn
my-special-domain.internal
`;
  const pushReq = new Request("https://doh.example.com/api/rules/sync", {
    method: "POST",
    headers: {
      Authorization: "Bearer test-secret-123",
      "Content-Type": "text/plain",
    },
    body: validRules,
  });
  const pushResp = await worker.fetch(pushReq, envWithSecret);
  assert.equal(pushResp.status, 200);
  const pushJson = await pushResp.json();
  assert.equal(pushJson.ok, true);
  assert.equal(pushJson.mode, "push");
  assert.ok(pushJson.rulesCount >= 3);
  assert.ok(mockKvStorage.has("rules:data"), "rules persisted to KV");
  console.log("  ok - valid rules pushed, written to KV, and adopted into memory");

  // 6. Verify that newly pushed rules route correctly
  const liveRules = await ensureRules(envWithSecret);
  assert.equal(isDomestic("sub.my-special-domain.internal", liveRules), true);
  assert.equal(isDomestic("custom-site.cn", liveRules), true);
  assert.equal(isDomestic("foreign-unknown-domain.net", liveRules), false);
  console.log("  ok - newly pushed domain rules route immediately as domestic");

  // 7. JSON payload mode
  const jsonReq = new Request("https://doh.example.com/api/rules/sync", {
    method: "POST",
    headers: {
      "X-Rules-Secret": "test-secret-123",
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ rules: "json-synced-domain.com\n" }),
  });
  const jsonResp = await worker.fetch(jsonReq, envWithSecret);
  assert.equal(jsonResp.status, 200);
  const updatedLiveRules = await ensureRules(envWithSecret);
  assert.equal(isDomestic("json-synced-domain.com", updatedLiveRules), true);
  console.log("  ok - JSON body payload successfully parsed and applied");

  console.log("\n7 passed, 0 failed\n");
}

testRulesSync();
