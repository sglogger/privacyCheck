import { test } from "node:test";
import assert from "node:assert/strict";
import { requireSameOriginBrowserRequest } from "../lib/same-origin.mjs";

function makeRes() {
  return {
    statusCode: null,
    body: null,
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
  };
}

// req.hostname is what Express derives from Host / trusted X-Forwarded-Host.
function makeReq(headers, hostname = "example.com") {
  return { headers, hostname };
}

function check(req) {
  const res = makeRes();
  return { blocked: requireSameOriginBrowserRequest(req, res), res };
}

test("Sec-Fetch-Site same-origin is allowed", () => {
  assert.equal(check(makeReq({ "sec-fetch-site": "same-origin" })).blocked, false);
});

test("Sec-Fetch-Site none (typed URL / bookmark) is allowed", () => {
  assert.equal(check(makeReq({ "sec-fetch-site": "none" })).blocked, false);
});

test("Sec-Fetch-Site cross-site is rejected with 403 and the expected body", () => {
  const { blocked, res } = check(makeReq({ "sec-fetch-site": "cross-site", origin: "https://evil.example" }));
  assert.equal(blocked, true);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { available: false, reason: "forbidden: request must come from this site" });
});

test("Sec-Fetch-Site wins over a mismatching Origin (proxy rewrote Host)", () => {
  const req = makeReq({ "sec-fetch-site": "same-origin", origin: "https://example.com" }, "127.0.0.1");
  assert.equal(check(req).blocked, false);
});

test("legacy browser: same-origin Origin is allowed, port ignored", () => {
  assert.equal(check(makeReq({ origin: "https://example.com:8443" })).blocked, false);
});

test("legacy browser: same-origin Referer (no Origin) is allowed", () => {
  assert.equal(check(makeReq({ referer: "https://example.com/page" })).blocked, false);
});

test("legacy browser: foreign Origin is rejected", () => {
  const { blocked, res } = check(makeReq({ origin: "https://evil.example" }));
  assert.equal(blocked, true);
  assert.equal(res.statusCode, 403);
});

test("legacy browser: foreign Referer (no Origin) is rejected", () => {
  assert.equal(check(makeReq({ referer: "https://evil.example/x" })).blocked, true);
});

test("unparsable Origin value is rejected", () => {
  assert.equal(check(makeReq({ origin: "not a url" })).blocked, true);
});

test("no Sec-Fetch-Site, Origin or Referer is allowed (stripped Referer, curl)", () => {
  const { blocked, res } = check(makeReq({}));
  assert.equal(blocked, false);
  assert.equal(res.statusCode, null);
});
