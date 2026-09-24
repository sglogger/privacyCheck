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

test("same-origin via Origin header is allowed", () => {
  const req = { headers: { origin: "https://example.com", host: "example.com" } };
  const res = makeRes();
  assert.equal(requireSameOriginBrowserRequest(req, res), false);
  assert.equal(res.statusCode, null);
});

test("same-origin via Referer header (no Origin) is allowed", () => {
  const req = { headers: { referer: "https://example.com/page", host: "example.com" } };
  const res = makeRes();
  assert.equal(requireSameOriginBrowserRequest(req, res), false);
  assert.equal(res.statusCode, null);
});

test("foreign Origin is rejected with 403 and the expected body", () => {
  const req = { headers: { origin: "https://evil.example", host: "example.com" } };
  const res = makeRes();
  assert.equal(requireSameOriginBrowserRequest(req, res), true);
  assert.equal(res.statusCode, 403);
  assert.deepEqual(res.body, { available: false, reason: "forbidden: request must come from this site" });
});

test("foreign Referer (no Origin) is rejected", () => {
  const req = { headers: { referer: "https://evil.example/x", host: "example.com" } };
  const res = makeRes();
  assert.equal(requireSameOriginBrowserRequest(req, res), true);
  assert.equal(res.statusCode, 403);
});

test("missing Origin and Referer is rejected", () => {
  const req = { headers: { host: "example.com" } };
  const res = makeRes();
  assert.equal(requireSameOriginBrowserRequest(req, res), true);
  assert.equal(res.statusCode, 403);
});

test("unparsable Origin value is rejected (exercises the catch branch)", () => {
  const req = { headers: { origin: "not a url", host: "example.com" } };
  const res = makeRes();
  assert.equal(requireSameOriginBrowserRequest(req, res), true);
  assert.equal(res.statusCode, 403);
});

// Known/intended limitation, not a bug: this check only inspects header
// *values*. A non-browser client (curl, a script, a bot) is free to set
// Origin to whatever it wants, including a value that matches Host exactly.
// Such a request sails through this check — because the check's job is to
// stop a *foreign browser tab* from driving a cross-origin request, not to
// verify who or what is actually making the call. It is not authentication,
// and callers must not treat a pass here as proof of anything about the
// caller's identity. The real abuse controls are the per-IP rate limiter
// and the server-derived probe target in server.js.
test("a forged same-origin header from a non-browser script still passes (documented limitation, not authentication)", () => {
  const scriptedRequest = { headers: { origin: "https://example.com", host: "example.com" } };
  const res = makeRes();
  assert.equal(requireSameOriginBrowserRequest(scriptedRequest, res), false);
});
