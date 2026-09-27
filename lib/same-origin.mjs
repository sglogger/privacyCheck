/* =========================================================================
 *  Same-origin browser check — probe endpoint gate
 *
 *  /api/traceroute, /api/portscan and /api/osdetect trigger real network
 *  operations (ICMP/TCP probes, an nmap run via sudo) against an IP the
 *  server resolves itself. There are no user accounts, so there is nothing
 *  to authenticate a request against — this module does NOT do that. It only
 *  stops an arbitrary third-party web page from driving a visitor's browser
 *  into calling these endpoints cross-site.
 *
 *  Decision order:
 *    1. Sec-Fetch-Site (sent by all current browsers, not forgeable by page
 *       script): reject only "cross-site".
 *    2. Older browsers without it: if Origin (or Referer) is present, its
 *       hostname must match req.hostname (which honours X-Forwarded-Host
 *       from a trusted proxy, see TRUST_PROXY). Ports are ignored so a proxy
 *       rewriting Host to 127.0.0.1:3010 can't cause a false mismatch.
 *    3. No such headers at all: allowed. Non-browser clients can forge any
 *       of these headers anyway, so rejecting their absence would only lock
 *       out visitors whose browser/extension/proxy strips Referer.
 *
 *  The real defences against probe abuse are the per-IP rate limiter
 *  (`probeLimited` / `makeRateLimiter`) and the server-derived, validated
 *  probe target (`resolveProbeTarget`), both in server.js.
 *
 *  One consumer: server.js, called before the rate limiter at the top of
 *  each probe route so rejected requests don't burn the visitor's quota.
 *
 *  No dependencies: global URL only.
 * ========================================================================= */

export function requireSameOriginBrowserRequest(req, res) {
  let foreign = false;
  const site = req.headers["sec-fetch-site"];
  if (site) {
    foreign = site === "cross-site";
  } else {
    const src = req.headers.origin || req.headers.referer;
    if (src) {
      try {
        foreign = new URL(src).hostname !== req.hostname;
      } catch {
        foreign = true;
      }
    }
  }
  if (foreign) {
    res.status(403).json({ available: false, reason: "forbidden: request must come from this site" });
  }
  return foreign;
}
