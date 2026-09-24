/* =========================================================================
 *  Same-origin browser check — probe endpoint gate
 *
 *  /api/traceroute, /api/portscan and /api/osdetect trigger real network
 *  operations (ICMP/TCP probes, an nmap run via sudo) against an IP the
 *  server resolves itself. There are no user accounts, so there is nothing
 *  to authenticate a request against — this module does NOT do that. What
 *  it does is check that the request's Origin (or, failing that, Referer)
 *  header names this site's own Host, so an arbitrary third-party web page
 *  can't drive a visitor's browser into calling these endpoints cross-origin
 *  (a CSRF-style abuse path) and rack up probes against strangers on the
 *  visitor's behalf.
 *
 *  Origin/Referer are ordinary request headers. A real browser sets them and
 *  won't let script on a foreign page forge them for this app's origin, but
 *  any non-browser client (curl, a script, a bot) can set either header to
 *  anything it likes. So this check is worthless against a direct, scripted,
 *  or forged request — it only constrains what an unrelated *browser tab*
 *  can be tricked into doing. Do not present this as authentication and do
 *  not rely on it as the only defense against probe abuse; that job belongs
 *  to the per-IP rate limiter (`probeLimited` / `makeRateLimiter`) and the
 *  server-derived, validated probe target (`resolveProbeTarget`), both in
 *  server.js.
 *
 *  One consumer: server.js, called immediately after the rate limiter at
 *  the top of each of the three probe route handlers.
 *
 *  No dependencies: global URL only.
 * ========================================================================= */

export function requireSameOriginBrowserRequest(req, res) {
  const origin = req.headers.origin || req.headers.referer;
  let ok = false;
  if (origin) {
    try {
      ok = new URL(origin).host === req.headers.host;
    } catch {
      ok = false;
    }
  }
  if (!ok) {
    res.status(403).json({ available: false, reason: "forbidden: request must come from this site" });
  }
  return !ok;
}
