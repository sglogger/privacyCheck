import express from "express";
import net from "node:net";
import os from "node:os";
import fs from "node:fs";
import { promises as dns } from "node:dns";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import path from "node:path";
import { fileURLToPath } from "node:url";

// execFile (no shell) so a spoofed X-Forwarded-For can never inject commands.
const execFileAsync = promisify(execFile);
const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const PORT = process.env.PORT || 3000;

// We sit behind whatever proxy/load balancer; trust the chain so req.ip is meaningful.
app.set("trust proxy", true);

// Apache "combined" access log to stdout (-> docker logs). Disable with LOG_REQUESTS=false.
const LOG_REQUESTS = process.env.LOG_REQUESTS !== "false";

// Optionally also append every log line to a file so it survives container
// restarts (docker logs are ephemeral). Set LOG_FILE to a path; mount that path
// as a volume to persist it on the host. Empty (default) = stdout only.
const LOG_FILE = process.env.LOG_FILE || "";
const logStream = LOG_FILE
  ? fs.createWriteStream(LOG_FILE, { flags: "a" })
  : null;
if (logStream) {
  logStream.on("error", (err) =>
    console.error(`log file ${LOG_FILE} write error: ${err.message}`)
  );
}

// Per-visitor report files. Auto-derived from LOG_FILE's directory when not set
// explicitly; empty = skip file writing (reports still appear in stdout/LOG_FILE).
const REPORT_DIR = process.env.REPORT_DIR ||
  (LOG_FILE ? path.join(path.dirname(path.resolve(LOG_FILE)), "reports") : "");
if (REPORT_DIR) fs.mkdirSync(REPORT_DIR, { recursive: true });

// Single sink for the access/exec/client audit lines: always stdout, plus the
// log file when LOG_FILE is set.
function logLine(line) {
  console.log(line);
  if (logStream) logStream.write(line + "\n");
}

if (LOG_REQUESTS) {
  app.use((req, res, next) => {
    res.on("finish", () => {
      const ip = clientIpOf(req); // real client (forwarded) — shown as "Client IP" on the page
      // Skip the container's own health-check noise (local probe of /api/healthz).
      if (req.path === "/api/healthz" && isPrivateOrLocal(ip)) return;
      const direct = directIpOf(req); // the TCP peer we actually talk to (Traefik/proxy) — "Direct peer"
      const reqLine = `${req.method} ${req.originalUrl} HTTP/${req.httpVersion}`;
      const len = res.getHeader("content-length") || "-";
      const ref = req.headers["referer"] || "-";
      const ua = req.headers["user-agent"] || "-";
      // %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" via=<direct peer>
      logLine(`${ip} - - [${apacheDate(new Date())}] "${reqLine}" ${res.statusCode} ${len} "${ref}" "${ua}" via=${direct}`);
    });
    next();
  });
}

// Security headers. Deliberately NOT set: Referrer-Policy — index.html opts
// into `unsafe-url` via <meta> because leaking the referrer is part of the
// demo. The CSP must stay permissive where the recon features need it: the
// google-analytics fetch (ad-blocker test — if *we* blocked it, every visitor
// would appear to run a blocker), the 127.0.0.1/localhost fetches (localhost
// port scan) and the OpenStreetMap map embeds.
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'", // the adblock bait element uses an inline style attribute
  "img-src 'self' data:",
  "connect-src 'self' https://api.ipify.org https://api64.ipify.org https://www.google-analytics.com http://127.0.0.1:* http://localhost:*",
  "frame-src https://www.openstreetmap.org",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "frame-ancestors 'self'",
].join("; ");
app.use((_req, res, next) => {
  res.set("Content-Security-Policy", CSP);
  res.set("X-Content-Type-Options", "nosniff");
  res.set("X-Frame-Options", "SAMEORIGIN");
  next();
});

app.use(express.static(path.join(__dirname, "public")));
app.use(express.json({ limit: "16kb" }));

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

// Normalize the IPv4-mapped IPv6 form (::ffff:1.2.3.4) to plain IPv4.
function normalizeIp(ip) {
  if (!ip) return ip;
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

// Timestamp in Apache log format: [dd/Mon/yyyy:HH:mm:ss +ZZZZ]
const APACHE_MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
function apacheDate(d) {
  const p = (n, l = 2) => String(n).padStart(l, "0");
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const oh = p(Math.floor(Math.abs(off) / 60));
  const om = p(Math.abs(off) % 60);
  return `${p(d.getDate())}/${APACHE_MONTHS[d.getMonth()]}/${d.getFullYear()}:${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())} ${sign}${oh}${om}`;
}

// Strict IPv4/IPv6 validation via the kernel-grade parser (net.isIP), NOT a
// regex. A homegrown "hex + colons" regex accepts strings that merely *look*
// like an address (e.g. "a:b") — and since anything passing this gate is handed
// to a root `sudo nmap` / traceroute as an argv token, validation and the sink
// MUST agree that the value is a real address. net.isIP returns 4, 6, or 0.
function isValidIp(ip) {
  if (!ip) return false;
  return net.isIP(normalizeIp(ip)) !== 0;
}

function isPrivateOrLocal(ip) {
  if (!ip) return true;
  const v = normalizeIp(ip);
  return (
    v === "127.0.0.1" ||
    v === "::1" ||
    v === "localhost" ||
    v.startsWith("10.") ||
    v.startsWith("192.168.") ||
    v.startsWith("169.254.") ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(v) ||
    v.startsWith("fc") ||
    v.startsWith("fd") ||
    v.startsWith("fe80")
  );
}

// --- IPv4 CIDR matching, used to mask configured "boring" leading hops ---
function ipv4ToInt(ip) {
  const parts = normalizeIp(ip || "").split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const o of parts) {
    const v = Number(o);
    if (!Number.isInteger(v) || v < 0 || v > 255) return null;
    n = n * 256 + v;
  }
  return n >>> 0;
}
function ipInCidr(ip, cidr) {
  const [range, bitsStr] = String(cidr).split("/");
  const bits = Number(bitsStr);
  const ipN = ipv4ToInt(ip);
  const rN = ipv4ToInt(range);
  if (ipN == null || rN == null || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  if (bits === 0) return true;
  const mask = (~((1 << (32 - bits)) - 1)) >>> 0;
  return (ipN & mask) === (rN & mask);
}

// Traceroute hop-masking config (env-overridable):
//   TRACEROUTE_HIDE_PRIVATE  "false" to keep private/RFC1918 leading hops (default: hide)
//   TRACEROUTE_HIDE_RANGES   comma-separated CIDRs to also hide (default: 193.239.20.0/22)
const TR_HIDE_PRIVATE = process.env.TRACEROUTE_HIDE_PRIVATE !== "false";
const TR_HIDE_RANGES = (process.env.TRACEROUTE_HIDE_RANGES ?? "193.239.20.0/22")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

// A leading hop is masked if it's private (when enabled) or inside a hide-range.
function hopShouldHide(ip) {
  if (!ip) return false; // an unanswered (*) hop ends the trimming
  if (TR_HIDE_PRIVATE && isPrivateOrLocal(ip)) return true;
  return TR_HIDE_RANGES.some((c) => ipInCidr(ip, c));
}

// Parse the full X-Forwarded-For chain so we can show every hop.
function forwardedChain(req) {
  const xff = req.headers["x-forwarded-for"];
  if (!xff) return [];
  return xff
    .split(",")
    .map((s) => normalizeIp(s.trim()))
    .filter(Boolean);
}

// Best guess at the requesting client's IP (used for both access + exec logs).
function clientIpOf(req) {
  const chain = forwardedChain(req);
  return (
    chain[0] ||
    normalizeIp(req.headers["cf-connecting-ip"]) ||
    normalizeIp(req.socket.remoteAddress) ||
    "-"
  );
}

// The direct TCP peer (e.g. Traefik/CDN) — not the real client when proxied.
function directIpOf(req) {
  return normalizeIp(req.socket.remoteAddress) || "-";
}

// The OS user the node process runs as (for the "who is executing" audit log).
const RUN_USER = (() => {
  try {
    return os.userInfo().username;
  } catch {
    return typeof process.getuid === "function" ? `uid:${process.getuid()}` : "unknown";
  }
})();

// Audit log for server-side command execution: which client triggered it, which
// local user runs it, and the exact argv. Goes to stdout -> docker logs.
function logExec(req, argv) {
  if (!LOG_REQUESTS) return;
  const cmd = Array.isArray(argv) ? argv.join(" ") : String(argv);
  logLine(`${clientIpOf(req)} - - [${apacheDate(new Date())}] EXEC (as ${RUN_USER}) ${cmd} via=${directIpOf(req)}`);
}

async function reverseDns(ip) {
  if (!ip || isPrivateOrLocal(ip) || !isValidIp(ip)) return null;
  try {
    const names = await dns.reverse(normalizeIp(ip));
    return names && names.length ? names : null;
  } catch {
    return null;
  }
}

// Validate a hostname before it is handed to the resolver — keeps this from
// becoming an open DNS-lookup proxy for arbitrary attacker-supplied strings.
function isValidHostname(h) {
  return (
    typeof h === "string" &&
    h.length > 0 &&
    h.length <= 253 &&
    /^(?=.{1,253}$)([a-z0-9_-]{1,63})(\.[a-z0-9_-]{1,63})+\.?$/i.test(h)
  );
}

// Forward DNS records for a hostname (only A/AAAA/CNAME/MX/NS/TXT/SOA).
async function dnsRecords(host) {
  const want = [
    ["A", "resolve4"],
    ["AAAA", "resolve6"],
    ["CNAME", "resolveCname"],
    ["MX", "resolveMx"],
    ["NS", "resolveNs"],
    ["TXT", "resolveTxt"],
    ["SOA", "resolveSoa"],
  ];
  const out = {};
  await Promise.all(
    want.map(async ([label, fn]) => {
      try {
        const r = await dns[fn](host);
        if (label === "MX") out.MX = r.map((m) => `${m.priority} ${m.exchange}`);
        else if (label === "TXT") out.TXT = r.map((parts) => parts.join(""));
        else if (label === "SOA") out.SOA = r ? `${r.nsname} ${r.hostmaster} serial=${r.serial}` : null;
        else out[label] = r;
      } catch {
        out[label] = null;
      }
    })
  );
  return out;
}

// Free, key-less geo/ASN lookup. 45 req/min limit — fine for a demo.
async function geoLookup(ip) {
  const fields =
    "status,message,continent,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query";
  // For local/private/invalid IPs ip-api resolves the *server's* public IP.
  // Only a strictly-validated IP is ever placed in the URL; encodeURIComponent
  // is belt-and-suspenders so a spoofed header can't tamper with the request.
  const target = !ip || isPrivateOrLocal(ip) || !isValidIp(ip) ? "" : normalizeIp(ip);
  try {
    const res = await fetch(`http://ip-api.com/json/${encodeURIComponent(target)}?fields=${fields}`, {
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return { status: "fail", message: `HTTP ${res.status}` };
    const data = await res.json();
    if (data && isPrivateOrLocal(ip)) data._note = "Local request — showing the server's public IP geolocation.";
    return data;
  } catch (err) {
    return { status: "fail", message: String(err?.message || err) };
  }
}

// Tor exit-node detection via the official bulk exit list, cached in memory.
const TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist";
const TOR_TTL_MS = 60 * 60 * 1000; // refresh hourly
let torCache = { set: null, fetchedAt: 0, error: null };

async function getTorExitSet() {
  const now = Date.now();
  if (torCache.set && now - torCache.fetchedAt < TOR_TTL_MS) return torCache;
  try {
    const res = await fetch(TOR_LIST_URL, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const text = await res.text();
    const set = new Set(
      text.split("\n").map((l) => l.trim()).filter((l) => l && !l.startsWith("#"))
    );
    torCache = { set, fetchedAt: now, error: null };
  } catch (err) {
    // Keep any stale set we already have; only record the error.
    torCache = {
      set: torCache.set,
      fetchedAt: torCache.set ? torCache.fetchedAt : now,
      error: String(err?.message || err),
    };
  }
  return torCache;
}

async function torCheck(ip) {
  if (!ip || isPrivateOrLocal(ip)) return { available: false, isExitNode: false, reason: "private/local IP" };
  const cache = await getTorExitSet();
  if (!cache.set) return { available: false, isExitNode: false, reason: "exit list unavailable: " + (cache.error || "unknown") };
  return {
    available: true,
    isExitNode: cache.set.has(normalizeIp(ip)),
    listSize: cache.set.size,
    listUpdated: new Date(cache.fetchedAt).toISOString(),
    stale: !!cache.error,
  };
}

// The server's own public IP, cached. Used as the probe target when the request
// comes from a private/local address (e.g. localhost dev) so traceroute / port
// scan / nmap still produce real output instead of bailing out.
let pubIpCache = { ip: null, at: 0 };
async function getServerPublicIp() {
  const now = Date.now();
  if (pubIpCache.ip && now - pubIpCache.at < 600000) return pubIpCache.ip;
  try {
    const res = await fetch("http://ip-api.com/json/?fields=query", { signal: AbortSignal.timeout(4000) });
    const d = await res.json();
    if (d && isValidIp(d.query)) pubIpCache = { ip: d.query, at: now };
  } catch {
    /* keep stale value if any */
  }
  return pubIpCache.ip;
}

// Resolve the effective probe target: the real public client IP, or — for
// local/private requests — the server's own public IP (with an explanatory
// note). Returns { ip, note } or { error } for genuinely invalid input.
async function resolveProbeTarget(rawIp) {
  if (isPrivateOrLocal(rawIp)) {
    const pub = await getServerPublicIp();
    if (pub && isValidIp(pub)) {
      return { ip: pub, note: "Local request — probing the server's own public IP instead of the private LAN address." };
    }
    return { error: "Client IP is private/local and the server's public IP couldn't be determined." };
  }
  if (!isValidIp(rawIp)) return { error: "Client IP is not a valid IP address." };
  const ip = normalizeIp(rawIp);
  // Defense in depth: a real IP can never start with "-", but guard anyway so a
  // future loosening of validation can't let a token be read as an nmap/
  // traceroute flag (argument injection into the root-privileged sink).
  if (ip.startsWith("-")) return { error: "Refusing option-like probe target." };
  return { ip, note: null };
}

// Per-IP sliding-window rate limiter factory (in-memory). Two instances below:
// a tight one for the expensive active probes (traceroute/nmap/portscan), so
// the server can't be abused as a root-privileged scan reflector, and a looser
// one for the cheap DNS endpoints, so they can't serve as an anonymous lookup
// relay. Tune via PROBE_RATE_MAX / PROBE_RATE_WINDOW_MS and LOOKUP_RATE_MAX /
// LOOKUP_RATE_WINDOW_MS.
function makeRateLimiter({ max, windowMs, label }) {
  const hitsMap = new Map(); // ip -> timestamps[]
  function check(req) {
    const ip = clientIpOf(req);
    const now = Date.now();
    const hits = (hitsMap.get(ip) || []).filter((t) => now - t < windowMs);
    if (hits.length >= max) {
      hitsMap.set(ip, hits);
      return { ok: false, retry: Math.ceil((windowMs - (now - hits[0])) / 1000) };
    }
    hits.push(now);
    hitsMap.set(ip, hits);
    if (hitsMap.size > 5000) {
      for (const [k, v] of hitsMap) {
        const keep = v.filter((t) => now - t < windowMs);
        if (keep.length) hitsMap.set(k, keep);
        else hitsMap.delete(k);
      }
    }
    return { ok: true };
  }
  // Sends the 429 and returns true when the request is over the limit.
  return function limited(req, res, extra = {}) {
    const rl = check(req);
    if (rl.ok) return false;
    res.set("Retry-After", String(rl.retry));
    res.status(429).json({
      available: false,
      reason: `Rate limited — max ${max} ${label} per ${windowMs / 1000}s. Try again in ${rl.retry}s.`,
      ...extra,
    });
    return true;
  };
}

const probeLimited = makeRateLimiter({
  max: Number(process.env.PROBE_RATE_MAX || 10),
  windowMs: Number(process.env.PROBE_RATE_WINDOW_MS || 60000),
  label: "probes",
});
const lookupLimited = makeRateLimiter({
  max: Number(process.env.LOOKUP_RATE_MAX || 30),
  windowMs: Number(process.env.LOOKUP_RATE_WINDOW_MS || 60000),
  label: "DNS lookups",
});

// Curated set of "what does the request leak" headers, kept in display order.
const INTERESTING_HEADERS = [
  "host",
  "user-agent",
  "accept",
  "accept-language",
  "accept-encoding",
  "referer",
  "origin",
  "dnt",
  "sec-gpc",
  "connection",
  "upgrade-insecure-requests",
  "cache-control",
  "x-forwarded-for",
  "x-real-ip",
  "x-forwarded-proto",
  "x-forwarded-host",
  "x-forwarded-port",
  "cf-connecting-ip",
  "cf-ipcountry",
  "cf-ray",
  "true-client-ip",
  "via",
  "forwarded",
  "from",
  "sec-ch-ua",
  "sec-ch-ua-mobile",
  "sec-ch-ua-platform",
  "sec-ch-ua-platform-version",
  "sec-ch-ua-arch",
  "sec-ch-ua-model",
  "sec-ch-ua-full-version-list",
  "sec-fetch-site",
  "sec-fetch-mode",
  "sec-fetch-dest",
  "sec-fetch-user",
];

function parseAcceptLanguage(header) {
  if (!header) return [];
  return header
    .split(",")
    .map((part) => {
      const [tag, q] = part.trim().split(";q=");
      return { tag: tag.trim(), q: q ? parseFloat(q) : 1.0 };
    })
    .filter((x) => x.tag)
    .sort((a, b) => b.q - a.q);
}

// Passive OS / device guess from User-Agent + Client Hints. No probing.
function osGuess(req) {
  const ua = req.headers["user-agent"] || "";
  const chPlatform = (req.headers["sec-ch-ua-platform"] || "").replace(/"/g, "");
  const chMobile = req.headers["sec-ch-ua-mobile"] === "?1";
  const chArch = (req.headers["sec-ch-ua-arch"] || "").replace(/"/g, "");
  const chModel = (req.headers["sec-ch-ua-model"] || "").replace(/"/g, "");

  let os = chPlatform || "unknown";
  if (os === "unknown") {
    if (/Windows NT 10/.test(ua)) os = "Windows 10/11";
    else if (/Windows NT/.test(ua)) os = "Windows (older)";
    else if (/iPhone|iPad|iPod/.test(ua)) os = "iOS / iPadOS";
    else if (/Mac OS X/.test(ua)) os = "macOS";
    else if (/Android/.test(ua)) os = "Android";
    else if (/CrOS/.test(ua)) os = "ChromeOS";
    else if (/Linux/.test(ua)) os = "Linux";
  }

  let browser = "unknown";
  if (/Edg\//.test(ua)) browser = "Edge";
  else if (/OPR\//.test(ua)) browser = "Opera";
  else if (/Firefox\//.test(ua)) browser = "Firefox";
  else if (/Chrome\//.test(ua)) browser = "Chrome/Chromium";
  else if (/Safari\//.test(ua)) browser = "Safari";

  let device = chMobile ? "mobile" : "desktop";
  if (/iPad|Tablet/.test(ua)) device = "tablet";

  return { os, browser, device, arch: chArch || null, model: chModel || null };
}

// UUID v4 validation — the only shape we accept as a visitor ID.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const isValidUUID = (v) => typeof v === "string" && UUID_RE.test(v);

// Build a self-contained HTML report for a single visitor record.
function buildReportHtml(data) {
  const esc = (s) =>
    String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const tr = (label, value, cls = "") =>
    `<tr><td>${esc(label)}</td><td class="val ${cls}">${esc(value ?? "—")}</td></tr>`;
  const pill = (label, cls = "on") => `<span class="pill ${cls}">${esc(label)}</span>`;
  const pillRow = (items) =>
    items?.length ? `<div class="pills">${items.map((t) => pill(t)).join("")}</div>` : `<span class="dim">—</span>`;
  const ynBad = (v) =>
    v == null ? `<span class="dim">—</span>` : v ? `<span class="bad">yes</span>` : `<span class="good">no</span>`;
  const ynGood = (v) =>
    v == null ? `<span class="dim">—</span>` : v ? `<span class="good">yes</span>` : `<span class="dim">no</span>`;

  const visits = data.visits || [];
  const last = visits[visits.length - 1] || {};
  const first = visits[0] || {};

  // nested objects from new format; fall back to old flat fields for old visits
  const g  = last.geo          || {};
  const br = last.browser      || {};
  const sc = last.screen       || {};
  const lc = last.locale       || {};
  const st = last.storage      || {};
  const nw = last.network;
  const wg = last.webgl;
  const fp = last.fingerprints || {};
  const ab = last.adblock;
  const pm = last.permissions;
  const md = last.mediaDevices;
  const bat= last.battery;
  const wrt= last.webrtc;
  const lp = last.localPorts   || [];
  const gps= last.geolocation;

  // compat: old visits stored flat fields
  const ua          = br.userAgent         || last.ua;
  const tz          = lc.timezone          || last.timezone;
  const lang        = br.language          || last.language;
  const cores       = br.cpuCores          ?? last.cpuCores;
  const mem         = br.deviceMemory      ?? last.deviceMemory;
  const canvasHash  = fp.canvas            || last.canvasHash;
  const audioHash   = fp.audio             || last.audioHash;
  const wglRenderer = wg?.renderer         || last.webglRenderer;

  // ── Section builders ──────────────────────────────────────────────────────

  const sNet = [
    tr("Client IP", last.clientIp),
    last.directIp && last.directIp !== last.clientIp ? tr("Direct peer", last.directIp) : "",
    tr("Country",  g.country ? `${g.country} (${g.countryCode})` : null),
    tr("Region",   g.regionName),
    tr("City",     g.city),
    tr("ISP",      g.isp),
    tr("Organization", g.org),
    tr("AS",       g.as),
    `<tr><td>Protocol</td><td class="val">${esc(last.proto || "—")}</td></tr>`,
    `<tr><td>Proxy / VPN</td><td>${ynBad(g.proxy)}</td></tr>`,
    `<tr><td>Hosting / DC</td><td>${ynBad(g.hosting)}</td></tr>`,
    `<tr><td>Tor exit node</td><td>${ynBad(last.isExitNode)}</td></tr>`,
    `<tr><td>Anonymization verdict</td><td><span class="${last.isExitNode ? "bad" : g.proxy ? "warn" : g.hosting ? "warn" : "good"}">${last.isExitNode ? "🧅 Tor exit node" : g.proxy ? "🕵️ proxy / VPN detected" : g.hosting ? "🖥️ datacenter / hosting IP" : "✓ appears to be a direct residential connection"}</span></td></tr>`,
  ].join("");

  const sLangs = last.languages?.length
    ? `<div class="pills">${last.languages.map((l) => pill(`${l.tag} (q=${l.q})`)).join("")}</div><p class="note" style="margin-top:.3rem">Sent in Accept-Language header on every request.</p>`
    : `<span class="dim">No Accept-Language header received</span>`;

  const sProxy = last.proxyChain?.length
    ? `<p class="note">X-Forwarded-For chain (client → … → server):</p><pre class="pre">${last.proxyChain.map((ip, i) => `${i}. ${esc(ip)}`).join("\n")}</pre>`
    : `<p class="note dim">No X-Forwarded-For header — client appears to be connecting directly.</p>`;

  const sRdns = last.discoveredPtr?.length
    ? last.discoveredPtr.map((d) => {
        const val = d.private ? "private — no public PTR" : d.ptr?.length ? d.ptr.join(", ") : "no PTR record";
        return tr(d.ip, val, d.ptr?.length ? "" : "dim");
      }).join("")
    : `<tr><td colspan="2" class="dim">No IPs discovered</td></tr>`;

  const sDns = last.dnsRecords ? (() => {
    const r = last.dnsRecords.records || {};
    const j = (a) => a?.length ? a.join(", ") : null;
    return [
      tr("Host",  last.dnsRecords.host),
      tr("A",     j(r.A)),
      tr("AAAA",  j(r.AAAA)),
      tr("CNAME", j(r.CNAME)),
      tr("MX",    j(r.MX)),
      tr("NS",    j(r.NS)),
      tr("TXT",   r.TXT?.length ? r.TXT.join(" | ") : null),
      tr("SOA",   r.SOA),
    ].join("");
  })() : `<tr><td colspan="2" class="dim">No PTR hostname to resolve forward records for</td></tr>`;

  const sBrowser = [
    tr("User-Agent",    ua),
    tr("Platform",      br.platform),
    tr("Vendor",        br.vendor),
    tr("Languages",     lang),
    tr("CPU cores",     cores),
    tr("Device memory", mem != null ? `${mem} GB (approx)` : null),
    tr("Touch points",  br.touchPoints),
    br.onLine  != null ? `<tr><td>Online</td><td>${ynGood(br.onLine)}</td></tr>` : "",
    br.pdfViewer != null ? tr("PDF viewer", br.pdfViewer ? "yes" : "no") : "",
    br.uach ? [
      tr("UA-CH platform", [br.uach.platform, br.uach.platformVersion].filter(Boolean).join(" ") || null),
      tr("UA-CH arch",     [br.uach.architecture, br.uach.bitness ? br.uach.bitness + "-bit" : ""].filter(Boolean).join(" ") || null),
      tr("UA-CH model",    br.uach.model || null),
      br.uach.wow64 != null ? tr("WoW64", br.uach.wow64 ? "yes" : "no") : "",
      br.uach.brands?.length ? `<tr><td>Brands</td><td class="val">${pillRow(br.uach.brands)}</td></tr>` : "",
    ].join("") : "",
  ].join("");

  const sScreen = [
    tr("Resolution",    sc.w    ? `${sc.w} × ${sc.h}` : null),
    tr("Available",     sc.availW ? `${sc.availW} × ${sc.availH}` : null),
    tr("Window",        sc.windowW ? `${sc.windowW} × ${sc.windowH}` : null),
    tr("Color depth",   sc.colorDepth ? `${sc.colorDepth}-bit` : null),
    tr("Pixel ratio",   sc.dpr),
    tr("Orientation",   sc.orientation),
    tr("Color scheme",  sc.colorScheme),
    sc.reducedMotion != null ? `<tr><td>Reduced motion</td><td>${ynGood(sc.reducedMotion)}</td></tr>` : "",
    sc.hdr != null ? tr("HDR", sc.hdr ? "yes" : "no") : "",
  ].join("");

  const sLocale = [
    tr("Timezone",        tz),
    tr("UTC offset",      lc.utcOffset),
    tr("Locale",          lc.locale),
    tr("Calendar",        lc.calendar),
    tr("Numbering system",lc.numberingSystem),
  ].join("");

  const sStorage = [
    `<tr><td>Cookies</td><td>${ynBad(st.cookies)}</td></tr>`,
    tr("Do Not Track",  st.dnt || "not set"),
    `<tr><td>Global Privacy Control</td><td>${st.gpc === true ? '<span class="good">on</span>' : st.gpc === false ? '<span class="dim">off</span>' : '<span class="dim">not set</span>'}</td></tr>`,
    tr("localStorage",   st.localStorage  != null ? (st.localStorage  ? "available" : "blocked") : null),
    tr("sessionStorage", st.sessionStorage != null ? (st.sessionStorage ? "available" : "blocked") : null),
    tr("indexedDB",      st.indexedDB      != null ? (st.indexedDB      ? "available" : "blocked") : null),
    st.quota ? tr("Storage quota", `${(st.quota / 1073741824).toFixed(1)} GB`) : "",
  ].join("");

  const sNetCond = nw ? [
    tr("Connection type", nw.type),
    tr("Downlink", nw.downlink != null ? `${nw.downlink} Mbps` : null),
    tr("RTT",      nw.rtt      != null ? `${nw.rtt} ms`       : null),
    `<tr><td>Save-Data</td><td>${nw.saveData ? '<span class="warn">on</span>' : '<span class="dim">off</span>'}</td></tr>`,
  ].join("") : `<tr><td colspan="2" class="dim">Network Information API not available</td></tr>`;

  const sWebgl = wg ? [
    tr("Vendor",       wg.vendor),
    tr("Renderer",     wg.renderer || wglRenderer),
    tr("GLSL version", wg.glsl),
    tr("Max texture",  wg.maxTexture),
  ].join("") : wglRenderer ? tr("Renderer", wglRenderer) :
    `<tr><td colspan="2" class="dim">WebGL unavailable or blocked</td></tr>`;

  const sFp = [
    tr("Canvas hash", canvasHash),
    tr("Audio hash",  audioHash),
  ].join("");

  const sCaps = last.capabilities?.length
    ? `<div class="pills">${last.capabilities.map((c) => pill(c)).join("")}</div>`
    : `<span class="dim">Not reported</span>`;

  const sFonts = last.fonts?.length
    ? `<p class="note">${last.fonts.length} fonts detected:</p><div class="pills">${last.fonts.map((f) => pill(f)).join("")}</div>`
    : `<span class="dim">None detected or not reported</span>`;

  const sPlugins = last.plugins?.length
    ? `<div class="pills">${last.plugins.map((p) => pill(p)).join("")}</div>`
    : `<span class="dim">No plugins (modern browsers return an empty/stub list)</span>`;

  const sAdblock = ab ? [
    `<tr><td>Bait element hidden</td><td>${ynBad(ab.baitHidden)}</td></tr>`,
    `<tr><td>Ad script blocked</td><td>${ynBad(ab.scriptBlocked)}</td></tr>`,
    `<tr><td>Tracker request blocked</td><td>${ynBad(ab.trackerBlocked)}</td></tr>`,
    `<tr><td>Verdict</td><td>${ab.blocking ? '<span class="warn">🛑 blocker active</span>' : '<span class="good">✓ no blocker detected</span>'}</td></tr>`,
  ].join("") : `<tr><td colspan="2" class="dim">Not reported</td></tr>`;

  const sPerms = pm && Object.keys(pm).length ? Object.entries(pm).map(([k, v]) => {
    const cls = v === "granted" ? "good" : v === "denied" ? "bad" : "warn";
    return `<tr><td>${esc(k)}</td><td><span class="${cls}">${esc(v)}</span></td></tr>`;
  }).join("") : `<tr><td colspan="2" class="dim">Not reported</td></tr>`;

  const sMedia = md ? [
    tr("Microphones", md.audioinput),
    tr("Speakers",    md.audiooutput),
    tr("Cameras",     md.videoinput),
  ].join("") : `<tr><td colspan="2" class="dim">Not reported</td></tr>`;

  const sBattery = bat ? [
    tr("Level",         bat.level != null ? `${bat.level}%` : null),
    `<tr><td>Charging</td><td>${ynGood(bat.charging)}</td></tr>`,
    tr("Time to full",  bat.chargingTime    != null ? `${bat.chargingTime}s`    : "—"),
    tr("Time to empty", bat.dischargingTime != null ? `${bat.dischargingTime}s` : "—"),
  ].join("") : `<tr><td colspan="2" class="dim">Battery API unavailable</td></tr>`;

  const sWebrtc = wrt && Object.keys(wrt).length
    ? Object.entries(wrt).map(([ip, kind]) =>
        `<tr><td>${esc(ip)}</td><td><span class="${kind === "public" ? "bad" : "warn"}">${esc(kind)}</span></td></tr>`
      ).join("")
    : `<tr><td colspan="2"><span class="good">No IPs leaked (blocked or unsupported)</span></td></tr>`;

  const sLocalPorts = lp.length
    ? lp.map((p) => `<tr><td class="bad">${esc(String(p.port))} / ${esc(p.service)}</td><td class="dim">${p.ms != null ? `${p.ms}ms` : ""}</td></tr>`).join("")
    : `<tr><td colspan="2" class="dim">No open localhost ports detected</td></tr>`;

  const sGps = gps
    ? [
        tr("Latitude",  gps.lat  != null ? Number(gps.lat).toFixed(6)  : null),
        tr("Longitude", gps.lon  != null ? Number(gps.lon).toFixed(6)  : null),
        tr("Accuracy",  gps.accuracy != null ? `${Math.round(gps.accuracy)} m` : null),
        tr("Altitude",  gps.altitude != null ? `${Math.round(gps.altitude)} m` : null),
        gps.lat != null && gps.lon != null ? (() => {
          const lat = Number(gps.lat), lon = Number(gps.lon);
          const d = Math.min(0.01, Math.max(0.002, (gps.accuracy || 200) / 111000));
          const bbox = `${lon - d}%2C${lat - d}%2C${lon + d}%2C${lat + d}`;
          return `<tr><td colspan="2"><iframe src="https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${lat}%2C${lon}" style="width:100%;height:220px;border:none;margin-top:.3rem" loading="lazy" title="GPS location"></iframe></td></tr>`;
        })() : "",
      ].join("")
    : `<tr><td colspan="2" class="dim">Not available — geolocation permission not yet granted</td></tr>`;

  const sHistory = visits.slice().reverse().map((v) => {
    const vg = v.geo || {};
    return `<div class="visit"><span class="ts">${esc(v.ts)}</span><span class="ip">${esc(v.clientIp)}</span><span class="loc">${esc([vg.city, vg.country].filter(Boolean).join(", "))}</span></div>`;
  }).join("");

  // ── Template ──────────────────────────────────────────────────────────────
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Visitor · ${esc(data.id)}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font:13px/1.6 'Courier New',monospace;background:#0d0d0d;color:#bbb;padding:2rem;max-width:860px}
h1{color:#3f3;font-size:1em;margin-bottom:1.5rem;letter-spacing:.05em}
h2{color:#2a2;font-size:.8em;text-transform:uppercase;letter-spacing:.12em;margin:1.5rem 0 .5rem;padding-bottom:.3rem;border-bottom:1px solid #1a1a1a}
table{border-collapse:collapse;width:100%;margin-bottom:.5rem}
td{padding:.2rem 0;border-bottom:1px solid #0f0f0f;vertical-align:top}
td:first-child{color:#555;width:165px;white-space:nowrap;padding-right:1.5rem}
.val{color:#ccc;word-break:break-all}.bad{color:#f55}.good{color:#3f3}.warn{color:#fa0}.dim{color:#444}
.note{color:#666;font-size:.9em;margin-bottom:.3rem}
.pills{display:flex;flex-wrap:wrap;gap:.25rem;margin:.2rem 0}
.pill{padding:.05rem .35rem;background:#111;border:1px solid #1e1e1e;border-radius:2px;font-size:.85em;color:#3a3;border-color:#1a3a1a}
.id-val{color:#3f3;word-break:break-all}
.pre{background:#0a0a0a;padding:.4rem .6rem;overflow:auto;font-size:.85em;margin:.2rem 0;border:1px solid #1a1a1a;white-space:pre}
.visit{padding:.3rem 0;border-bottom:1px solid #111;display:flex;gap:1.5rem;flex-wrap:wrap;font-size:.9em}
.visit .ts{color:#555;min-width:220px}.visit .ip{color:#3a3}.visit .loc{color:#777}
.meta{color:#444;font-size:.75em;margin-top:2rem;padding-top:.5rem;border-top:1px solid #111}
</style>
</head>
<body>
<h1>// visitor report — hidden-homepage</h1>

<h2>Identity</h2>
<table>
<tr><td>Visitor ID</td><td class="id-val">${esc(data.id)}</td></tr>
<tr><td>First seen</td><td class="val">${esc(first.ts || "—")}</td></tr>
<tr><td>Last seen</td><td class="val">${esc(last.ts || "—")}</td></tr>
<tr><td>Visit count</td><td class="val">${visits.length}</td></tr>
</table>

<h2>Network — server-side</h2><table>${sNet}</table>
<h2>Browser Languages (server-seen)</h2>${sLangs}
<h2>Proxy / Forwarding Path</h2>${sProxy}
<h2>Reverse DNS (all discovered IPs)</h2><table>${sRdns}</table>
<h2>DNS Records (your domain)</h2><table>${sDns}</table>
<h2>Browser &amp; Device</h2><table>${sBrowser}</table>
<h2>Screen &amp; Display</h2><table>${sScreen}</table>
<h2>Locale &amp; Time</h2><table>${sLocale}</table>
<h2>Privacy &amp; Storage</h2><table>${sStorage}</table>
<h2>Network Conditions — client</h2><table>${sNetCond}</table>
<h2>GPU / WebGL</h2><table>${sWebgl}</table>
<h2>Fingerprints</h2><table>${sFp}</table>
<h2>Browser Capabilities</h2>${sCaps}
<h2>Installed Fonts</h2>${sFonts}
<h2>Plugins</h2>${sPlugins}
<h2>Ad / Tracker Detection</h2><table>${sAdblock}</table>
<h2>Permissions</h2><table>${sPerms}</table>
<h2>Media Devices</h2><table>${sMedia}</table>
<h2>Battery</h2><table>${sBattery}</table>
<h2>WebRTC IP Leak</h2><table>${sWebrtc}</table>
<h2>Open Localhost Ports</h2><table>${sLocalPorts}</table>
<h2>Precise Geolocation (GPS)</h2><table>${sGps}</table>

<h2>Visit History (${visits.length})</h2>
<div>${sHistory || "<p class='dim' style='padding:.5rem 0'>No visits recorded.</p>"}</div>
<p class="meta">Generated by hidden-homepage · ${esc(new Date().toISOString())}</p>
</body>
</html>`;
}

/* ------------------------------------------------------------------ */
/* API                                                                */
/* ------------------------------------------------------------------ */

app.get("/api/info", async (req, res) => {
  const directIp = normalizeIp(req.socket.remoteAddress);
  const chain = forwardedChain(req);
  // The "real" client is the left-most forwarded entry, falling back to the socket peer.
  const clientIp =
    chain[0] ||
    normalizeIp(req.headers["cf-connecting-ip"]) ||
    normalizeIp(req.headers["true-client-ip"]) ||
    directIp;

  const headers = {};
  for (const h of INTERESTING_HEADERS) {
    if (req.headers[h] !== undefined) headers[h] = req.headers[h];
  }

  // Reverse-resolve every distinct IP we already know about server-side.
  const discovered = [
    ...new Set(
      [
        clientIp,
        directIp,
        ...chain,
        normalizeIp(req.headers["cf-connecting-ip"]),
        normalizeIp(req.headers["true-client-ip"]),
      ].filter(Boolean)
    ),
  ];

  const [geo, ptr, directPtr, tor, discoveredPtr] = await Promise.all([
    geoLookup(clientIp),
    reverseDns(clientIp),
    reverseDns(directIp),
    torCheck(clientIp),
    Promise.all(
      discovered.map(async (ip) => ({
        ip,
        ptr: await reverseDns(ip),
        private: isPrivateOrLocal(ip),
      }))
    ),
  ]);

  res.json({
    serverTime: new Date().toISOString(),
    osGuess: osGuess(req),
    network: {
      clientIp,
      directIp, // the TCP peer the server actually talks to (proxy or client)
      behindProxy: chain.length > 0 || !!headers["via"] || !!headers["forwarded"],
      forwardedChain: chain,
      cfConnectingIp: normalizeIp(req.headers["cf-connecting-ip"]) || null,
      trueClientIp: normalizeIp(req.headers["true-client-ip"]) || null,
      protocol: req.protocol,
      httpVersion: req.httpVersion,
      reverseDns: ptr,
      directReverseDns: directPtr,
      discoveredPtr, // [{ ip, ptr, private }] for every IP seen server-side
    },
    languages: parseAcceptLanguage(req.headers["accept-language"]),
    tor,
    geo,
    headers,
    allHeaders: req.headers,
  });
});

// Best-effort traceroute back to the requesting client. Frequently blocked in
// containers (needs raw sockets / CAP_NET_RAW) and on hosts that drop ICMP, so
// it degrades gracefully and never throws.
app.get("/api/traceroute", async (req, res) => {
  if (probeLimited(req, res, { hops: [] })) return;
  const chain = forwardedChain(req);
  const clientIp =
    chain[0] ||
    normalizeIp(req.headers["cf-connecting-ip"]) ||
    normalizeIp(req.socket.remoteAddress);

  const tgt = await resolveProbeTarget(clientIp);
  if (tgt.error) {
    return res.json({ available: false, target: clientIp, reason: tgt.error, hops: [] });
  }

  try {
    // -m 20 max hops, -w 2 wait 2s, -q 1 one probe per hop -> keep it snappy.
    // execFile + arg array: the target is a single argv entry, never shell-parsed.
    const trArgs = ["traceroute", "-m", "20", "-w", "2", "-q", "1", "-n", tgt.ip];
    logExec(req, trArgs);
    const { stdout } = await execFileAsync(trArgs[0], trArgs.slice(1), { timeout: 45000 });
    const hops = stdout
      .split("\n")
      .slice(1)
      .map((line) => line.trim())
      .filter(Boolean)
      .map((line) => {
        const m = line.match(/^(\d+)\s+(.*)$/);
        if (!m) return null;
        const ipMatch = m[2].match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
        const msMatch = m[2].match(/([\d.]+)\s*ms/);
        return {
          hop: parseInt(m[1], 10),
          ip: ipMatch ? ipMatch[1] : null,
          rttMs: msMatch ? parseFloat(msMatch[1]) : null,
          raw: m[2],
        };
      })
      .filter(Boolean);

    // Redact (don't drop) the masked hops: keep their position/RTT but strip the
    // address. Hops that are private/RFC1918 or inside a hide-range are blanked.
    let redactedCount = 0;
    for (const h of hops) {
      if (hopShouldHide(h.ip)) {
        h.redacted = true;
        h.ip = null;
        delete h.raw; // raw line still contains the address — don't leak it
        redactedCount++;
      }
    }

    // Reverse-resolve only the non-redacted responding hops.
    await Promise.all(
      hops.map(async (h) => {
        if (h.ip && !h.redacted) h.host = await reverseDns(h.ip);
      })
    );

    res.json({
      available: true,
      target: tgt.ip,
      note: tgt.note,
      redactedCount,
      hideConfig: { private: TR_HIDE_PRIVATE, ranges: TR_HIDE_RANGES },
      hops,
    });
  } catch (err) {
    res.json({
      available: false,
      target: tgt.ip,
      reason:
        "traceroute unavailable (blocked by network, missing CAP_NET_RAW, or ICMP filtered).",
      detail: String(err?.message || err).slice(0, 300),
      hops: [],
    });
  }
});

// Common ports worth probing on a residential/edge IP, with service labels.
const SCAN_PORTS = [
  // --- file transfer ---
  { p: 20, s: "FTP-data" }, { p: 21, s: "FTP" }, { p: 69, s: "TFTP" },
  { p: 115, s: "SFTP" }, { p: 873, s: "rsync" }, { p: 2049, s: "NFS" },
  { p: 548, s: "AFP (Apple)" },
  // --- remote access / shell ---
  { p: 22, s: "SSH" }, { p: 23, s: "Telnet" }, { p: 2222, s: "SSH-alt" },
  { p: 3389, s: "RDP" }, { p: 5900, s: "VNC" }, { p: 5901, s: "VNC-1" },
  // --- mail ---
  { p: 25, s: "SMTP" }, { p: 110, s: "POP3" }, { p: 143, s: "IMAP" },
  { p: 465, s: "SMTPS" }, { p: 587, s: "SMTP/submission" },
  { p: 993, s: "IMAPS" }, { p: 995, s: "POP3S" },
  // --- web ---
  { p: 80, s: "HTTP" }, { p: 443, s: "HTTPS" }, { p: 591, s: "HTTP-alt" },
  { p: 3000, s: "dev/Grafana" }, { p: 8000, s: "HTTP-dev" },
  { p: 8080, s: "HTTP-alt" }, { p: 8081, s: "HTTP-alt" },
  { p: 8443, s: "HTTPS-alt" }, { p: 8888, s: "HTTP-alt" },
  // --- naming / directory / management ---
  { p: 53, s: "DNS" }, { p: 67, s: "DHCP" }, { p: 123, s: "NTP" },
  { p: 161, s: "SNMP" }, { p: 389, s: "LDAP" }, { p: 636, s: "LDAPS" },
  { p: 111, s: "RPCbind" }, { p: 135, s: "MSRPC" }, { p: 139, s: "NetBIOS" },
  { p: 445, s: "SMB" }, { p: 5985, s: "WinRM" }, { p: 5986, s: "WinRM-S" },
  // --- databases / cache ---
  { p: 1433, s: "MSSQL" }, { p: 1521, s: "Oracle" }, { p: 3306, s: "MySQL" },
  { p: 5432, s: "Postgres" }, { p: 6379, s: "Redis" }, { p: 11211, s: "Memcached" },
  { p: 27017, s: "MongoDB" }, { p: 9200, s: "Elasticsearch" },
  { p: 5984, s: "CouchDB" }, { p: 8086, s: "InfluxDB" },
  // --- messaging / realtime ---
  { p: 5060, s: "SIP" }, { p: 5061, s: "SIP-TLS" }, { p: 5222, s: "XMPP" },
  { p: 6667, s: "IRC" }, { p: 1883, s: "MQTT" }, { p: 8883, s: "MQTT-TLS" },
  { p: 5672, s: "AMQP/RabbitMQ" },
  // --- VPN ---
  { p: 500, s: "IKE/IPsec" }, { p: 1194, s: "OpenVPN" }, { p: 1701, s: "L2TP" },
  { p: 1723, s: "PPTP" }, { p: 51820, s: "WireGuard" },
  // --- printing / misc services ---
  { p: 631, s: "IPP/printing" }, { p: 9100, s: "JetDirect" },
  // --- admin panels / self-hosted ---
  { p: 2082, s: "cPanel" }, { p: 2083, s: "cPanel-SSL" }, { p: 10000, s: "Webmin" },
  { p: 8006, s: "Proxmox" }, { p: 9090, s: "Prometheus/Cockpit" },
  { p: 5601, s: "Kibana" }, { p: 9000, s: "Portainer/misc" },
  // --- media / streaming ---
  { p: 32400, s: "Plex" }, { p: 8096, s: "Jellyfin/Emby" },
  { p: 9091, s: "Transmission" }, { p: 51413, s: "BitTorrent" },
  // --- game servers ---
  { p: 25565, s: "Minecraft" }, { p: 27015, s: "Source/Steam" },
];

// Single TCP connect probe. open = SYN-ACK before timeout. No payload sent.
function probePort(ip, port, timeout = 1500) {
  return new Promise((resolve) => {
    const start = Date.now();
    const sock = new net.Socket();
    let settled = false;
    const done = (state) => {
      if (settled) return;
      settled = true;
      sock.destroy();
      resolve({ port, state, ms: Date.now() - start });
    };
    sock.setTimeout(timeout);
    sock.once("connect", () => done("open"));
    sock.once("timeout", () => done("filtered"));
    sock.once("error", (e) => done(e.code === "ECONNREFUSED" ? "closed" : "filtered"));
    sock.connect(port, ip);
  });
}

// Reverse port scan of the visitor's own public IP (TCP connect, no nmap/root).
app.get("/api/portscan", async (req, res) => {
  if (probeLimited(req, res, { ports: [] })) return;
  const chain = forwardedChain(req);
  const ip =
    chain[0] ||
    normalizeIp(req.headers["cf-connecting-ip"]) ||
    normalizeIp(req.socket.remoteAddress);

  const tgt = await resolveProbeTarget(ip);
  if (tgt.error) {
    return res.json({ available: false, target: ip, reason: tgt.error, ports: [] });
  }

  logExec(req, ["tcp-connect-portscan", `${SCAN_PORTS.length}ports`, tgt.ip]);
  // limited concurrency to stay polite while keeping the larger list snappy
  const results = [];
  const queue = [...SCAN_PORTS];
  const workers = Array.from({ length: 16 }, async () => {
    while (queue.length) {
      const { p, s } = queue.shift();
      const r = await probePort(tgt.ip, p);
      results.push({ ...r, service: s });
    }
  });
  await Promise.all(workers);
  results.sort((a, b) => a.port - b.port);
  res.json({
    available: true,
    target: tgt.ip,
    note: tgt.note,
    scannedAt: new Date().toISOString(),
    open: results.filter((r) => r.state === "open").length,
    ports: results,
  });
});

// Active OS detection via nmap. nmap insists on euid==0 (it ignores file caps),
// so we invoke it through sudo (a tight NOPASSWD rule limits node to nmap only).
// Degrades to the passive UA guess if sudo/nmap/raw sockets aren't available.
app.get("/api/osdetect", async (req, res) => {
  if (probeLimited(req, res, { passive: osGuess(req) })) return;
  const chain = forwardedChain(req);
  const ip = chain[0] || normalizeIp(req.headers["cf-connecting-ip"]) || normalizeIp(req.socket.remoteAddress);
  const tgt = await resolveProbeTarget(ip);
  if (tgt.error) {
    return res.json({ available: false, reason: tgt.error, passive: osGuess(req) });
  }
  try {
    // execFile + arg array: no shell, so the IP can't break out into a command.
    const nmapArgs = ["sudo", "-n", "nmap", "-O", "-Pn", "--osscan-guess", "--max-retries", "1", "--host-timeout", "30s", tgt.ip];
    logExec(req, nmapArgs); // note: sudo elevates nmap to root (see Dockerfile sudoers rule)
    const { stdout } = await execFileAsync(nmapArgs[0], nmapArgs.slice(1), { timeout: 40000 });
    res.json({ available: true, target: tgt.ip, note: tgt.note, passive: osGuess(req), nmap: stdout });
  } catch (err) {
    res.json({
      available: false,
      target: tgt.ip,
      note: tgt.note,
      passive: osGuess(req),
      reason: "nmap unavailable or lacks raw-socket privileges; showing passive UA-based guess only.",
      detail: String(err?.message || err).slice(0, 200),
    });
  }
});

// Bulk reverse-DNS for a caller-supplied IP list (e.g. WebRTC-leaked IPs that
// only the browser knows). Each entry is strictly validated; the list is capped.
app.get("/api/rdns", async (req, res) => {
  if (lookupLimited(req, res, { results: [] })) return;
  const list = String(req.query.ips || "")
    .split(",")
    .map((s) => normalizeIp(s.trim()))
    .filter(Boolean);
  const valid = [...new Set(list.filter(isValidIp))].slice(0, 40);
  const results = await Promise.all(
    valid.map(async (ip) => ({ ip, ptr: await reverseDns(ip), private: isPrivateOrLocal(ip) }))
  );
  res.json({ available: true, results });
});

// Forward DNS records for a validated hostname (the client's reverse-DNS name).
app.get("/api/dns", async (req, res) => {
  if (lookupLimited(req, res)) return;
  const host = String(req.query.host || "").trim().toLowerCase().replace(/\.$/, "");
  if (!isValidHostname(host)) {
    return res.json({ available: false, reason: "invalid or missing hostname" });
  }
  const records = await dnsRecords(host);
  res.json({ available: true, host, records });
});

// The browser's own public IP (from its external echo lookup). When the client
// sits behind NAT/VPN and reaches us via an internal hop, the server can't see
// this IP itself — so the page reports it here purely so it lands in the log,
// next to the forwarded client IP and the direct (Traefik) peer.
app.get("/api/clientmeta", (req, res) => {
  const pub = normalizeIp(String(req.query.pubip || ""));
  const ok = isValidIp(pub);
  if (LOG_REQUESTS) {
    const ua = req.headers["user-agent"] || "-";
    logLine(
      `${clientIpOf(req)} - - [${apacheDate(new Date())}] CLIENT pubip=${ok ? pub : "-"} via=${directIpOf(req)} "${ua}"`
    );
  }
  res.status(204).end();
});

// Client-side recon report: the browser POSTs everything it gathered and we
// log it + write a per-visitor JSON/HTML report to REPORT_DIR.
app.post("/api/clientreport", async (req, res) => {
  res.status(204).end();
  const b = req.body;
  if (!b || typeof b !== "object" || Array.isArray(b)) return;

  // ── Sanitizers ────────────────────────────────────────────────────────────
  const clip  = (v, max = 200) =>
    typeof v === "string" ? v.slice(0, max) : v != null ? String(v).slice(0, max) : null;
  const num   = (v) => (Number.isFinite(Number(v)) ? Number(v) : null);
  const bool  = (v) => (v === true || v === false ? v : null);
  const obj   = (v) => (v && typeof v === "object" && !Array.isArray(v)) ? v : {};
  const strArr= (v, maxItems = 60, maxLen = 80) =>
    Array.isArray(v) ? v.filter((x) => typeof x === "string").slice(0, maxItems).map((x) => x.slice(0, maxLen)) : [];

  const vid = isValidUUID(b.visitorId) ? b.visitorId.toLowerCase() : null;
  const br = obj(b.browser);
  const sc = obj(b.screen);
  const lc = obj(b.locale);
  const st = obj(b.storage);
  const nw = b.network && typeof b.network === "object" && !Array.isArray(b.network) ? b.network : null;
  const wg = b.webgl   && typeof b.webgl   === "object" && !Array.isArray(b.webgl)   ? b.webgl   : null;
  const fp = obj(b.fingerprints);
  const ab = b.adblock     && typeof b.adblock     === "object" ? b.adblock     : null;
  const pm = b.permissions && typeof b.permissions === "object" ? b.permissions : null;
  const md = b.mediaDevices&& typeof b.mediaDevices=== "object" ? b.mediaDevices: null;
  const bt = b.battery     && typeof b.battery     === "object" ? b.battery     : null;
  const wrt= b.webrtc      && typeof b.webrtc      === "object" ? b.webrtc      : null;
  const lp = Array.isArray(b.localPorts) ? b.localPorts : [];

  // ── Access log line ───────────────────────────────────────────────────────
  if (LOG_REQUESTS) {
    const parts = [
      vid ? `id=${vid}` : "id=-",
      `screen=${num(sc.w) ?? "-"}x${num(sc.h) ?? "-"}`,
      `dpr=${num(sc.dpr) ?? "-"}`,
      `tz="${clip(lc.timezone) ?? ""}"`,
      `lang="${clip(br.language) ?? ""}"`,
      `cores=${num(br.cpuCores) ?? "-"}`,
      `mem=${num(br.deviceMemory) ?? "-"}`,
      `webgl="${clip(wg?.renderer, 150) ?? ""}"`,
      `canvas=${clip(fp.canvas, 64) ?? "-"}`,
      `audio=${clip(fp.audio,  64) ?? "-"}`,
    ];
    logLine(`${clientIpOf(req)} - - [${apacheDate(new Date())}] CLIENT_REPORT ${parts.join(" ")} via=${directIpOf(req)}`);
  }

  if (!REPORT_DIR || !vid) return;

  // ── Write per-visitor report ──────────────────────────────────────────────
  try {
    const ip     = clientIpOf(req);
    const direct = directIpOf(req);
    const chain  = forwardedChain(req);
    const discovered = [...new Set([ip, direct, ...chain].filter(Boolean))];

    const [geo, tor, discoveredPtr] = await Promise.all([
      geoLookup(ip),
      torCheck(ip),
      Promise.all(discovered.map(async (dip) => ({
        ip: dip, ptr: await reverseDns(dip), private: isPrivateOrLocal(dip),
      }))),
    ]);

    // Forward DNS for the primary PTR hostname (needs PTR result, so sequential)
    const primaryPtr = (discoveredPtr.find((d) => d.ip === ip)?.ptr || [])[0] || null;
    const fwdDns = primaryPtr && isValidHostname(primaryPtr) ? await dnsRecords(primaryPtr) : null;
    const langs  = parseAcceptLanguage(req.headers["accept-language"]);

    const jsonPath = path.join(REPORT_DIR, `${vid}.json`);
    let data = { id: vid, visits: [] };
    let isNew = false;
    try {
      data = JSON.parse(await fs.promises.readFile(jsonPath, "utf8"));
    } catch {
      // First visit — stamp creation time once; it is never overwritten on reload.
      data.createdAt = new Date().toISOString();
      isNew = true;
    }

    const uach = br.uach && typeof br.uach === "object" ? {
      platform:        clip(br.uach.platform),
      platformVersion: clip(br.uach.platformVersion),
      architecture:    clip(br.uach.architecture),
      bitness:         clip(br.uach.bitness),
      model:           clip(br.uach.model),
      wow64:           bool(br.uach.wow64),
      brands:          strArr(br.uach.brands, 10, 80),
    } : null;

    data.visits.push({
      ts:       new Date().toISOString(),
      clientIp: ip,
      directIp: directIpOf(req),
      ua:       req.headers["user-agent"] || null,
      geo: geo?.status === "success" ? {
        country: geo.country, countryCode: geo.countryCode,
        regionName: geo.regionName, city: geo.city,
        isp: geo.isp, org: geo.org, as: geo.as,
        proxy: !!geo.proxy, hosting: !!geo.hosting,
      } : null,
      isExitNode: tor?.isExitNode ?? false,

      browser: {
        userAgent:   clip(br.userAgent, 300),
        platform:    clip(br.platform),
        vendor:      clip(br.vendor),
        language:    clip(br.language),
        cpuCores:    num(br.cpuCores),
        deviceMemory:num(br.deviceMemory),
        touchPoints: num(br.touchPoints),
        onLine:      bool(br.onLine),
        pdfViewer:   bool(br.pdfViewer),
        uach,
      },
      screen: {
        w: num(sc.w), h: num(sc.h),
        availW: num(sc.availW), availH: num(sc.availH),
        windowW: num(sc.windowW), windowH: num(sc.windowH),
        colorDepth:   num(sc.colorDepth),
        dpr:          num(sc.dpr),
        orientation:  clip(sc.orientation),
        colorScheme:  clip(sc.colorScheme),
        reducedMotion:bool(sc.reducedMotion),
        hdr:          bool(sc.hdr),
      },
      locale: {
        timezone:       clip(lc.timezone),
        utcOffset:      clip(lc.utcOffset),
        locale:         clip(lc.locale),
        calendar:       clip(lc.calendar),
        numberingSystem:clip(lc.numberingSystem),
      },
      storage: {
        cookies:       bool(st.cookies),
        dnt:           clip(st.dnt, 10),
        gpc:           bool(st.gpc),
        localStorage:  bool(st.localStorage),
        sessionStorage:bool(st.sessionStorage),
        indexedDB:     bool(st.indexedDB),
        quota:         num(st.quota),
      },
      network: nw ? {
        type:     clip(nw.type, 20),
        downlink: num(nw.downlink),
        rtt:      num(nw.rtt),
        saveData: bool(nw.saveData),
      } : null,
      webgl: wg ? {
        vendor:     clip(wg.vendor,   200),
        renderer:   clip(wg.renderer, 200),
        glsl:       clip(wg.glsl,     100),
        maxTexture: num(wg.maxTexture),
      } : null,
      fingerprints: {
        canvas: clip(fp.canvas, 64),
        audio:  clip(fp.audio,  64),
      },
      capabilities: strArr(b.capabilities, 30, 40),
      fonts:        strArr(b.fonts,        60, 60),
      plugins:      strArr(b.plugins,      20, 100),
      adblock: ab ? {
        baitHidden:    bool(ab.baitHidden),
        scriptBlocked: bool(ab.scriptBlocked),
        trackerBlocked:bool(ab.trackerBlocked),
        blocking:      bool(ab.blocking),
      } : null,
      permissions: pm ? (() => {
        const allowed = ["geolocation","notifications","camera","microphone","clipboard-read","midi"];
        const out = {};
        for (const k of allowed) if (k in pm) out[k] = clip(pm[k], 20);
        return out;
      })() : null,
      mediaDevices: md ? {
        audioinput:  num(md.audioinput),
        audiooutput: num(md.audiooutput),
        videoinput:  num(md.videoinput),
      } : null,
      battery: bt ? {
        level:          num(bt.level),
        charging:       bool(bt.charging),
        chargingTime:   num(bt.chargingTime),
        dischargingTime:num(bt.dischargingTime),
      } : null,
      webrtc: wrt ? (() => {
        const out = {};
        for (const [k, v] of Object.entries(wrt).slice(0, 10)) {
          if (typeof k === "string" && k.length < 50 && (v === "local" || v === "public"))
            out[k] = v;
        }
        return Object.keys(out).length ? out : null;
      })() : null,
      localPorts: lp.slice(0, 20)
        .filter((p) => p && typeof p === "object")
        .map((p) => ({ port: num(p.port), service: clip(p.service, 30), ms: num(p.ms) }))
        .filter((p) => p.port != null),

      // Server-side enrichment (not available from the browser payload)
      languages:    langs,
      proxyChain:   chain,
      discoveredPtr: discoveredPtr,
      dnsRecords:   fwdDns ? { host: primaryPtr, records: fwdDns } : null,

      // Client-sent GPS (only present when permission was already "granted")
      geolocation: (() => {
        const g = b.geolocation;
        if (!g || typeof g !== "object") return null;
        const lat = num(g.lat), lon = num(g.lon), acc = num(g.accuracy);
        if (lat == null || lon == null) return null;
        return { lat, lon, accuracy: acc, altitude: num(g.altitude) };
      })(),
    });

    await Promise.all([
      fs.promises.writeFile(jsonPath, JSON.stringify(data, null, 2)),
      fs.promises.writeFile(path.join(REPORT_DIR, `${vid}.html`), buildReportHtml(data)),
    ]);
  } catch (err) {
    console.error(`clientreport write error: ${err.message}`);
  }
});

// Serve a per-visitor report page by UUID.
app.get("/reports/:id", (req, res) => {
  if (!REPORT_DIR) {
    return res.status(404).send("Report storage is not configured (set REPORT_DIR or LOG_FILE).");
  }
  const id = String(req.params.id || "").toLowerCase().replace(/\.html$/, "");
  if (!isValidUUID(id)) return res.status(400).send("Invalid visitor ID.");
  const htmlPath = path.join(REPORT_DIR, `${id}.html`);
  res.sendFile(htmlPath, { root: "/" }, (err) => {
    if (err) res.status(404).send("Report not found for this visitor ID.");
  });
});

app.get("/api/healthz", (_req, res) => res.json({ ok: true }));

// Delete per-visitor report files whose first visit is older than 30 minutes.
const REPORT_TTL_MS = 15 * 60 * 1000;
async function cleanupOldReports() {
  if (!REPORT_DIR) return;
  try {
    const files = await fs.promises.readdir(REPORT_DIR);
    const now = Date.now();
    let removed = 0;
    for (const file of files) {
      if (!file.endsWith(".json")) continue;
      const jsonPath = path.join(REPORT_DIR, file);
      try {
        const data = JSON.parse(await fs.promises.readFile(jsonPath, "utf8"));
        // createdAt is set once on first write and never updated on reloads.
        // Falls back to visits[0].ts for files written before this field existed.
        const anchor = data.createdAt || data.visits?.[0]?.ts;
        if (anchor && now - new Date(anchor).getTime() > REPORT_TTL_MS) {
          const id = file.slice(0, -5);
          await Promise.all([
            fs.promises.unlink(jsonPath),
            fs.promises.unlink(path.join(REPORT_DIR, `${id}.html`)).catch(() => {}),
          ]);
          removed++;
        }
      } catch {}
    }
    if (removed) console.log(`report cleanup: removed ${removed} expired profile(s)`);
  } catch (err) {
    console.error(`report cleanup error: ${err.message}`);
  }
}

app.listen(PORT, () => {
  console.log(`privacyCheck listening on http://0.0.0.0:${PORT}`);
  if (logStream) console.log(`access/exec/client log also appended to ${LOG_FILE}`);
  if (REPORT_DIR) console.log(`per-visitor reports → ${REPORT_DIR}  (served at /reports/<uuid>, TTL 30 min)`);
  if (REPORT_DIR) {
    cleanupOldReports(); // purge any leftovers from before the last restart
    setInterval(cleanupOldReports, 5 * 60 * 1000); // then every 5 minutes
  }
  // Warm the Tor exit-list cache so the first visitor doesn't pay the fetch.
  getTorExitSet().then((c) =>
    console.log(c.set ? `Tor exit list loaded: ${c.set.size} nodes` : `Tor exit list unavailable: ${c.error}`)
  );
});
