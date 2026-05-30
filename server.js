import express from "express";
import net from "node:net";
import os from "node:os";
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
      console.log(`${ip} - - [${apacheDate(new Date())}] "${reqLine}" ${res.statusCode} ${len} "${ref}" "${ua}" via=${direct}`);
    });
    next();
  });
}

app.use(express.static(path.join(__dirname, "public")));

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
  console.log(`${clientIpOf(req)} - - [${apacheDate(new Date())}] EXEC (as ${RUN_USER}) ${cmd} via=${directIpOf(req)}`);
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

// Per-IP rate limit for the expensive active probes (traceroute/nmap/portscan),
// so the server can't be abused as a root-privileged scan reflector. In-memory
// sliding window; tune via PROBE_RATE_MAX / PROBE_RATE_WINDOW_MS.
const PROBE_MAX = Number(process.env.PROBE_RATE_MAX || 10);
const PROBE_WINDOW_MS = Number(process.env.PROBE_RATE_WINDOW_MS || 60000);
const probeHits = new Map(); // ip -> timestamps[]
function probeRateLimit(req) {
  const ip = clientIpOf(req);
  const now = Date.now();
  const hits = (probeHits.get(ip) || []).filter((t) => now - t < PROBE_WINDOW_MS);
  if (hits.length >= PROBE_MAX) {
    probeHits.set(ip, hits);
    return { ok: false, retry: Math.ceil((PROBE_WINDOW_MS - (now - hits[0])) / 1000) };
  }
  hits.push(now);
  probeHits.set(ip, hits);
  if (probeHits.size > 5000) {
    for (const [k, v] of probeHits) {
      const keep = v.filter((t) => now - t < PROBE_WINDOW_MS);
      if (keep.length) probeHits.set(k, keep);
      else probeHits.delete(k);
    }
  }
  return { ok: true };
}

function probeLimited(req, res, extra = {}) {
  const rl = probeRateLimit(req);
  if (rl.ok) return false;
  res.set("Retry-After", String(rl.retry));
  res.status(429).json({
    available: false,
    reason: `Rate limited — max ${PROBE_MAX} probes per ${PROBE_WINDOW_MS / 1000}s. Try again in ${rl.retry}s.`,
    ...extra,
  });
  return true;
}

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
    console.log(
      `${clientIpOf(req)} - - [${apacheDate(new Date())}] CLIENT pubip=${ok ? pub : "-"} via=${directIpOf(req)} "${ua}"`
    );
  }
  res.status(204).end();
});

app.get("/api/healthz", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`hidden-homepage listening on http://0.0.0.0:${PORT}`);
  // Warm the Tor exit-list cache so the first visitor doesn't pay the fetch.
  getTorExitSet().then((c) =>
    console.log(c.set ? `Tor exit list loaded: ${c.set.size} nodes` : `Tor exit list unavailable: ${c.error}`)
  );
});
