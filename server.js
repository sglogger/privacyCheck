import express from "express";
import net from "node:net";
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
app.use(express.static(path.join(__dirname, "public")));

/* ------------------------------------------------------------------ */
/* Helpers                                                            */
/* ------------------------------------------------------------------ */

// Normalize the IPv4-mapped IPv6 form (::ffff:1.2.3.4) to plain IPv4.
function normalizeIp(ip) {
  if (!ip) return ip;
  return ip.startsWith("::ffff:") ? ip.slice(7) : ip;
}

// Strict IPv4/IPv6 validation — anything passed to an external command must
// pass this, so header-spoofed garbage never reaches a child process.
function isValidIp(ip) {
  if (!ip) return false;
  const v = normalizeIp(ip);
  if (/^(\d{1,3})(\.\d{1,3}){3}$/.test(v)) {
    return v.split(".").every((o) => Number(o) >= 0 && Number(o) <= 255);
  }
  // Conservative IPv6: hex groups + colons only.
  return v.includes(":") && /^[0-9a-fA-F:]+$/.test(v);
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

// Parse the full X-Forwarded-For chain so we can show every hop.
function forwardedChain(req) {
  const xff = req.headers["x-forwarded-for"];
  if (!xff) return [];
  return xff
    .split(",")
    .map((s) => normalizeIp(s.trim()))
    .filter(Boolean);
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
  return { ip: normalizeIp(rawIp), note: null };
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
    const { stdout } = await execFileAsync(
      "traceroute",
      ["-m", "20", "-w", "2", "-q", "1", "-n", tgt.ip],
      { timeout: 45000 }
    );
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

    // Reverse-resolve each responding hop so the path shows hostnames too.
    await Promise.all(
      hops.map(async (h) => {
        if (h.ip) h.host = await reverseDns(h.ip);
      })
    );

    res.json({ available: true, target: tgt.ip, note: tgt.note, hops });
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
  const chain = forwardedChain(req);
  const ip =
    chain[0] ||
    normalizeIp(req.headers["cf-connecting-ip"]) ||
    normalizeIp(req.socket.remoteAddress);

  const tgt = await resolveProbeTarget(ip);
  if (tgt.error) {
    return res.json({ available: false, target: ip, reason: tgt.error, ports: [] });
  }

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
  const chain = forwardedChain(req);
  const ip = chain[0] || normalizeIp(req.headers["cf-connecting-ip"]) || normalizeIp(req.socket.remoteAddress);
  const tgt = await resolveProbeTarget(ip);
  if (tgt.error) {
    return res.json({ available: false, reason: tgt.error, passive: osGuess(req) });
  }
  try {
    // execFile + arg array: no shell, so the IP can't break out into a command.
    const { stdout } = await execFileAsync(
      "sudo",
      ["-n", "nmap", "-O", "-Pn", "--osscan-guess", "--max-retries", "1", "--host-timeout", "30s", tgt.ip],
      { timeout: 40000 }
    );
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

app.get("/api/healthz", (_req, res) => res.json({ ok: true }));

app.listen(PORT, () => {
  console.log(`hidden-homepage listening on http://0.0.0.0:${PORT}`);
  // Warm the Tor exit-list cache so the first visitor doesn't pay the fetch.
  getTorExitSet().then((c) =>
    console.log(c.set ? `Tor exit list loaded: ${c.set.size} nodes` : `Tor exit list unavailable: ${c.error}`)
  );
});
