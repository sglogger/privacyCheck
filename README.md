# privacyCheck — "What the Internet Knows About You"

A stylish, single-page **privacy-awareness dashboard**. Open it and it instantly
surfaces how much your connection and browser reveal, split into **server-side**
analysis (from your HTTP request) and **in-browser** reconnaissance (JavaScript
fingerprinting).

> **Warning — this is now a data-collection demo, not just a display.**
> Every detail shown on the page is **automatically transmitted to the server**
> without any user interaction and stored in a **per-visitor profile** for
> 15 minutes. A link to the profile is shown prominently at the top of the page
> and can be opened from any device on any network.
>
> Educational / privacy-awareness demo. The active probes (port scan, traceroute,
> nmap, localhost scan) only ever target **the visitor's own IP/machine** (or, for
> local requests, the server's own public IP).

Source: <https://github.com/sglogger/privacyCheck>

---

## What it shows

### Server-side (from your request)

- **Client IP** + the direct TCP peer (proxy vs. you) + a **public-IP cross-check**
  (the browser reports its own public IP, which can differ from what the server sees)
- **Proxy / forwarding path** — full `X-Forwarded-For` chain, `Via`, CF / true-client-IP headers
- **Reverse DNS (PTR)** for **every discovered IP** — your IP, the peer, proxy hops,
  and WebRTC-leaked IPs
- **Forward DNS records** of your reverse-DNS domain (A, AAAA, CNAME, MX, NS, TXT, SOA)
- **Geolocation** — continent, country, region, city, district, postal, lat/lon + embedded OpenStreetMap
- **Timezone & UTC offset** derived from your IP
- **Network operator (ASN)** — AS number, AS name, ISP, org
- **Anonymization detection** — Tor exit node (live Tor exit list) + VPN/proxy/hosting/mobile flags
- **Languages** parsed from `Accept-Language`
- **Full request headers**, including Client Hints (`Sec-CH-UA-*`)
- **OS & device fingerprint** — passive guess from UA + Client Hints
- **Reverse port scan** — TCP-connect probe of ~80 common ports on your public IP (on demand)
- **Active OS detection** — `nmap -O` stack fingerprinting (on demand)
- **Traceroute** — hop-by-hop path back to you, with per-hop reverse DNS and
  configurable masking of the boring leading hops (see below)

### In-browser (JavaScript, sent silently to the server)

- Browser, OS, vendor, platform, CPU cores, device memory, touch points, high-entropy UA-CH
- **Browser up-to-date check** — parsed version vs. reference latest-stable versions
- Screen / display: resolution, available area, window size, DPR, color depth, color scheme, reduced-motion, HDR
- Time & locale: timezone, offset, locale, calendar, numbering system
- Privacy signals: Do-Not-Track, Global Privacy Control, storage availability, storage quota
- **Cookies** — first-party, JS-readable cookies for this origin
- Network Information API: effective type, downlink, RTT, save-data
- **GPU / WebGL** vendor, renderer, GLSL version, max texture size
- **Canvas + audio fingerprints** (cookieless tracking IDs stable across reloads)
- **Installed font detection** via metric probing (~30 common fonts)
- Plugins & MIME types
- Browser capability matrix (WebRTC, WebGPU, WebAuthn, Bluetooth, USB, NFC, …)
- **Ad / tracker blocker detection** (bait element + ad-script + tracker-fetch tests)
- Permission states (camera, mic, notifications, etc. — without prompting)
- Media-device counts (mics / speakers / cameras)
- Battery level & charging state
- **WebRTC IP leak** — local & public IPs that can bypass VPNs
- **Localhost port scan** — detects services running on the visitor's own machine (runs automatically)
- **Silent GPS** — if geolocation permission was already granted by a previous visit, precise coordinates are collected without showing a dialog

All of the above is automatically `POST`ed to `/api/clientreport` in one request
after the page loads. No button click, no opt-in.

---

## Per-visitor reports

When `LOG_FILE` (or `REPORT_DIR`) is configured, the server writes two files per visitor:

```text
logs/reports/<uuid>.json   raw data + full visit history
logs/reports/<uuid>.html   rendered report, viewable in any browser
```

The report is served at **`/reports/<uuid>`** and includes 24 sections:

| Section | Source |
| --- | --- |
| Identity | visitor UUID + visit count |
| Network — server-side | IP, geo, ISP, ASN, proxy/VPN/Tor verdict |
| Browser Languages (server-seen) | parsed `Accept-Language` |
| Proxy / Forwarding Path | `X-Forwarded-For` chain |
| Reverse DNS (all IPs) | PTR lookup for every IP seen |
| DNS Records (your domain) | A/AAAA/MX/NS/TXT/SOA for your PTR hostname |
| Browser & Device | UA, platform, CPU, memory, touch, UA-CH |
| Screen & Display | resolution, DPR, window size, HDR, dark mode |
| Locale & Time | timezone, offset, locale, calendar |
| Privacy & Storage | cookies, DNT, GPC, localStorage, quota |
| Network Conditions — client | connection type, downlink, RTT |
| GPU / WebGL | vendor, renderer, GLSL, max texture |
| Fingerprints | canvas hash, audio hash |
| Browser Capabilities | supported APIs (WebRTC, WASM, etc.) |
| Installed Fonts | detected from metric probing |
| Plugins | browser plugin list |
| Ad / Tracker Detection | blocker verdict |
| Permissions | geolocation, camera, mic, notifications… |
| Media Devices | mic / speaker / camera counts |
| Battery | level, charging state, time estimates |
| WebRTC IP Leak | leaked local & public IPs |
| Open Localhost Ports | services detected on visitor's machine |
| Precise Geolocation (GPS) | coordinates + embedded map (if permission granted) |
| Visit History | timestamped list of every visit by this browser |

### Visitor ID

A UUID v4 is generated in the browser on first visit and stored in `localStorage`
as `hh_vid`. It persists across reloads and is sent with every report POST.
The same ID is shown as a clickable link at the top of the page — opening it
from any other device shows the stored profile.

### 30-minute TTL

Report files are deleted **30 minutes after the first visit** (anchored to
`createdAt` in the JSON, not the file's modification time, so reloading the
page does not reset the clock). A cleanup task runs on startup and every
5 minutes thereafter.

---

## Run it

### Docker Compose (recommended)

```bash
mkdir -p ./logs
cp docker-compose.yml-example docker-compose.yml   # then edit ports/env to taste
docker compose up -d --build
docker compose logs -f
# publishes http://localhost:3010 by default
```

> Use **Compose V2** (`docker compose`, with a space). The legacy Python
> `docker-compose` v1 is EOL. If you're stuck on v1, never use
> `docker-compose restart` after a rebuild — instead:
> `docker-compose down && docker-compose up -d`.

### Plain Docker

```bash
docker build -t privacycheck .
docker run --rm -p 3000:3000 \
  -e LOG_FILE=/logs/access.log \
  -v "$(pwd)/logs:/logs" \
  privacycheck
```

### Local (Node 22+)

```bash
npm install
npm start   # http://localhost:3000
```

---

## Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Port the server listens on |
| `LOG_REQUESTS` | `true` | Apache-format access + exec audit logging to stdout; `false` to disable |
| `LOG_FILE` | _(unset)_ | Append every log line to this file (survives restarts). Also activates per-visitor report file writing — reports land in `<LOG_FILE_DIR>/reports/`. Mount the directory as a volume to persist on the host. |
| `REPORT_DIR` | _(derived from `LOG_FILE`)_ | Override the per-visitor report directory explicitly |
| `TRACEROUTE_HIDE_PRIVATE` | `true` | Mask private/RFC1918 hops in traceroute output |
| `TRACEROUTE_HIDE_RANGES` | `193.239.20.0/22` | Comma-separated CIDRs to also mask (e.g. your ISP edge) |
| `PROBE_RATE_MAX` | `10` | Max active probes (traceroute/nmap/portscan) per IP per window |
| `PROBE_RATE_WINDOW_MS` | `60000` | Rate-limit window in ms for the active probes |

---

## Deploying behind a proxy

The server sets `trust proxy` and reads `X-Forwarded-For`, so put it behind
Traefik / nginx / Caddy / Cloudflare to see real client IPs and the full proxy
chain. On `localhost` (or any private/internal client IP) the geo lookup and the
active probes fall back to the **server's own public IP** and say so.

---

## Logging

With `LOG_REQUESTS` on (default), the container writes to stdout (→ `docker logs`):

**Access log** — Apache _combined_ format plus the direct peer:

```text
203.0.113.5 - - [01/Jun/2026:20:32:44 +0000] "GET /api/info HTTP/1.1" 200 1257 "https://hidden.ch/" "Mozilla/5.0 …" via=172.18.0.9
```

**Exec audit** — every server-side command, who triggered it and as which OS user:

```text
203.0.113.5 - - [01/Jun/2026:19:14:30 +0000] EXEC (as node) sudo -n nmap -O … 203.0.113.5 via=172.18.0.9
```

**Client public IP** — the browser's own public IP (can differ from what the server sees behind NAT/VPN):

```text
10.10.10.172 - - [01/Jun/2026:20:38:40 +0000] CLIENT pubip=188.63.145.121 via=172.18.0.9 "Mozilla/5.0 …"
```

**Client report** — one line per page load with the key fingerprint fields:

```text
203.0.113.5 - - [01/Jun/2026:20:38:41 +0000] CLIENT_REPORT id=d38ab8c8-… screen=2560x1440 dpr=2 tz="Europe/Zurich" lang="de-CH,de,en" cores=10 mem=8 webgl="Apple M2 Pro" canvas=3f9a1c… audio=7b2e4a… via=172.18.0.9
```

By default these are ephemeral container logs (lost on restart/recreate). Set
`LOG_FILE` to also append the same lines to a file, and mount that path as a
volume to keep them on the host:

```yaml
environment:
  - LOG_FILE=/var/log/hidden-homepage/access.log
volumes:
  - ./logs:/var/log/hidden-homepage
```

---

## Traceroute hop masking

Leading hops that are private/RFC1918 or inside `TRACEROUTE_HIDE_RANGES` (default
`193.239.20.0/22`) are shown as `*redacted*` — kept in place (with their RTT) but
with the address and reverse-DNS stripped.

---

## Security notes

- All client-supplied input is treated as untrusted. The client IP is validated
  with **`net.isIP()`** (the kernel parser — not a hand-rolled regex), and any
  value starting with `-` is rejected so a token can never be read as an nmap /
  traceroute flag (argument injection). Hostnames for DNS lookups pass a hostname
  validator. External commands run via `execFile` (no shell). The DOM is built
  without any `innerHTML` sink.
- The `clientreport` payload is validated and size-limited (16 KB). Only
  whitelisted field shapes are stored; unknown keys are discarded.
- The active probes are **rate-limited per IP** (`PROBE_RATE_MAX` per
  `PROBE_RATE_WINDOW_MS`, default 10/60s). Private/internal targets fall back
  to the server's own public IP.
- Runs as the **non-root** `node` user. `traceroute` works via a file capability
  (`setcap cap_net_raw`); `nmap` is allowed via a narrow passwordless `sudo` rule
  that lets `node` run **only** `/usr/bin/nmap`. Everything degrades gracefully
  if raw sockets aren't available.

---

## Other notes

- **Geo/ASN** and the local-request public-IP fallback come from the free
  [ip-api.com](https://ip-api.com) endpoint (HTTP, 45 req/min, non-commercial).
  The Tor exit list is fetched from the Tor Project and cached hourly.
- Adblock, localhost-scan and browser-version checks are **heuristics** — expect
  occasional false positives/negatives.

---

## Layout

```text
server.js                     Express server, all APIs, per-visitor report writer
public/index.html             Page shell + adblock bait + report-notice placeholder
public/style.css              Dark "recon dashboard" styling
public/app.js                 Client-side recon, rendering, silent data collection
public/ads/advertisement.js   Adblock bait script
tools/logstats.py             Log analysis helper
Dockerfile
docker-compose.yml            Active config (gitignored)
docker-compose.yml-example    Template — copy to docker-compose.yml and adjust
```

---

## API endpoints

| Endpoint | Description |
| --- | --- |
| `GET /api/info` | All passive server-side analysis (IP, geo, ASN, Tor, DNS, headers, OS guess) |
| `GET /api/traceroute` | Traceroute back to the client (on demand) |
| `GET /api/portscan` | Reverse TCP-connect port scan of the client's public IP |
| `GET /api/osdetect` | `nmap -O` active OS detection |
| `GET /api/rdns?ips=` | Bulk reverse DNS for a validated, capped IP list |
| `GET /api/dns?host=` | Forward DNS records for a validated hostname |
| `GET /api/clientmeta?pubip=` | Beacon: logs the browser-reported public IP |
| `POST /api/clientreport` | Receives full client fingerprint payload; writes per-visitor JSON + HTML report |
| `GET /reports/:uuid` | Serves the per-visitor HTML report (requires `LOG_FILE` or `REPORT_DIR`) |
| `GET /api/healthz` | Health check |
