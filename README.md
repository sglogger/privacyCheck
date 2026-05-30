# privacyCheck — "What the Internet Knows About You"

A stylish, single-page **privacy-awareness dashboard**. Open it and it instantly
surfaces how much your connection and browser reveal, split into **server-side**
analysis (from your HTTP request) and **in-browser** reconnaissance (JavaScript
fingerprinting). No database — everything is computed live for your session.

> Educational / privacy-awareness demo. The active probes (port scan, traceroute,
> nmap, localhost scan) only ever target **the visitor's own IP/machine** (or, for
> local requests, the server's own public IP).

Source: <https://github.com/sglogger/privacyCheck>

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

### In-browser (JavaScript)

- Browser, OS, vendor, platform, CPU cores, device memory, touch points, high-entropy UA-CH
- **Browser up-to-date check** — parsed version vs. reference latest-stable versions
- Screen / display: resolution, DPR, color depth, color scheme, reduced-motion, HDR
- Time & locale: timezone, offset, calendar, numbering system
- Privacy signals: Do-Not-Track, Global Privacy Control, storage quota
- **Cookies** — first-party, JS-readable cookies for this origin
- Network Information API: effective type, downlink, RTT, save-data
- **GPU / WebGL** vendor + renderer
- **Canvas + audio fingerprints** (cookieless tracking IDs)
- **Installed font detection** via metric probing
- Plugins & MIME types
- Browser capability matrix (WebRTC, WebGPU, WebAuthn, Bluetooth, USB, NFC, …)
- **Ad / tracker blocker detection** (bait element + ad-script + tracker-fetch tests)
- Permission states (without prompting)
- Media-device counts (mics / speakers / cameras)
- Battery level & charging state
- **WebRTC IP leak** — local & public IPs that can bypass VPNs
- **Localhost port scan** — detects services running on the visitor's own machine (runs automatically)
- **Precise GPS geolocation** (opt-in, prompts permission) — with an embedded map

## Run it

### Docker Compose (recommended)

```bash
cp docker-compose.yml-example docker-compose.yml   # then edit ports/env to taste
docker compose up -d --build
docker compose logs -f
# the example publishes http://localhost:3010
```

> Use **Compose V2** (`docker compose`, with a space). The legacy Python
> `docker-compose` v1 is EOL and has two known bugs with modern Docker:
> a `KeyError: 'id'` in the log-attach thread (cosmetic) and a
> `KeyError: 'ContainerConfig'` on recreate. If you're stuck on v1, never use
> `docker-compose restart` after a rebuild (it keeps the **old** image) — instead:
> `docker-compose down && docker-compose up -d`.

### Plain Docker

```bash
docker build -t privacycheck .
docker run --rm -p 3000:3000 privacycheck   # CAP_NET_RAW is a Docker default; probes work out of the box
```

### Local (Node 20+)

```bash
npm install
npm start   # http://localhost:3000  (traceroute/nmap need a Linux host with the tools installed)
```

## Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `3000` | Port the server listens on |
| `LOG_REQUESTS` | `true` | Apache-format access + exec audit logging to stdout; `false` to disable |
| `TRACEROUTE_HIDE_PRIVATE` | `true` | Mask private/RFC1918 hops in traceroute output |
| `TRACEROUTE_HIDE_RANGES` | `193.239.20.0/22` | Comma-separated CIDRs to also mask (e.g. your ISP edge) |
| `PROBE_RATE_MAX` | `10` | Max active probes (traceroute/nmap/portscan) per IP per window |
| `PROBE_RATE_WINDOW_MS` | `60000` | Rate-limit window in ms for the active probes |

## Deploying behind a proxy

The server sets `trust proxy` and reads `X-Forwarded-For`, so put it behind
Traefik / nginx / Caddy / Cloudflare to see real client IPs and the full proxy
chain. On `localhost` (or any private/internal client IP) the geo lookup and the
active probes fall back to the **server's own public IP** and say so.

When proxied, the access log records both IPs shown on the page: the forwarded
client IP as the log host, and the direct proxy peer as `via=`.

## Logging

With `LOG_REQUESTS` on (default), the container writes to stdout (→ `docker logs`):

- **Access log** — Apache *combined* format plus the direct peer:

  ```text
  203.0.113.5 - - [29/May/2026:20:32:44 +0000] "GET /api/info HTTP/1.1" 200 1257 "https://hidden.ch/" "Mozilla/5.0 …" via=172.18.0.9
  ```

- **Exec audit** — every server-side command, who triggered it and as which OS user:

  ```text
  203.0.113.5 - - [29/May/2026:19:14:30 +0000] EXEC (as node) sudo -n nmap -O … 203.0.113.5 via=172.18.0.9
  ```

- **Client public IP** — the browser's own public IP (it can differ from what the
  server sees behind NAT/VPN), reported by the page and logged for correlation:

  ```text
  10.10.10.172 - - [29/May/2026:20:38:40 +0000] CLIENT pubip=188.63.145.121 via=172.18.0.9 "Mozilla/5.0 …"
  ```

These are ephemeral container logs; the app persists nothing itself.

## Traceroute hop masking

Leading hops that are private/RFC1918 or inside `TRACEROUTE_HIDE_RANGES` (default
`193.239.20.0/22`) are shown as `*redacted*` — kept in place (with their RTT) but
with the address and reverse-DNS stripped, so the server's own gateway / ISP edge
isn't exposed. Public hops beyond that are shown normally with hostnames.

## Security notes

- All client-supplied input is treated as untrusted. The client IP fed to
  `traceroute` / `nmap` / the port scan / geo lookups can come from a spoofable
  `X-Forwarded-For` header, so it is validated with **`net.isIP()`** (the kernel
  parser — not a hand-rolled regex that would accept merely address-shaped junk),
  and any value starting with `-` is rejected so a token can never be read as an
  nmap/traceroute flag (argument injection). Hostnames for DNS lookups pass a
  hostname validator. External commands run via `execFile` (no shell) — command
  injection is not possible. The DOM is built without any `innerHTML` sink, so
  server strings can't inject markup. Thanks to @antoinet for pointing me to this :)
- The active probes are **rate-limited per IP** (`PROBE_RATE_MAX` per
  `PROBE_RATE_WINDOW_MS`, default 10/60s) so the server can't be abused as a
  root-privileged scan reflector. Private/internal targets aren't probed — they
  fall back to the server's own public IP.
- Runs as the **non-root** `node` user. `traceroute` works via a file capability
  (`setcap cap_net_raw`); `nmap` (which ignores file caps and demands `euid==0`)
  is allowed via a narrow passwordless `sudo` rule that lets `node` run **only**
  `nmap`. Everything degrades gracefully if raw sockets aren't available.

## Other notes

- **Geo/ASN** and the local-request public-IP fallback come from the free
  [ip-api.com](https://ip-api.com) endpoint (HTTP, 45 req/min, non-commercial).
  The Tor exit list is fetched from the Tor Project and cached hourly. Swap in
  MaxMind GeoLite2 / ipinfo for production scale.
- Adblock, localhost-scan and browser-version checks are **heuristics** — expect
  occasional false positives/negatives.

## Layout

```text
server.js                     Express server + all server-side probes/APIs
public/index.html             Page shell + adblock bait
public/style.css              Dark "recon dashboard" styling
public/app.js                 All client-side recon + rendering
public/ads/advertisement.js   Adblock bait script
Dockerfile
docker-compose.yml-example    Copy to docker-compose.yml and adjust
```

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
| `GET /api/healthz` | Health check |
