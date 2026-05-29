# hidden-homepage

**"What the Internet Knows About You"** — a stylish, single-page privacy-awareness
dashboard. Open it and it instantly surfaces how much your connection and browser
leak, split into **server-side** analysis (from your HTTP request) and
**in-browser** reconnaissance (JavaScript fingerprinting). Nothing is stored — it's
all computed live for your session.

> Educational / privacy-awareness demo. Run it for yourself or visitors who land
> on it. Active probes (port scan, traceroute, nmap, localhost scan) only ever
> target **the visitor's own IP/machine**.

## What it shows

### Server-side (from your request)
- **Client IP** + the direct TCP peer (proxy vs. you)
- **Proxy / forwarding path** — full `X-Forwarded-For` chain, `Via`, CF / true-client-IP headers
- **Reverse DNS (PTR)** for your IP and the peer
- **Geolocation** — country, region, city, postal, lat/lon + embedded OpenStreetMap
- **Timezone & UTC offset** derived from your IP
- **Network operator (ASN)** — AS number, AS name, ISP, org, and proxy/VPN/hosting/mobile flags
- **Languages** parsed from `Accept-Language`
- **Full request headers**, including Client Hints (`Sec-CH-UA-*`)
- **OS & device fingerprint** — passive guess from UA + Client Hints
- **Reverse port scan** — TCP-connect probe of common ports on your public IP (on demand)
- **Active OS detection** — `nmap -O` stack fingerprinting (best effort; needs privileges)
- **Traceroute** — hop-by-hop path from the server back to you (on demand, best effort)

### In-browser (JavaScript)
- Browser, OS, vendor, platform, CPU cores, device memory, touch points, high-entropy UA-CH
- Screen / display: resolution, DPR, color depth, color scheme, reduced-motion, HDR
- Time & locale: timezone, offset, calendar, numbering system
- Privacy signals: cookies, Do-Not-Track, Global Privacy Control, storage quota
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
- **Localhost port scan** — detects services running on the visitor's own machine
- **Precise GPS geolocation** (opt-in, prompts permission)

## Run it

### Docker (recommended)
```bash
docker compose up --build
# open http://localhost:3000
```

Or plain Docker:
```bash
docker build -t hidden-homepage .
docker run --rm -p 3000:3000 --cap-add=NET_RAW --cap-add=NET_ADMIN hidden-homepage
```

### Local (Node 20+)
```bash
npm install
npm start
```

## Deploying behind a proxy

The server sets `trust proxy` and reads `X-Forwarded-For`, so put it behind
nginx / Caddy / Cloudflare to see real client IPs and the full proxy chain. On
`localhost` the geo lookup falls back to the **server's** public IP (and says so).

## Notes & caveats

- **Geo/ASN** come from the free [ip-api.com](https://ip-api.com) endpoint
  (HTTP, 45 req/min, non-commercial). Swap in MaxMind GeoLite2 or ipinfo for
  production scale.
- **traceroute / nmap -O** need raw sockets (`CAP_NET_RAW`, part of Docker's
  default capability set). The app runs as the non-root `node` user, yet both
  work: `traceroute` carries the capability on its binary (`setcap`), and `nmap`
  (which ignores file caps and demands `euid==0`) is allowed via a narrow
  passwordless `sudo` rule that lets `node` run **only** `nmap`. No `--cap-add`
  needed for a plain `docker run`; both still degrade gracefully to the passive
  guess if the capability is dropped.
- **Security:** the client IP fed to `traceroute`/`nmap`/the port scan can come
  from a client-spoofable `X-Forwarded-For` header, so it's strictly validated as
  a real IPv4/IPv6 address and passed via `execFile` (no shell) — command
  injection is not possible.
- Adblock / localhost detection are **heuristics** — timing- and bait-based, so
  occasional false positives/negatives are expected.
- Everything is ephemeral: no database, no logging of visitors, no analytics.

## Layout
```
server.js              Express server + all server-side probes/APIs
public/index.html      Page shell + adblock bait
public/style.css       Dark "recon dashboard" styling
public/app.js          All client-side recon + rendering
public/ads/advertisement.js   Adblock bait script
Dockerfile / docker-compose.yml
```
