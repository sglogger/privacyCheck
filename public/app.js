/* =========================================================================
 *  hidden-homepage — client recon & rendering
 *  Everything runs in your session. Nothing is sent anywhere except the
 *  geo/ASN lookup the server already did for your IP.
 * ========================================================================= */

const grid = document.getElementById("grid");

/* ---------- tiny DOM helpers ---------- */
const el = (tag, attrs = {}, ...kids) => {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null) continue;
    // No innerHTML path on purpose: every value goes in as text/attribute only,
    // so server-supplied strings (headers, IPs, geo) can never inject markup.
    if (k === "class") n.className = v;
    else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids.flat()) {
    if (kid == null) continue;
    n.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return n;
};

let cardCount = 0;
function card(title, icon, side, bodyNodes) {
  cardCount++;
  const tag = side === "server" ? "server-side" : side === "client" ? "in-browser" : "mixed";
  const body = el("div", { class: "card-body" }, ...[].concat(bodyNodes).filter(Boolean));
  const c = el(
    "div",
    { class: "card" },
    el(
      "div",
      { class: "card-head" },
      el("span", { class: "icon" }, icon),
      el("h2", {}, title),
      el("span", { class: `tag ${side || "mixed"}` }, tag)
    ),
    body
  );
  c.style.animationDelay = `${Math.min(cardCount * 35, 600)}ms`;
  return { card: c, body };
}

function row(k, v, cls) {
  const value = v === undefined || v === null || v === "" ? "—" : v;
  return el(
    "div",
    { class: "row" },
    el("span", { class: "k" }, k),
    el("span", { class: `v ${cls || (value === "—" ? "dim" : "")}` }, value)
  );
}

function pillSet(items) {
  // items: [{label, state}]  state: on|off|warn|bad
  const wrap = el("div", {});
  for (const it of items) wrap.append(el("span", { class: `pill ${it.state || ""}` }, it.label));
  return wrap;
}

const add = (c) => grid.append(c);
const yesno = (b) => (b ? "yes" : "no");

/* =========================================================================
 *  SERVER-SIDE INFO
 * ========================================================================= */
async function loadServerInfo() {
  let data;
  try {
    const res = await fetch("/api/info", { headers: { "x-recon": "1" } });
    if (!res.ok) throw new Error("HTTP " + res.status);
    data = await res.json();
  } catch (e) {
    // No backend reachable — almost always means the page was opened as a file
    // or served without the Node server. Make that obvious instead of hanging.
    for (const id of ["hero-ip", "hero-pubip", "hero-loc", "hero-asn"]) {
      const node = document.getElementById(id);
      if (node) node.textContent = "no server";
    }
    add(
      card("Server analysis unavailable", "🛰️", "server", [
        row("error", String(e.message || e), "bad"),
        el("p", { class: "note" },
          "The /api/info endpoint could not be reached. The server-side analysis (IP, geolocation, ASN, Tor, proxy chain, ports) needs the Node backend. Run it via Docker or `npm start` and open the URL it serves — don't open index.html as a file."),
      ]).card
    );
    return;
  }

  const { network, geo, languages, headers, allHeaders, osGuess, tor } = data;

  /* Hero fill */
  document.getElementById("hero-ip").textContent = network.clientIp || "unknown";
  if (geo && geo.status === "success") {
    // geo.query is the real public IP ip-api resolved — baseline for the public
    // IP tile; the client-side fetchPublicIp() overrides it with the browser's
    // independently-observed public IP if that lookup succeeds.
    const pub = document.getElementById("hero-pubip");
    if (pub && pub.textContent === "…") pub.textContent = geo.query || network.clientIp || "—";
    document.getElementById("hero-loc").textContent =
      [geo.city, geo.regionName, geo.country].filter(Boolean).join(", ") || "—";
    document.getElementById("hero-asn").textContent = geo.as || geo.isp || "—";
  } else {
    document.getElementById("hero-loc").textContent = "lookup unavailable";
    document.getElementById("hero-asn").textContent = "—";
  }

  /* Card: connection / IP */
  {
    const b = [
      row("Client IP", network.clientIp),
      row("Direct peer", network.directIp, network.directIp !== network.clientIp ? "warn" : ""),
      row("Behind proxy", yesno(network.behindProxy), network.behindProxy ? "warn" : "good"),
      row("Protocol", `${(network.protocol || "").toUpperCase()} / HTTP ${network.httpVersion}`),
      row("Reverse DNS", network.reverseDns ? network.reverseDns.join(", ") : "no PTR record"),
    ];
    if (network.cfConnectingIp) b.push(row("CF-Connecting-IP", network.cfConnectingIp, "warn"));
    if (network.trueClientIp) b.push(row("True-Client-IP", network.trueClientIp, "warn"));
    add(card("Connection & IP", "🌐", "server", b).card);
  }

  /* Card: proxy chain */
  {
    const b = [];
    if (network.forwardedChain && network.forwardedChain.length) {
      b.push(
        el("p", { class: "note" }, "X-Forwarded-For chain (client → … → us):"),
        el("pre", { class: "block" }, network.forwardedChain.map((ip, i) => `${i}. ${ip}`).join("\n"))
      );
    } else {
      b.push(el("p", { class: "note" }, "No X-Forwarded-For header — you appear to be connecting directly (no detected proxy/CDN in front)."));
    }
    if (network.directReverseDns) b.push(row("Peer reverse DNS", network.directReverseDns.join(", ")));
    add(card("Proxy / forwarding path", "🔀", "server", b).card);
  }

  /* Card: reverse DNS of every discovered IP */
  {
    const c = card("Reverse DNS (all discovered IPs)", "🔁", "server", [
      el("p", { class: "note" }, "PTR lookup for every IP seen so far — your IP, the peer, proxy hops. WebRTC-leaked IPs get added below once detected."),
    ]);
    add(c.card);
    const renderRows = (entries) => {
      for (const e of entries) {
        const val = e.private
          ? "private — no public PTR"
          : e.ptr && e.ptr.length
          ? e.ptr.join(", ")
          : "no PTR record";
        c.body.append(row(e.ip, val, e.ptr && e.ptr.length ? "" : "dim"));
      }
    };
    renderRows(network.discoveredPtr || []);
    // Stash the resolver so the WebRTC card can push its leaked IPs in here too.
    window.__addRdnsRows = renderRows;
  }

  /* Card: forward DNS records of your domain */
  {
    const host = network.reverseDns && network.reverseDns[0];
    const c = card("DNS records (your domain)", "📒", "server", [
      el("p", { class: "note" }, "Forward DNS records for the hostname your IP reverse-resolves to."),
    ]);
    add(c.card);
    if (host) {
      fetch(`/api/dns?host=${encodeURIComponent(host)}`)
        .then((r) => r.json())
        .then((d) => {
          if (!d.available) { c.body.append(row("status", d.reason, "dim")); return; }
          const r = d.records || {};
          const j = (a) => (a && a.length ? a.join(", ") : null);
          c.body.append(
            row("Host", d.host, "full"),
            row("A", j(r.A)),
            row("AAAA", j(r.AAAA)),
            row("CNAME", j(r.CNAME)),
            row("MX", j(r.MX)),
            row("NS", j(r.NS)),
            row("TXT", r.TXT && r.TXT.length ? r.TXT.join(" | ") : null),
            row("SOA", r.SOA)
          );
        })
        .catch((e) => c.body.append(row("error", String(e), "bad")));
    } else {
      c.body.append(el("p", { class: "note" }, "Your IP has no reverse-DNS hostname, so there's no domain to resolve forward records for."));
    }
  }

  /* Card: geolocation + map */
  {
    const b = [];
    if (geo && geo.status === "success") {
      b.push(
        row("Continent", geo.continent),
        row("Country", `${geo.country || ""} ${geo.countryCode ? "(" + geo.countryCode + ")" : ""}`),
        row("Region", `${geo.regionName || ""}${geo.region ? " (" + geo.region + ")" : ""}`),
        row("City", geo.city),
        row("District", geo.district),
        row("Postal", geo.zip),
        row("Coordinates", geo.lat != null ? `${geo.lat}, ${geo.lon}` : null),
        row("Timezone", geo.timezone),
        row("UTC offset", geo.offset != null ? `${geo.offset / 3600 >= 0 ? "+" : ""}${geo.offset / 3600}h` : null),
        row("Currency", geo.currency)
      );
      if (geo._note) b.push(el("p", { class: "note" }, geo._note));
      if (geo.lat != null && geo.lon != null) {
        const d = 0.05;
        const bbox = `${geo.lon - d}%2C${geo.lat - d}%2C${geo.lon + d}%2C${geo.lat + d}`;
        const src = `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${geo.lat}%2C${geo.lon}`;
        b.push(el("div", { class: "map-wrap" }, el("iframe", { src, loading: "lazy", title: "approx location" })));
        b.push(el("p", { class: "note" }, "Approximate — IP geolocation is city-level at best, often the ISP's POP."));
      }
    } else {
      b.push(row("status", (geo && geo.message) || "unavailable", "bad"));
    }
    const geoCard = card("Geolocation", "📍", "server", b).card;
    geoCard.style.order = "-3"; // pull to the very front of the grid
    add(geoCard);
  }

  /* Card: network operator / ASN */
  {
    const b = [];
    if (geo && geo.status === "success") {
      b.push(
        row("AS", geo.as),
        row("AS name", geo.asname),
        row("ISP", geo.isp),
        row("Organization", geo.org),
        el(
          "div",
          { class: "row" },
          el("span", { class: "k" }, "Flags"),
          el(
            "span",
            { class: "v full" },
            pillSet([
              { label: "mobile", state: geo.mobile ? "warn" : "off" },
              { label: "proxy/vpn", state: geo.proxy ? "bad" : "off" },
              { label: "hosting/DC", state: geo.hosting ? "warn" : "off" },
            ])
          )
        )
      );
    } else {
      b.push(row("status", "unavailable", "bad"));
    }
    const asnCard = card("Network operator (ASN)", "🛰️", "server", b).card;
    asnCard.style.order = "-2"; // right after Geolocation
    add(asnCard);
  }

  /* Card: Tor / anonymization */
  {
    const b = [];
    const proxyFlag = geo && geo.status === "success" && geo.proxy;
    const hostingFlag = geo && geo.status === "success" && geo.hosting;
    if (tor && tor.available) {
      b.push(
        row("Tor exit node", tor.isExitNode ? "YES — request via Tor" : "no", tor.isExitNode ? "bad" : "good"),
        row("Exit list size", tor.listSize != null ? tor.listSize.toLocaleString() + " nodes" : "—"),
        row("List updated", tor.listUpdated ? new Date(tor.listUpdated).toLocaleString() : "—", "dim")
      );
      if (tor.stale) b.push(el("p", { class: "note warn" }, "Using a cached list — last refresh failed."));
    } else {
      b.push(row("Tor exit node", "check unavailable", "dim"));
      if (tor && tor.reason) b.push(el("p", { class: "note" }, tor.reason));
    }
    b.push(
      row("IP-DB proxy/VPN flag", geo && geo.status === "success" ? (proxyFlag ? "flagged" : "no") : "—", proxyFlag ? "warn" : ""),
      row("Datacenter / hosting", geo && geo.status === "success" ? (hostingFlag ? "yes" : "no") : "—", hostingFlag ? "warn" : ""),
      el("div", { class: "row" },
        el("span", { class: "k" }, "Verdict"),
        el("span", { class: `v ${tor && tor.isExitNode ? "bad" : proxyFlag || hostingFlag ? "warn" : "good"}` },
          tor && tor.isExitNode ? "🧅 Tor" : proxyFlag ? "🕵️ proxy/VPN" : hostingFlag ? "🖥️ datacenter IP" : "✓ looks like a direct residential connection"))
    );
    add(card("Anonymization (Tor / VPN / proxy)", "🧅", "server", b).card);
  }

  /* Card: accept-language */
  {
    const b = [];
    if (languages && languages.length) {
      b.push(
        el(
          "div",
          { class: "row" },
          el("span", { class: "k" }, "Preferred"),
          el("span", { class: "v full" }, pillSet(languages.map((l) => ({ label: `${l.tag} (q=${l.q})`, state: "on" }))))
        ),
        el("p", { class: "note" }, "Sent in your Accept-Language header on every request.")
      );
    } else b.push(row("Accept-Language", "not sent"));
    add(card("Browser languages (server-seen)", "🗣️", "server", b).card);
  }

  /* Card: request headers */
  {
    const lines = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
    const c = card("Request headers you sent", "📨", "server", [
      el("p", { class: "note" }, "The interesting subset of headers your browser attached:"),
      el("pre", { class: "block" }, lines || "(none)"),
      el("details", {}, el("summary", { class: "note", style: "cursor:pointer" }, "Show ALL headers"),
        el("pre", { class: "block" }, Object.entries(allHeaders).map(([k, v]) => `${k}: ${v}`).join("\n"))),
    ]);
    c.card.classList.add("span-2"); // wide card: span two columns
    add(c.card);
  }

  /* Card: OS / device fingerprint (passive) */
  if (osGuess) {
    add(card("OS & device fingerprint", "🧬", "server", [
      row("Operating system", osGuess.os),
      row("Browser", osGuess.browser),
      row("Device type", osGuess.device),
      row("CPU arch", osGuess.arch),
      row("Device model", osGuess.model),
      el("p", { class: "note" }, "Inferred passively from your User-Agent and Client-Hint headers — no probing required."),
    ]).card);
  }

  /* Card: reverse port scan (on demand) */
  {
    const out = el("div", {});
    const btn = el("button", { class: "btn ghost", onclick: async () => {
      btn.disabled = true;
      out.replaceChildren(el("p", { class: "note" }, el("span", { class: "spinner" }), " probing common TCP ports on your IP…"));
      try {
        const r = await (await fetch("/api/portscan")).json();
        if (!r.available) { out.replaceChildren(el("p", { class: "note" }, r.reason)); btn.disabled = false; return; }
        out.replaceChildren(
          r.note ? el("p", { class: "note warn" }, r.note) : document.createTextNode(""),
          el("p", { class: "note" }, `Scanned ${r.ports.length} ports on ${r.target} — ${r.open} open:`),
          el("div", {}, pillSet(r.ports.map((p) => ({
            label: `${p.port} ${p.service}`,
            state: p.state === "open" ? "bad" : p.state === "closed" ? "off" : "warn",
          })))),
          el("p", { class: "note" }, "Open = reachable from the internet (red). Filtered = no response (firewall/NAT). Closed = refused."),
        );
      } catch (e) { out.replaceChildren(el("p", { class: "note bad" }, "scan failed: " + e)); }
      btn.disabled = false;
    } }, "Scan my open ports →");
    add(card("Reverse port scan (server → you)", "🔓", "server", [
      el("p", { class: "note" }, "TCP-connect probe of common ports on your public IP, straight from the container. Only your own IP is scanned."),
      btn, out,
    ]).card);
  }

  /* Card: active OS detection (nmap, best effort) */
  {
    const out = el("div", {});
    const btn = el("button", { class: "btn ghost", onclick: async () => {
      btn.disabled = true;
      out.replaceChildren(el("p", { class: "note" }, el("span", { class: "spinner" }), " running nmap OS detection (may take ~30s)…"));
      try {
        const r = await (await fetch("/api/osdetect")).json();
        if (r.available) out.replaceChildren(
          r.note ? el("p", { class: "note warn" }, r.note) : document.createTextNode(""),
          el("pre", { class: "block" }, r.nmap)
        );
        else out.replaceChildren(el("p", { class: "note" }, r.reason));
      } catch (e) { out.replaceChildren(el("p", { class: "note bad" }, "failed: " + e)); }
      btn.disabled = false;
    } }, "Active OS detection (nmap) →");
    const c = card("Active OS detection (nmap)", "🩻", "server", [
      el("p", { class: "note" }, "TCP/IP stack fingerprinting via nmap -O. Needs raw-socket privileges in the container; otherwise falls back to the passive guess above."),
      btn, out,
    ]);
    c.card.classList.add("span-2"); // wide: nmap output is a broad text table
    add(c.card);
  }

  /* Card: traceroute (lazy, on demand) */
  {
    const out = el("div", {});
    const btn = el("button", {
      class: "btn ghost",
      onclick: async () => {
        btn.disabled = true;
        out.replaceChildren(el("p", { class: "note" }, el("span", { class: "spinner" }), " tracing route back to you…"));
        try {
          const r = await (await fetch("/api/traceroute")).json();
          if (r.available && r.hops.length) {
            const redMsg = r.redactedCount
              ? `${r.redactedCount} hop${r.redactedCount > 1 ? "s" : ""} redacted (private${r.hideConfig && r.hideConfig.ranges.length ? " / " + r.hideConfig.ranges.join(", ") : ""}).`
              : null;
            out.replaceChildren(
              r.note ? el("p", { class: "note warn" }, r.note) : document.createTextNode(""),
              redMsg ? el("p", { class: "note" }, redMsg) : document.createTextNode(""),
              el("p", { class: "note" }, `Path from the server to ${r.target}:`),
              el("pre", { class: "block" }, r.hops.map((h) => {
                const addr = h.redacted ? "*redacted*" : (h.ip || "*");
                const host = h.redacted ? "" : (h.host && h.host.length ? h.host[0] : "");
                return `${String(h.hop).padStart(2)}  ${addr.padEnd(16)}  ${h.rttMs != null ? (h.rttMs + " ms").padEnd(10) : "".padEnd(10)}${host}`;
              }).join("\n"))
            );
          } else {
            out.replaceChildren(el("p", { class: "note" }, r.reason || "unavailable"));
          }
        } catch (e) {
          out.replaceChildren(el("p", { class: "note bad" }, "traceroute failed: " + e));
        }
        btn.disabled = false;
      },
    }, "Run traceroute →");
    const c = card("Traceroute (server → you)", "🛤️", "server", [
      el("p", { class: "note" }, "Best-effort hop-by-hop path from the container back to your IP. Often blocked by ICMP filtering."),
      btn, out,
    ]);
    c.card.classList.add("span-2"); // wide: hop lines include IP + RTT + hostname
    add(c.card);
  }

  document.getElementById("footer-meta").textContent =
    `server time ${data.serverTime} · client ip ${network.clientIp}`;
}

/* =========================================================================
 *  CLIENT-SIDE INFO
 * ========================================================================= */
function loadClientInfo() {
  const n = navigator;

  /* ---- Browser & OS (incl. UA-CH) ---- */
  {
    const b = [
      row("User agent", n.userAgent, "full"),
      row("Platform", n.platform),
      row("Vendor", n.vendor),
      row("Languages", (n.languages || []).join(", ")),
      row("CPU cores", n.hardwareConcurrency),
      row("Device memory", n.deviceMemory != null ? n.deviceMemory + " GB (approx)" : "hidden"),
      row("Touch points", n.maxTouchPoints),
      row("Online", yesno(n.onLine)),
      row("PDF viewer", yesno(n.pdfViewerEnabled)),
      row("Java enabled", typeof n.javaEnabled === "function" ? yesno(n.javaEnabled()) : "—"),
    ];
    const c = card("Browser & device", "🧭", "client", b);
    add(c.card);
    // High-entropy User-Agent Client Hints (Chromium)
    if (n.userAgentData && n.userAgentData.getHighEntropyValues) {
      n.userAgentData
        .getHighEntropyValues(["architecture", "bitness", "model", "platformVersion", "fullVersionList", "wow64"])
        .then((uah) => {
          c.body.append(
            row("UA-CH platform", `${uah.platform || ""} ${uah.platformVersion || ""}`.trim()),
            row("UA-CH arch", `${uah.architecture || ""} ${uah.bitness ? uah.bitness + "-bit" : ""}`.trim()),
            row("UA-CH model", uah.model || "(none)"),
            row("Brands", (uah.fullVersionList || uah.brands || []).map((x) => `${x.brand} ${x.version}`).join(", "))
          );
        })
        .catch(() => {});
    }
  }

  /* ---- Browser version / up-to-date check ---- */
  {
    const bv = detectBrowserVersion();
    const latest = LATEST_STABLE[bv.name];
    const b = [
      row("Browser", bv.name),
      row("Your version", bv.major != null ? "v" + bv.major : "unknown"),
      row("Latest known", latest != null ? "v" + latest + " (ref.)" : "unknown"),
    ];
    if (bv.major != null && latest != null) {
      const behind = latest - bv.major;
      // Safari bumps majors slowly, so be stricter there.
      const strict = bv.name === "Safari";
      let verdict, cls;
      if (behind <= 0) { verdict = "✓ up to date"; cls = "good"; }
      else if (behind <= (strict ? 0 : 2)) { verdict = `slightly behind (${behind} version${behind > 1 ? "s" : ""})`; cls = "warn"; }
      else { verdict = `⚠ outdated — ${behind} versions behind`; cls = "bad"; }
      b.push(el("div", { class: "row" },
        el("span", { class: "k" }, "Status"),
        el("span", { class: `v ${cls}` }, verdict)));
    } else {
      b.push(row("Status", "can't determine version", "dim"));
    }
    b.push(el("p", { class: "note" }, "Heuristic: your version is parsed from the User-Agent / Client Hints and compared to reference latest-stable versions (early 2026). An outdated browser is a real security risk."));
    add(card("Browser up to date?", "🆙", "client", b).card);
  }

  /* ---- Screen & display ---- */
  {
    const s = screen;
    add(card("Screen & display", "🖥️", "client", [
      row("Resolution", `${s.width} × ${s.height}`),
      row("Available", `${s.availWidth} × ${s.availHeight}`),
      row("Window", `${innerWidth} × ${innerHeight}`),
      row("Color depth", s.colorDepth + "-bit"),
      row("Pixel ratio", devicePixelRatio),
      row("Orientation", (s.orientation && s.orientation.type) || "—"),
      row("Color scheme", matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light"),
      row("Reduced motion", matchMedia("(prefers-reduced-motion: reduce)").matches ? "yes" : "no"),
      row("HDR", matchMedia("(dynamic-range: high)").matches ? "yes" : "no"),
    ]).card);
  }

  /* ---- Time & locale ---- */
  {
    const dtf = Intl.DateTimeFormat().resolvedOptions();
    const nf = Intl.NumberFormat().resolvedOptions();
    add(card("Time & locale", "🕒", "client", [
      row("Timezone", dtf.timeZone),
      row("UTC offset", `${-new Date().getTimezoneOffset() / 60 >= 0 ? "+" : ""}${-new Date().getTimezoneOffset() / 60}h`),
      row("Locale", dtf.locale),
      row("Calendar", dtf.calendar),
      row("Numbering", nf.numberingSystem),
      row("Local time", new Date().toString(), "full"),
    ]).card);
  }

  /* ---- Privacy signals & storage ---- */
  {
    let ls = false, ss = false, idb = false;
    try { localStorage.setItem("_t", "1"); localStorage.removeItem("_t"); ls = true; } catch {}
    try { sessionStorage.setItem("_t", "1"); sessionStorage.removeItem("_t"); ss = true; } catch {}
    try { idb = !!indexedDB; } catch {}
    const b = [
      row("Cookies enabled", yesno(n.cookieEnabled), n.cookieEnabled ? "warn" : "good"),
      row("Do Not Track", n.doNotTrack || msTrackingProtectionEnabledSafe() || "not set"),
      row("Global Privacy Control", n.globalPrivacyControl === true ? "on" : n.globalPrivacyControl === false ? "off" : "not set"),
      el("div", { class: "row" }, el("span", { class: "k" }, "Storage"),
        el("span", { class: "v full" }, pillSet([
          { label: "localStorage", state: ls ? "on" : "off" },
          { label: "sessionStorage", state: ss ? "on" : "off" },
          { label: "indexedDB", state: idb ? "on" : "off" },
        ]))),
    ];
    const c = card("Privacy & storage", "🔐", "client", b);
    add(c.card);
    if (navigator.storage && navigator.storage.estimate) {
      navigator.storage.estimate().then((est) => {
        c.body.append(row("Storage quota", est.quota ? (est.quota / 1073741824).toFixed(1) + " GB" : "—"));
      }).catch(() => {});
    }
  }

  function msTrackingProtectionEnabledSafe() {
    try { return window.external && window.external.msTrackingProtectionEnabled && window.external.msTrackingProtectionEnabled() ? "on (IE TPL)" : null; }
    catch { return null; }
  }

  /* ---- Cookies ---- */
  {
    // Demonstrate the mechanism: set a first-party cookie, then read everything
    // JS can see for this origin. HttpOnly / other-origin cookies stay invisible.
    try {
      document.cookie = "hh_demo=set_by_this_page; path=/; max-age=3600; SameSite=Lax";
    } catch {}

    const raw = document.cookie || "";
    const cookies = raw
      .split(";")
      .map((c) => c.trim())
      .filter(Boolean)
      .map((c) => {
        const i = c.indexOf("=");
        return i === -1 ? { name: c, value: "" } : { name: c.slice(0, i), value: c.slice(i + 1) };
      });

    const b = [
      row("Cookies enabled", yesno(n.cookieEnabled), n.cookieEnabled ? "warn" : "good"),
      row("Readable cookies", cookies.length, cookies.length ? "warn" : "good"),
    ];

    if (cookies.length) {
      const rows = cookies.map((c) =>
        el("div", { class: "row" },
          el("span", { class: "k" }, c.name),
          el("span", { class: "v" }, c.value.length > 80 ? c.value.slice(0, 80) + "…" : decodeURIComponent(c.value || "(empty)")))
      );
      b.push(el("div", {}, ...rows));
    } else {
      b.push(el("p", { class: "note" }, "No first-party cookies readable from JavaScript on this origin."));
    }

    b.push(
      el("p", { class: "note" }, "Only this site's non-HttpOnly cookies are visible to JavaScript. HttpOnly cookies and cookies from other domains are hidden by the same-origin policy — a tracker can still correlate you across sites it's embedded on.")
    );

    add(card("Cookies (this site, JS-readable)", "🍪", "client", b).card);
  }

  /* ---- Network connection ---- */
  {
    const conn = n.connection || n.mozConnection || n.webkitConnection;
    const b = conn
      ? [
          row("Type", conn.effectiveType),
          row("Downlink", conn.downlink != null ? conn.downlink + " Mbps" : "—"),
          row("RTT", conn.rtt != null ? conn.rtt + " ms" : "—"),
          row("Save-Data", conn.saveData ? "on" : "off"),
        ]
      : [el("p", { class: "note" }, "Network Information API not exposed by this browser.")];
    add(card("Network conditions", "📶", "client", b).card);
  }

  /* ---- GPU / WebGL ---- */
  {
    const b = [];
    try {
      const cv = document.createElement("canvas");
      const gl = cv.getContext("webgl") || cv.getContext("experimental-webgl");
      if (gl) {
        const dbg = gl.getExtension("WEBGL_debug_renderer_info");
        b.push(
          row("Vendor", dbg ? gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR), "full"),
          row("Renderer", dbg ? gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER), "full"),
          row("GLSL", gl.getParameter(gl.SHADING_LANGUAGE_VERSION)),
          row("Max texture", gl.getParameter(gl.MAX_TEXTURE_SIZE))
        );
      } else b.push(row("WebGL", "unavailable", "warn"));
    } catch (e) {
      b.push(row("WebGL", "blocked", "warn"));
    }
    add(card("GPU / WebGL", "🎮", "client", b).card);
  }

  /* ---- Fingerprints (canvas + audio) ---- */
  {
    const c = card("Device fingerprints", "🫆", "client", [
      el("p", { class: "note" }, "Hashes derived from how your exact hardware/driver stack renders. Stable across reloads → trackable without cookies."),
    ]);
    add(c.card);
    // canvas
    try {
      const cv = document.createElement("canvas");
      cv.width = 240; cv.height = 60;
      const ctx = cv.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "16px 'Arial'";
      ctx.fillStyle = "#f60"; ctx.fillRect(2, 2, 120, 28);
      ctx.fillStyle = "#069"; ctx.fillText("hidden-homepage \u{1F575}\u{FE0F}", 4, 6);
      ctx.fillStyle = "rgba(102,204,0,0.7)"; ctx.fillText("hidden-homepage \u{1F575}\u{FE0F}", 6, 20);
      // The canvas is rendered only to derive the fingerprint hash; we don't
      // show the (ugly) bitmap itself — the hash is the meaningful signal.
      const data = cv.toDataURL();
      hash(data).then((h) => c.body.append(row("Canvas hash", h, "full")));
    } catch { c.body.append(row("Canvas", "blocked", "warn")); }
    // audio
    audioFingerprint().then((h) => c.body.append(row("Audio hash", h || "blocked/unavailable", h ? "full" : "warn"))).catch(() => {});
  }

  /* ---- Fonts detection ---- */
  {
    const c = card("Installed fonts (detected)", "🔤", "client", [
      el("p", { class: "note" }, el("span", { class: "spinner" }), " probing common fonts via metric differences…"),
    ]);
    add(c.card);
    setTimeout(() => {
      const found = detectFonts();
      c.body.replaceChildren(
        el("p", { class: "note" }, `${found.length} of ${FONT_LIST.length} probed fonts present:`),
        el("div", {}, pillSet(found.map((f) => ({ label: f, state: "on" }))))
      );
    }, 50);
  }

  /* ---- Plugins & MIME ---- */
  {
    const plugins = Array.from(n.plugins || []).map((p) => p.name);
    const mimes = Array.from(n.mimeTypes || []).map((m) => m.type);
    add(card("Plugins & MIME types", "🧩", "client", [
      plugins.length
        ? el("div", {}, pillSet(plugins.map((p) => ({ label: p, state: "on" }))))
        : el("p", { class: "note" }, "navigator.plugins is empty — modern Chrome/Firefox return a fixed stub list or nothing for privacy."),
      mimes.length ? el("details", {}, el("summary", { class: "note", style: "cursor:pointer" }, `${mimes.length} MIME types`), el("pre", { class: "block" }, mimes.join("\n"))) : null,
    ]).card);
  }

  /* ---- Feature / API surface (extension & capability hints) ---- */
  {
    const feats = [
      ["WebRTC", "RTCPeerConnection" in window],
      ["WebGL2", "WebGL2RenderingContext" in window],
      ["WebGPU", "gpu" in navigator],
      ["WebAuthn", "credentials" in navigator && "PublicKeyCredential" in window],
      ["Web Bluetooth", "bluetooth" in navigator],
      ["WebUSB", "usb" in navigator],
      ["Web Serial", "serial" in navigator],
      ["WebHID", "hid" in navigator],
      ["Web NFC", "NDEFReader" in window],
      ["Gamepad", "getGamepads" in navigator],
      ["Speech synth", "speechSynthesis" in window],
      ["Service Worker", "serviceWorker" in navigator],
      ["Push API", "PushManager" in window],
      ["Notifications", "Notification" in window],
      ["Payment Request", "PaymentRequest" in window],
      ["Credential Mgmt", "credentials" in navigator],
      ["Idle Detection", "IdleDetector" in window],
      ["WebTransport", "WebTransport" in window],
      ["WebCodecs", "VideoEncoder" in window],
      ["SharedArrayBuffer", "SharedArrayBuffer" in window],
      ["WASM", "WebAssembly" in window],
      ["Battery API", "getBattery" in navigator],
    ];
    add(card("Browser capabilities", "⚙️", "client", [
      el("div", {}, pillSet(feats.map(([label, on]) => ({ label, state: on ? "on" : "off" })))),
    ]).card);
  }

  /* ---- Adblocker & tracker-blocker detection ---- */
  {
    const c = card("Ad / tracker blockers", "🛡️", "client", [
      el("p", { class: "note" }, el("span", { class: "spinner" }), " running bait tests…"),
    ]);
    add(c.card);
    detectAdblock().then((res) => {
      c.body.replaceChildren(
        row("Bait element hidden", res.baitHidden ? "yes" : "no", res.baitHidden ? "warn" : "good"),
        row("Ad script blocked", res.scriptBlocked ? "yes" : "no", res.scriptBlocked ? "warn" : "good"),
        row("Tracker request blocked", res.trackerBlocked ? "yes" : "no", res.trackerBlocked ? "warn" : "good"),
        el("div", { class: "row" },
          el("span", { class: "k" }, "Verdict"),
          el("span", { class: `v ${res.blocking ? "warn" : "good"}` }, res.blocking ? "🛑 ad/tracker blocker active" : "no blocker detected")),
        el("p", { class: "note" }, "Detected by checking whether known ad/tracker resources get hidden or fail to load.")
      );
    });
  }

  /* ---- Permissions snapshot ---- */
  {
    const c = card("Permission states", "✋", "client", [
      el("p", { class: "note" }, "Current grant state — queried without prompting."),
    ]);
    add(c.card);
    if (navigator.permissions && navigator.permissions.query) {
      const names = ["geolocation", "notifications", "camera", "microphone", "clipboard-read", "midi", "background-sync"];
      Promise.allSettled(names.map((name) => navigator.permissions.query({ name }))).then((rs) => {
        const pills = rs.map((r, i) => ({
          label: `${names[i]}: ${r.status === "fulfilled" ? r.value.state : "n/a"}`,
          state: r.status === "fulfilled" ? (r.value.state === "granted" ? "on" : r.value.state === "denied" ? "bad" : "off") : "off",
        }));
        c.body.append(el("div", {}, pillSet(pills)));
      });
    } else c.body.append(el("p", { class: "note" }, "Permissions API unavailable."));
  }

  /* ---- Media devices (count, no labels until granted) ---- */
  {
    const c = card("Media devices", "🎥", "client", []);
    add(c.card);
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      navigator.mediaDevices.enumerateDevices().then((devs) => {
        const counts = { audioinput: 0, audiooutput: 0, videoinput: 0 };
        devs.forEach((d) => (counts[d.kind] = (counts[d.kind] || 0) + 1));
        c.body.append(
          row("Microphones", counts.audioinput),
          row("Speakers", counts.audiooutput),
          row("Cameras", counts.videoinput),
          el("p", { class: "note" }, "Device labels stay hidden until you grant camera/mic — counts alone are still fingerprintable.")
        );
      }).catch(() => c.body.append(row("status", "unavailable", "warn")));
    } else c.body.append(row("status", "unavailable", "warn"));
  }

  /* ---- Battery ---- */
  {
    if (navigator.getBattery) {
      const c = card("Battery", "🔋", "client", []);
      add(c.card);
      navigator.getBattery().then((bat) => {
        c.body.append(
          row("Level", Math.round(bat.level * 100) + "%"),
          row("Charging", yesno(bat.charging)),
          row("Time to full", bat.chargingTime === Infinity ? "—" : bat.chargingTime + "s"),
          row("Time to empty", bat.dischargingTime === Infinity ? "—" : bat.dischargingTime + "s")
        );
      });
    }
  }

  /* ---- Localhost port scan (browser-side, runs automatically) ---- */
  {
    const out = el("div", {}, el("p", { class: "note" }, el("span", { class: "spinner" }), " probing services on your own machine…"));
    add(card("Local services on YOUR machine", "🖧", "client", [
      el("p", { class: "note" }, "JavaScript silently pokes localhost ports from this page — revealing apps running on your own computer. This ran on load, no click needed."),
      out,
    ]).card);
    scanLocalhost().then((res) => {
      out.replaceChildren(
        el("p", { class: "note" }, "Heuristic — distinguishes refused vs responding ports by timing:"),
        el("div", {}, pillSet(res.map((r) => ({ label: `${r.port} ${r.service}`, state: r.likelyOpen ? "bad" : "off" })))),
        el("p", { class: "note" }, "Ports flagged red likely have a local service listening (dev servers, databases, etc.).")
      );
    });
  }

  /* ---- WebRTC local IP leak ---- */
  {
    const c = card("WebRTC IP leak", "💧", "client", [
      el("p", { class: "note" }, el("span", { class: "spinner" }), " gathering ICE candidates…"),
    ]);
    add(c.card);
    webrtcIps().then((ips) => {
      const list = Object.entries(ips);
      c.body.replaceChildren(
        el("p", { class: "note" }, "IP addresses leaked via WebRTC (can bypass VPNs/proxies):"),
        list.length
          ? el("div", {}, pillSet(list.map(([ip, kind]) => ({ label: `${ip} (${kind})`, state: kind === "public" ? "bad" : "warn" }))))
          : el("p", { class: "note good" }, "No candidate IPs leaked (blocked or unsupported).")
      );
      // Reverse-resolve the leaked IPs server-side and add them to the rDNS card.
      const ipsParam = list.map(([ip]) => ip).join(",");
      if (ipsParam) {
        fetch(`/api/rdns?ips=${encodeURIComponent(ipsParam)}`)
          .then((r) => r.json())
          .then((d) => {
            if (d.available && d.results.length && window.__addRdnsRows) window.__addRdnsRows(d.results);
          })
          .catch(() => {});
      }
    });
  }

  /* ---- Geolocation (explicit, on demand) ---- */
  {
    const out = el("div", {});
    const btn = el("button", { class: "btn ghost", onclick: () => {
      out.replaceChildren(el("p", { class: "note" }, el("span", { class: "spinner" }), " requesting precise location…"));
      navigator.geolocation.getCurrentPosition(
        (pos) => {
          const { latitude: lat, longitude: lon, accuracy } = pos.coords;
          // Map window sized to the reported accuracy (clamped to a sane range).
          const d = Math.min(0.05, Math.max(0.002, (accuracy || 100) / 111000));
          const bbox = `${lon - d}%2C${lat - d}%2C${lon + d}%2C${lat + d}`;
          const src = `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${lat}%2C${lon}`;
          out.replaceChildren(
            row("Latitude", lat.toFixed(6)),
            row("Longitude", lon.toFixed(6)),
            row("Accuracy", Math.round(accuracy) + " m"),
            row("Altitude", pos.coords.altitude != null ? Math.round(pos.coords.altitude) + " m" : "—"),
            row("Heading", pos.coords.heading != null ? pos.coords.heading + "°" : "—"),
            row("Speed", pos.coords.speed != null ? pos.coords.speed + " m/s" : "—"),
            el("div", { class: "map-wrap" }, el("iframe", { src, loading: "lazy", title: "your precise location" })),
            el("p", { class: "note" },
              el("a", { href: `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=17/${lat}/${lon}`, target: "_blank", rel: "noopener" }, "Open full map →"))
          );
        },
        (err) => out.replaceChildren(el("p", { class: "note bad" }, "denied / failed: " + err.message)),
        { enableHighAccuracy: true, timeout: 10000 }
      );
    } }, "Reveal precise GPS location →");
    add(card("Precise geolocation (GPS)", "🛰️", "client", [
      el("p", { class: "note" }, "Opt-in: this prompts the browser permission dialog. GPS-grade, meter-level — far sharper than IP geo."),
      btn, out,
    ]).card);
  }
}

/* =========================================================================
 *  low-level recon utilities
 * ========================================================================= */
// Reference latest *stable major* versions (approx, early 2026). Browsers
// release fast, so this is a heuristic — update the numbers to stay accurate.
const LATEST_STABLE = { Chrome: 132, Edge: 132, Opera: 117, Firefox: 134, Safari: 18 };

function detectBrowserVersion() {
  const ua = navigator.userAgent;
  let name = "unknown", major = null;
  // UA-CH gives the most reliable brand+version on Chromium browsers.
  const brands = navigator.userAgentData && navigator.userAgentData.brands;
  if (brands) {
    const real = brands.find((b) => !/Not.?A.?Brand/i.test(b.brand));
    if (real) major = parseInt(real.version, 10);
  }
  if (/Edg\//.test(ua)) { name = "Edge"; major = major || +(ua.match(/Edg\/(\d+)/) || [])[1]; }
  else if (/OPR\//.test(ua)) { name = "Opera"; major = +(ua.match(/OPR\/(\d+)/) || [])[1] || major; }
  else if (/Firefox\//.test(ua)) { name = "Firefox"; major = +(ua.match(/Firefox\/(\d+)/) || [])[1]; }
  else if (/Chrome\//.test(ua)) { name = "Chrome"; major = major || +(ua.match(/Chrome\/(\d+)/) || [])[1]; }
  else if (/Safari\//.test(ua) && /Version\//.test(ua)) { name = "Safari"; major = +(ua.match(/Version\/(\d+)/) || [])[1]; }
  return { name, major: Number.isFinite(major) ? major : null };
}

async function hash(str) {
  try {
    const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
    return Array.from(new Uint8Array(buf)).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 32);
  } catch {
    let h = 0; for (let i = 0; i < str.length; i++) h = (h * 31 + str.charCodeAt(i)) | 0;
    return "fnv:" + (h >>> 0).toString(16);
  }
}

async function audioFingerprint() {
  try {
    const Ctx = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (!Ctx) return null;
    const ctx = new Ctx(1, 44100, 44100);
    const osc = ctx.createOscillator();
    osc.type = "triangle";
    osc.frequency.value = 10000;
    const comp = ctx.createDynamicsCompressor();
    osc.connect(comp); comp.connect(ctx.destination);
    osc.start(0);
    const buf = await ctx.startRendering();
    const data = buf.getChannelData(0).slice(4500, 5000);
    let sum = 0; for (const v of data) sum += Math.abs(v);
    return hash(sum.toString());
  } catch { return null; }
}

const FONT_LIST = [
  "Arial", "Arial Black", "Calibri", "Cambria", "Comic Sans MS", "Consolas", "Courier New",
  "Georgia", "Helvetica", "Helvetica Neue", "Impact", "Lucida Console", "Menlo", "Monaco",
  "Palatino", "Segoe UI", "Tahoma", "Times New Roman", "Trebuchet MS", "Verdana",
  "Roboto", "Ubuntu", "Cantarell", "DejaVu Sans", "Liberation Sans", "Noto Sans",
  "SF Pro Text", "Microsoft YaHei", "PingFang SC", "Hiragino Kaku Gothic Pro",
];
function detectFonts() {
  const base = ["monospace", "sans-serif", "serif"];
  const text = "mmmmmmmmmmlli WWWW";
  const size = "72px";
  const span = document.createElement("span");
  span.style.cssText = "position:absolute;left:-9999px;font-size:" + size + ";";
  span.textContent = text;
  document.body.appendChild(span);
  const baseDims = {};
  for (const b of base) { span.style.fontFamily = b; baseDims[b] = [span.offsetWidth, span.offsetHeight]; }
  const found = [];
  for (const f of FONT_LIST) {
    let detected = false;
    for (const b of base) {
      span.style.fontFamily = `'${f}',${b}`;
      if (span.offsetWidth !== baseDims[b][0] || span.offsetHeight !== baseDims[b][1]) { detected = true; break; }
    }
    if (detected) found.push(f);
  }
  document.body.removeChild(span);
  return found;
}

async function detectAdblock() {
  const res = { baitHidden: false, scriptBlocked: false, trackerBlocked: false, blocking: false };

  // 1) bait element from index.html
  const bait = document.getElementById("ad-bait");
  if (bait) {
    const cs = getComputedStyle(bait);
    res.baitHidden = bait.offsetParent === null || cs.display === "none" || cs.visibility === "hidden" || bait.offsetHeight === 0;
  }

  // 2) try to load a known ad script filename (most lists block this path)
  res.scriptBlocked = await new Promise((resolve) => {
    const s = document.createElement("script");
    s.src = "/ads/advertisement.js?_=" + (location.search.length); // local stub, blocked by name patterns
    let done = false;
    const finish = (blocked) => { if (!done) { done = true; s.remove(); resolve(blocked); } };
    s.onload = () => finish(false);
    s.onerror = () => finish(true);
    document.body.appendChild(s);
    setTimeout(() => finish(true), 2500);
  });

  // 3) attempt a fetch to a well-known tracker host; blockers abort it
  res.trackerBlocked = await new Promise((resolve) => {
    fetch("https://www.google-analytics.com/analytics.js", { mode: "no-cors", cache: "no-store" })
      .then(() => resolve(false))
      .catch(() => resolve(true));
    setTimeout(() => resolve(true), 2500);
  });

  res.blocking = res.baitHidden || res.scriptBlocked || res.trackerBlocked;
  return res;
}

// Browser-side localhost probe. A refused port errors almost instantly; an
// open port that speaks a different protocol stalls until our short timeout.
// That timing gap is the (imperfect) signal.
const LOCAL_PORTS = [
  { port: 22, service: "SSH" }, { port: 80, service: "HTTP" },
  { port: 443, service: "HTTPS" }, { port: 3000, service: "dev server" },
  { port: 3306, service: "MySQL" }, { port: 5000, service: "Flask/dev" },
  { port: 5432, service: "Postgres" }, { port: 6379, service: "Redis" },
  { port: 8000, service: "dev server" }, { port: 8080, service: "HTTP-alt" },
  { port: 8443, service: "HTTPS-alt" }, { port: 9000, service: "misc" },
  { port: 9200, service: "Elasticsearch" }, { port: 27017, service: "MongoDB" },
  { port: 11434, service: "Ollama" }, { port: 5173, service: "Vite" },
];
function probeLocal(port, timeout = 1200) {
  return new Promise((resolve) => {
    const start = performance.now();
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeout);
    fetch(`http://127.0.0.1:${port}`, { mode: "no-cors", signal: ctrl.signal, cache: "no-store" })
      .then(() => { clearTimeout(timer); resolve({ port, elapsed: performance.now() - start, reached: true }); })
      .catch(() => { clearTimeout(timer); resolve({ port, elapsed: performance.now() - start, reached: false }); });
  });
}
async function scanLocalhost() {
  // Probe all ports concurrently so the auto-run finishes in ~1 timeout window.
  return Promise.all(
    LOCAL_PORTS.map(async ({ port, service }) => {
      const r = await probeLocal(port);
      // Reached (CORS/opaque) => definitely open. Otherwise long stall => probably open.
      const likelyOpen = r.reached || r.elapsed > 900;
      return { port, service, likelyOpen, ms: Math.round(r.elapsed) };
    })
  );
}

function webrtcIps() {
  return new Promise((resolve) => {
    const ips = {};
    let pc;
    try {
      pc = new RTCPeerConnection({ iceServers: [{ urls: "stun:stun.l.google.com:19302" }] });
    } catch { return resolve(ips); }
    pc.createDataChannel("x");
    const re = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{0,4}(:[a-f0-9]{0,4}){2,7})/i;
    pc.onicecandidate = (e) => {
      if (!e.candidate) { try { pc.close(); } catch {} return resolve(ips); }
      const m = (e.candidate.candidate || "").match(re);
      if (m) {
        const ip = m[1];
        const isLocal = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|127\.|::1|fe80|f[cd])/i.test(ip);
        const isMdns = /\.local$/i.test(ip);
        if (!isMdns) ips[ip] = isLocal ? "local" : "public";
      }
    };
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch(() => resolve(ips));
    setTimeout(() => { try { pc.close(); } catch {} resolve(ips); }, 3000);
  });
}

// Independently determine the browser's public IP via an external echo service.
// This is a cross-check against what our server sees (network.clientIp): if a
// proxy/VPN sits in between, the two can differ. Falls back to the server value.
async function fetchPublicIp() {
  const node = document.getElementById("hero-pubip");
  if (!node) return;
  const sources = ["https://api.ipify.org?format=json", "https://api64.ipify.org?format=json"];
  for (const url of sources) {
    try {
      const r = await fetch(url, { signal: AbortSignal.timeout(4000), cache: "no-store" });
      if (!r.ok) continue;
      const j = await r.json();
      if (j && j.ip) {
        node.textContent = j.ip;
        // Report it back so the public IP shows up in the server access log too
        // (the server can't see it when we reach it via NAT/an internal hop).
        fetch(`/api/clientmeta?pubip=${encodeURIComponent(j.ip)}`, { cache: "no-store" }).catch(() => {});
        return;
      }
    } catch {}
  }
  // Leave the server-provided baseline; only mark blocked if nothing filled it.
  if (node.textContent === "…") node.textContent = "lookup blocked";
}

/* =========================================================================
 *  boot
 * ========================================================================= */
loadServerInfo();
loadClientInfo();
fetchPublicIp();
