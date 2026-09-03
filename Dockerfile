# ---- privacyCheck ----
FROM node:22-slim

# traceroute + nmap power the best-effort server-side probes.
#  - traceroute honors file capabilities, so setcap CAP_NET_RAW lets it run as
#    the non-root app user directly.
#  - nmap ignores file caps and insists on euid==0, so we instead allow the app
#    user to run *only* nmap via sudo (tight NOPASSWD rule below). CAP_NET_RAW is
#    in Docker's default capability set, so root-via-sudo nmap works with a plain
#    `docker run`. Everything degrades gracefully if the cap is dropped.
RUN apt-get update \
    && apt-get install -y --no-install-recommends traceroute nmap ca-certificates libcap2-bin sudo \
    && rm -rf /var/lib/apt/lists/* \
    && setcap cap_net_raw+eip "$(readlink -f "$(command -v traceroute)")" \
    && echo "node ALL=(root) NOPASSWD: /usr/bin/nmap" > /etc/sudoers.d/nmap \
    && chmod 0440 /etc/sudoers.d/nmap \
    && echo "configured: traceroute cap + sudo nmap rule"

WORKDIR /app

# npm ci against the committed lockfile -> reproducible builds
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

COPY server.js ./
COPY public ./public

ENV NODE_ENV=production
ENV PORT=3000
EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||3000)+'/api/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

# Pre-create the log + report directories as the app user so bind-mount writes
# work without root on the host (uid 1000 = node).
RUN mkdir -p /var/log/hidden-homepage/reports \
    && chown -R node:node /var/log/hidden-homepage

# Run the app as non-root. traceroute works via its file capability; nmap -O
# works via the narrow sudo rule above — the app itself never runs as root.
USER node

CMD ["node", "server.js"]
