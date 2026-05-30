#!/usr/bin/env python3
"""
logstats.py — a tiny access-statistics dashboard for privacyCheck logs.

It parses the Apache-combined access lines plus the EXEC and CLIENT lines that
the server writes to stdout, and prints a terminal dashboard: page views, unique
visitors, top IPs/paths, which server-side probes (execs) get used and against
what, browser-reported public IPs, and a heuristic "suspicious IPs" list.

Requests from 127.0.0.1 (health checks, local curls) are ignored by default.

Usage:
    docker logs hidden-homepage | python3 logstats.py
    docker compose logs --no-color | python3 logstats.py
    python3 logstats.py --container hidden-homepage
    python3 logstats.py --file access.log --top 15 --no-color

Stdlib only — no pip install needed.
"""

import argparse
import re
import sys
import subprocess
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

ANSI = re.compile(r"\x1b\[[0-9;]*m")
# docker-compose prefixes each line with "<service>    | "
COMPOSE_PREFIX = re.compile(r"^[A-Za-z0-9_.-]+\s+\|\s?")

PREFIX = re.compile(r"^(?P<ip>\S+) - - \[(?P<date>[^\]]+)\] (?P<rest>.*)$")
ACCESS = re.compile(
    r'^"(?P<method>\S+)\s+(?P<path>.*?)\s+HTTP/[\d.]+"\s+'
    r"(?P<status>\d{3})\s+(?P<bytes>\S+)\s+"
    r'"(?P<ref>[^"]*)"\s+"(?P<ua>[^"]*)"(?:\s+via=(?P<via>\S+))?'
)
EXEC = re.compile(r"^EXEC \(as (?P<user>[^)]+)\)\s+(?P<cmd>.*)$")
CLIENT = re.compile(
    r'^CLIENT pubip=(?P<pub>\S+)\s+via=(?P<via>\S+)(?:\s+"(?P<ua>[^"]*)")?'
)


def clean(line):
    line = ANSI.sub("", line.rstrip("\n"))
    line = COMPOSE_PREFIX.sub("", line)
    return line


def parse_date(s):
    try:
        return datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def classify_exec(cmd):
    """Return (kind, target) for an EXEC command string (via= already stripped)."""
    parts = cmd.split()
    target = parts[-1] if parts else "-"
    if cmd.startswith("traceroute"):
        return "traceroute", target
    if "nmap" in cmd:
        return "nmap -O", target
    if cmd.startswith("tcp-connect-portscan"):
        return "portscan", target
    return parts[0] if parts else "?", target


class Stats:
    def __init__(self, ignore_ips):
        self.ignore = set(ignore_ips)
        self.total = 0
        self.pageviews = 0
        self.bytes = 0
        self.first = None
        self.last = None

        self.ip_reqs = Counter()
        self.ip_errors = Counter()
        self.ip_404 = Counter()
        self.ip_execs = Counter()
        self.ip_paths = defaultdict(set)
        self.ip_uas = defaultdict(Counter)
        self.day_reqs = Counter()  # requests per calendar day, for the timeline

        self.paths = Counter()
        self.status = Counter()
        self.uas = Counter()
        self.methods = Counter()

        self.exec_kinds = Counter()
        self.exec_targets = Counter()
        self.exec_by_ip = Counter()

        self.pubips = Counter()          # browser-reported public IPs
        self.pub_map = defaultdict(set)  # forwarded/internal ip -> {public ip}

    def track_time(self, dt):
        if dt is None:
            return
        if self.first is None or dt < self.first:
            self.first = dt
        if self.last is None or dt > self.last:
            self.last = dt

    def feed(self, line):
        line = clean(line)
        m = PREFIX.match(line)
        if not m:
            return
        ip = m.group("ip")
        if ip in self.ignore:
            return
        dt = parse_date(m.group("date"))
        rest = m.group("rest")

        if rest.startswith('"'):
            a = ACCESS.match(rest)
            if not a:
                return
            self.track_time(dt)
            if dt:
                self.day_reqs[dt.date()] += 1
            self.total += 1
            self.ip_reqs[ip] += 1
            status = int(a.group("status"))
            self.status[status] += 1
            self.methods[a.group("method")] += 1
            path = a.group("path").split("?", 1)[0]
            self.paths[path] += 1
            self.ip_paths[ip].add(path)
            ua = a.group("ua") or "-"
            if ua not in ("-", "node"):
                self.uas[ua] += 1
                self.ip_uas[ip][ua] += 1
            b = a.group("bytes")
            if b.isdigit():
                self.bytes += int(b)
            if path == "/":
                self.pageviews += 1
            if status >= 400:
                self.ip_errors[ip] += 1
            if status == 404:
                self.ip_404[ip] += 1

        elif rest.startswith("EXEC"):
            e = EXEC.match(rest)
            if not e:
                return
            self.track_time(dt)
            cmd = e.group("cmd")
            via = None
            if " via=" in cmd:
                cmd, via = cmd.rsplit(" via=", 1)
            kind, target = classify_exec(cmd.strip())
            self.exec_kinds[kind] += 1
            self.exec_targets[f"{kind} -> {target}"] += 1
            self.exec_by_ip[ip] += 1
            self.ip_execs[ip] += 1

        elif rest.startswith("CLIENT"):
            c = CLIENT.match(rest)
            if not c:
                return
            self.track_time(dt)
            pub = c.group("pub")
            if pub and pub != "-":
                self.pubips[pub] += 1
                self.pub_map[ip].add(pub)

    # --- suspicion heuristics -------------------------------------------
    def suspicious(self):
        flagged = []
        for ip, reqs in self.ip_reqs.items():
            reasons = []
            errs = self.ip_errors[ip]
            n404 = self.ip_404[ip]
            execs = self.ip_execs[ip]
            npaths = len(self.ip_paths[ip])
            nuas = len(self.ip_uas[ip])
            if reqs >= 200:
                reasons.append(f"high volume ({reqs} reqs)")
            if n404 >= 10:
                reasons.append(f"{n404}x 404 (scanning?)")
            if errs and reqs and errs / reqs > 0.5 and reqs >= 10:
                reasons.append(f"{errs}/{reqs} error responses")
            if execs >= 10:
                reasons.append(f"{execs} probe runs (traceroute/nmap/portscan)")
            if npaths >= 25:
                reasons.append(f"{npaths} distinct paths")
            if nuas >= 4:
                reasons.append(f"{nuas} different user-agents")
            if reasons:
                flagged.append((ip, reqs, reasons))
        flagged.sort(key=lambda x: x[1], reverse=True)
        return flagged


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

class C:
    def __init__(self, on):
        self.on = on

    def _w(self, code, s):
        return f"\x1b[{code}m{s}\x1b[0m" if self.on else s

    def bold(self, s):  return self._w("1", s)
    def dim(self, s):   return self._w("2", s)
    def green(self, s): return self._w("32", s)
    def yellow(self, s):return self._w("33", s)
    def red(self, s):   return self._w("31", s)
    def cyan(self, s):  return self._w("36", s)


def bar(n, mx, width=28):
    if mx <= 0:
        return ""
    filled = round(width * n / mx)
    return "█" * filled + "·" * (width - filled)


def section(c, title):
    print()
    print(c.bold(c.cyan(f"━━ {title} ")) + c.cyan("━" * max(0, 56 - len(title))))


def top_list(c, title, counter, top, color=None):
    section(c, title)
    if not counter:
        print(c.dim("   (none)"))
        return
    mx = max(counter.values())
    for label, n in counter.most_common(top):
        label = str(label)
        label = (label[:46] + "…") if len(label) > 47 else label
        line = f"   {n:>6}  {bar(n, mx)}  {label}"
        print(color(line) if color else line)


def short_ua(ua):
    """Condense a User-Agent string to e.g. 'Chrome 148, macOS'."""
    if not ua or ua in ("-", "node"):
        return ua or "-"
    br = ""
    for key, label in (("Edg/", "Edge"), ("OPR/", "Opera"), ("Firefox/", "Firefox"),
                       ("Chrome/", "Chrome"), ("Safari/", "Safari")):
        if key in ua:
            mver = re.search(re.escape(key) + r"([\d.]+)", ua)
            br = f"{label} {mver.group(1).split('.')[0]}" if mver else label
            break
    if not br:
        br = ua[:28]
    os_ = ""
    mos = re.search(r"\(([^)]*)\)", ua)
    if mos:
        seg = mos.group(1)
        if "Windows" in seg:
            os_ = "Windows"
        elif "Mac OS" in seg or "Macintosh" in seg:
            os_ = "macOS"
        elif "iPhone" in seg or "iPad" in seg:
            os_ = "iOS"
        elif "Android" in seg:
            os_ = "Android"
        elif "Linux" in seg:
            os_ = "Linux"
    return f"{br}{', ' + os_ if os_ else ''}"


def render_timeline(c, day_counter, days=60):
    section(c, f"Usage — last {days} days (requests/day)")
    if not day_counter:
        print(c.dim("   (no dated activity)"))
        return
    end = max(day_counter)
    series = [end - timedelta(days=days - 1 - i) for i in range(days)]
    counts = [day_counter.get(d, 0) for d in series]
    mx = max(counts) or 1
    blocks = "▁▂▃▄▅▆▇█"

    def cell(v):
        if v == 0:
            return c.dim("·")
        idx = min(len(blocks) - 1, max(0, round((len(blocks) - 1) * v / mx)))
        return blocks[idx]

    print("   " + "".join(cell(v) for v in counts))
    print(c.dim(f"   {series[0]:%b %d} {'─' * (days - 14)} {series[-1]:%b %d}    peak {mx}/day"))

    # detailed bars for the days that actually saw traffic
    active = [(d, day_counter[d]) for d in series if day_counter.get(d, 0) > 0]
    if active:
        dmx = max(n for _, n in active)
        print()
        for d, n in active:
            print(f"   {d:%a %m-%d}  {bar(n, dmx, 30)}  {n}")


def main():
    ap = argparse.ArgumentParser(description="Access-statistics dashboard for privacyCheck logs.")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--container", help="run `docker logs <name>` and analyze its output")
    src.add_argument("--file", help="read from a log file instead of stdin")
    ap.add_argument("--top", type=int, default=10, help="how many rows per top-list (default 10)")
    ap.add_argument("--ignore-ip", action="append", default=["127.0.0.1", "::1"],
                    help="client IPs to skip (repeatable; default 127.0.0.1, ::1)")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    args = ap.parse_args()

    c = C(on=not args.no_color and sys.stdout.isatty())

    if args.container:
        try:
            proc = subprocess.run(["docker", "logs", args.container],
                                  capture_output=True, text=True, check=True)
            lines = (proc.stdout + proc.stderr).splitlines()
        except Exception as e:
            sys.exit(f"failed to read docker logs for {args.container}: {e}")
    elif args.file:
        with open(args.file, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    else:
        if sys.stdin.isatty():
            sys.exit("no input — pipe logs in, or use --container / --file (see --help)")
        lines = sys.stdin.readlines()

    st = Stats(args.ignore_ip)
    for line in lines:
        st.feed(line)

    # ---- header ----
    print()
    print(c.bold("  privacyCheck — access statistics"))
    rng = "no timestamped lines"
    if st.first and st.last:
        span = st.last - st.first
        rng = f"{st.first:%Y-%m-%d %H:%M} → {st.last:%Y-%m-%d %H:%M}  ({span})"
    print(c.dim(f"  {rng}"))
    print(c.dim(f"  ignoring: {', '.join(args.ignore_ip)}"))

    # ---- overview ----
    section(c, "Overview")
    visitors = len(st.ip_reqs)
    errors = sum(v for k, v in st.status.items() if k >= 400)
    mb = st.bytes / (1024 * 1024)
    def kv(k, v): print(f"   {k:<22} {c.bold(str(v))}")
    kv("Page views (GET /)", st.pageviews)
    kv("Total requests", st.total)
    kv("Unique visitors", visitors)
    kv("Server-side execs", sum(st.exec_kinds.values()))
    kv("Error responses 4xx/5xx", errors)
    kv("Data served", f"{mb:.1f} MB")

    # ---- 60-day usage timeline ----
    render_timeline(c, st.day_reqs, days=60)

    # ---- status codes ----
    top_list(c, "HTTP status codes", st.status, 10)

    # ---- top pages ----
    top_list(c, "Top paths", st.paths, args.top)

    # ---- top visitors (with their main user-agent) ----
    section(c, "Top visitors (by requests)")
    if not st.ip_reqs:
        print(c.dim("   (none)"))
    else:
        mx = max(st.ip_reqs.values())
        for ip, n in st.ip_reqs.most_common(args.top):
            ua = short_ua(st.ip_uas[ip].most_common(1)[0][0]) if st.ip_uas.get(ip) else "-"
            print(c.green(f"   {n:>6}  {bar(n, mx)}  {ip}") + c.dim(f"  ({ua})"))

    # ---- exec usage ----
    top_list(c, "Server-side probes used", st.exec_kinds, args.top, color=c.yellow)
    top_list(c, "Probe targets", st.exec_targets, args.top, color=c.yellow)

    # ---- public ips ----
    section(c, "Browser-reported public IPs")
    if not st.pubips:
        print(c.dim("   (none reported)"))
    else:
        mx = max(st.pubips.values())
        for pub, n in st.pubips.most_common(args.top):
            print(f"   {n:>6}  {bar(n, mx)}  {pub}")
        # internal -> public mapping where they differ
        diffs = [(i, sorted(p)) for i, p in st.pub_map.items() if p and any(x != i for x in p)]
        if diffs:
            print(c.dim("   forwarded/internal → public:"))
            for i, pubs in diffs[: args.top]:
                print(c.dim(f"     {i} → {', '.join(pubs)}"))

    # ---- user agents ----
    top_list(c, "Top user-agents", st.uas, args.top)

    # ---- suspicious ----
    section(c, "Suspicious IPs (heuristic)")
    flagged = st.suspicious()
    if not flagged:
        print(c.dim("   nothing stands out"))
    else:
        for ip, reqs, reasons in flagged[: args.top]:
            print(f"   {c.red(ip):<24} " + c.dim("· ".join(reasons)))
    print()


if __name__ == "__main__":
    main()
