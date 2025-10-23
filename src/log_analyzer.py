#!/usr/bin/env python3
import argparse, os, re, json, csv, smtplib, time, requests
from email.message import EmailMessage
from datetime import datetime
from dotenv import load_dotenv
load_dotenv()

# ---------------- Regex ----------------
FAILED_RE = re.compile(
    r"""(?P<ts>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+\S+\s+sshd\[\d+\]:\s+Failed\s+password\s+for\s+(?:invalid\s+user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)""",
    re.VERBOSE
)
ERROR_RE = re.compile(
    r"""(?P<ts>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d)\s+\S+\s+\S+\[\d+\]:\s+ERROR:\s+(?P<msg>.+)""",
    re.VERBOSE
)
SUDO_FAIL_RE = re.compile(
    r"""(?P<ts>\w{3}\s+\d{1,2}\s+\d\d:\d\d:\d\d).*(?:sudo).*?(?:authentication failure|incorrect password)""",
    re.IGNORECASE | re.VERBOSE
)
WEB_CLF_RE = re.compile(
    r"""(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+\[(?P<dt>[^\]]+)\]\s+"[^"]*"\s+(?P<status>\d{3})\s+\d+""",
    re.VERBOSE
)

# ---------------- IP Enrichment helpers ----------------
def _load_cache(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return {}

def _save_cache(path, data):
    try:
        with open(path, "w") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

def enrich_ips(ips, cache_file=".ip_enrich_cache.json", timeout=5):
    """Return {ip: {'country','region','city','asn','org'}} using ipinfo (if IPINFO_TOKEN) else ipapi.co."""
    ips = sorted(set(ips))
    cache = _load_cache(cache_file)
    out = {}
    token = os.getenv("IPINFO_TOKEN")  # optional
    headers = {"User-Agent": "log-alert-automation/1.0"}

    for ip in ips:
        if ip in cache:
            out[ip] = cache[ip]; continue

        meta = {"country": None, "region": None, "city": None, "asn": None, "org": None}
        try:
            if token:
                r = requests.get(f"https://ipinfo.io/{ip}", params={"token": token}, timeout=timeout, headers=headers)
                if r.ok:
                    j = r.json()
                    meta["country"] = j.get("country")
                    meta["region"]  = j.get("region")
                    meta["city"]    = j.get("city")
                    org = j.get("org") or ""
                    if org.startswith("AS"):
                        parts = org.split(" ", 1)
                        meta["asn"] = parts[0]
                        meta["org"] = parts[1] if len(parts) > 1 else None
                    else:
                        meta["org"] = org or None
                else:
                    raise RuntimeError(f"ipinfo status {r.status_code}")
            else:
                r = requests.get(f"https://ipapi.co/{ip}/json/", timeout=timeout, headers=headers)
                if r.ok:
                    j = r.json()
                    meta["country"] = j.get("country")
                    meta["region"]  = j.get("region")
                    meta["city"]    = j.get("city")
                    meta["asn"]     = j.get("asn")
                    meta["org"]     = j.get("org") or j.get("org_name")
                else:
                    raise RuntimeError(f"ipapi status {r.status_code}")
        except Exception:
            pass  # leave meta with None fields

        cache[ip] = meta
        out[ip] = meta
        time.sleep(0.2)  # be gentle

    _save_cache(cache_file, cache)
    return out

def format_origin(meta):
    if not meta:
        return "unknown"
    loc = "/".join([x for x in [meta.get("country"), meta.get("city")] if x])
    net = " ".join([x for x in [meta.get("asn"), meta.get("org")] if x])
    return f"{loc} ({net})" if loc and net else (loc or net or "unknown")

# ---------------- Time parsing ----------------
MONTHS = {m:i for i,m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

def parse_syslog_ts(ts_str: str, year: int=None):
    now = datetime.now()
    year = year or now.year
    try:
        mon = MONTHS[ts_str.split()[0]]
        day = int(ts_str.split()[1])
        hh, mm, ss = map(int, ts_str.split()[2].split(":"))
        return datetime(year, mon, day, hh, mm, ss)
    except Exception:
        return None

def parse_clf_ts(ts_str: str):
    try:
        ts_main = ts_str.split()[0]
        return datetime.strptime(ts_main, "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None

# ---------------- Detectors ----------------
def detect_failed_logins(lines, window=300, threshold=5):
    events = []
    for ln in lines:
        m = FAILED_RE.search(ln)
        if m:
            dt = parse_syslog_ts(m.group("ts"))
            if dt:
                events.append({"ts": dt.isoformat(), "user": m.group("user"), "ip": m.group("ip")})
    alerts, events_sorted = [], sorted(events, key=lambda e: e["ts"])
    for i, e in enumerate(events_sorted):
        t0 = datetime.fromisoformat(e["ts"])
        j, count, offenders = i, 0, []
        while j < len(events_sorted):
            tj = datetime.fromisoformat(events_sorted[j]["ts"])
            if (tj - t0).total_seconds() <= window:
                count += 1; offenders.append(events_sorted[j]["ip"]); j += 1
            else:
                break
        if count >= threshold:
            alerts.append({
                "rule": "failed_logins",
                "start": t0.isoformat(),
                "count": count,
                "unique_ips": sorted(set(offenders)),
                "window_sec": window
            })
    # de-dupe by (rule,start)
    uniq, seen = [], set()
    for a in alerts:
        key = (a["rule"], a["start"])
        if key not in seen:
            uniq.append(a); seen.add(key)
    return uniq, events

def detect_errors(lines, window=300, threshold=3):
    events = []
    for ln in lines:
        m = ERROR_RE.search(ln)
        if m:
            dt = parse_syslog_ts(m.group("ts"))
            if dt:
                events.append({"ts": dt.isoformat(), "msg": m.group("msg").strip()})
    alerts, events_sorted = [], sorted(events, key=lambda e: e["ts"])
    for i, e in enumerate(events_sorted):
        t0 = datetime.fromisoformat(e["ts"])
        j, count = i, 0
        while j < len(events_sorted):
            tj = datetime.fromisoformat(events_sorted[j]["ts"])
            if (tj - t0).total_seconds() <= window:
                count += 1; j += 1
            else:
                break
        if count >= threshold:
            alerts.append({"rule": "errors", "start": t0.isoformat(), "count": count, "window_sec": window})
    uniq, seen = [], set()
    for a in alerts:
        key = (a["rule"], a["start"])
        if key not in seen:
            uniq.append(a); seen.add(key)
    return uniq, events

def detect_sudo_failures(lines, window=300, threshold=3):
    events = []
    for ln in lines:
        m = SUDO_FAIL_RE.search(ln)
        if m:
            dt = parse_syslog_ts(m.group("ts"))
            if dt:
                events.append({"ts": dt.isoformat(), "type": "sudo_failure"})
    alerts, ev_sorted = [], sorted(events, key=lambda e: e["ts"])
    for i, e in enumerate(ev_sorted):
        t0 = datetime.fromisoformat(e["ts"])
        j, count = i, 0
        while j < len(ev_sorted):
            tj = datetime.fromisoformat(ev_sorted[j]["ts"])
            if (tj - t0).total_seconds() <= window:
                count += 1; j += 1
            else:
                break
        if count >= threshold:
            alerts.append({"rule": "sudo_failures", "start": t0.isoformat(), "count": count})
    return alerts, events

def detect_web_unauthorized(lines, window=300, threshold=5):
    events = []
    for ln in lines:
        m = WEB_CLF_RE.search(ln)
        if m:
            status = int(m.group("status"))
            if status in (401, 403):
                dt = parse_clf_ts(m.group("dt"))
                if dt:
                    events.append({"ts": dt.isoformat(), "ip": m.group("ip"), "status": status})
    alerts, ev_sorted = [], sorted(events, key=lambda e: (e["ip"], e["ts"]))
    for i, e in enumerate(ev_sorted):
        ip = e["ip"]
        t0 = datetime.fromisoformat(e["ts"])
        j, count = i, 0
        while j < len(ev_sorted) and ev_sorted[j]["ip"] == ip:
            tj = datetime.fromisoformat(ev_sorted[j]["ts"])
            if (tj - t0).total_seconds() <= window:
                count += 1; j += 1
            else:
                break
        if count >= threshold:
            alerts.append({"rule": "web_unauthorized", "start": t0.isoformat(), "count": count, "ip": ip})
    return alerts, events

# ---------------- Reporting ----------------
def write_reports(out_dir, formats, alerts, events):
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}")

    if "json" in formats:
        with open(base + ".json", "w") as f:
            json.dump({"alerts": alerts, "events": events}, f, indent=2)

    if "csv" in formats:
        alert_fields = sorted({k for a in alerts for k in a.keys()}) or ["rule", "start", "count", "msg"]
        with open(base + "_alerts.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=alert_fields); w.writeheader()
            for a in alerts: w.writerow(a)

        if events:
            all_keys = sorted({k for e in events for k in e.keys()})
            with open(base + "_events.csv", "w", newline="") as f:
                w = csv.DictWriter(f, fieldnames=all_keys); w.writeheader()
                for e in events: w.writerow(e)

    return base

# ---------------- Email ----------------
def send_email_if_alerts(alerts):
    """Send email alert summary if alerts exist. Requires env vars (SMTP_HOST, etc.)."""
    if not alerts:
        return

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd = os.getenv("SMTP_PASS")
    mail_from = os.getenv("SMTP_FROM", user or "")
    mail_to = os.getenv("SMTP_TO")
    use_tls = os.getenv("SMTP_TLS", "1") == "1"
    use_ssl = os.getenv("SMTP_SSL", "0") == "1"

    if not (host and mail_to and (user or mail_from)):
        print("[!] Email not sent (missing SMTP env vars).")
        return

    # Body (plain text) with origins for failed_logins
    body_lines = ["Alerts generated:\n"]
    for a in alerts:
        body_lines.append(json.dumps(a, indent=2))
        if a.get("rule") == "failed_logins" and a.get("ip_origins"):
            body_lines.append("  Origins:")
            for item in a["ip_origins"]:
                body_lines.append(f"   - {item.get('ip')}: {item.get('origin','unknown')}")
        body_lines.append("")

    msg = EmailMessage()
    msg["Subject"] = "Log Analyzer Alerts"
    msg["From"] = mail_from
    msg["To"] = mail_to
    msg.set_content("\n".join(body_lines))

    try:
        if use_ssl:
            with smtplib.SMTP_SSL(host, port, timeout=15) as s:
                if user and pwd: s.login(user, pwd)
                s.send_message(msg)
        else:
            with smtplib.SMTP(host, port, timeout=15) as s:
                if use_tls: s.starttls()
                if user and pwd: s.login(user, pwd)
                s.send_message(msg)
        print(f"[+] Email alert sent to {mail_to}")
    except smtplib.SMTPAuthenticationError as e:
        print("[!] Authentication failed:", e)
    except Exception as e:
        print("[!] Email send error:", e)

# ---------------- Main ----------------
def main():
    ap = argparse.ArgumentParser(description="Automated Log Analysis and Alerting Tool")
    ap.add_argument("--log", required=True, help="Path to log file")
    ap.add_argument("--out", default="reports", help="Output directory for reports")
    ap.add_argument("--format", nargs="+", default=["json"], choices=["csv", "json"], help="Report formats")
    ap.add_argument("--rules", nargs="+", default=["failed_logins", "errors"], help="Alert rules to apply")
    ap.add_argument("--window", type=int, default=300, help="Window (seconds)")
    ap.add_argument("--threshold", type=int, default=5, help="Event threshold")
    args = ap.parse_args()

    with open(args.log, "r", errors="ignore") as f:
        lines = f.readlines()

    all_alerts, all_events = [], []

    if "failed_logins" in args.rules:
        alerts, events = detect_failed_logins(lines, window=args.window, threshold=args.threshold)
        all_alerts.extend(alerts); all_events.extend(events)

    if "errors" in args.rules:
        alerts, events = detect_errors(lines, window=args.window, threshold=args.threshold)
        all_alerts.extend(alerts); all_events.extend(events)

    if "sudo_failures" in args.rules:
        alerts, events = detect_sudo_failures(lines, window=args.window, threshold=args.threshold)
        all_alerts.extend(alerts); all_events.extend(events)

    if "web_unauthorized" in args.rules:
        alerts, events = detect_web_unauthorized(lines, window=args.window, threshold=args.threshold)
        all_alerts.extend(alerts); all_events.extend(events)

    # Enrich attacker IPs and attach readable origins
    all_ips = sorted({ip for a in all_alerts for ip in a.get("unique_ips", [])})
    if all_ips:
        ip_meta = enrich_ips(all_ips)
        for a in all_alerts:
            if "unique_ips" in a:
                a["ip_origins"] = [{"ip": ip, "origin": format_origin(ip_meta.get(ip))} for ip in a["unique_ips"]]

    # Write reports
    base = write_reports(out_dir=args.out, formats=args.format, alerts=all_alerts, events=all_events)

    # Console summary
    print(f"[+] Wrote reports to base: {base}")
    if all_alerts:
        print("[!] ALERTS:")
        for a in all_alerts:
            rule = a.get("rule", "?"); start = a.get("start", "?"); count = a.get("count", "?")
            print(f"  - {rule} at {start} (count={count})")
            if rule == "failed_logins" and a.get("ip_origins"):
                for item in a["ip_origins"]:
                    print(f"      · {item['ip']}: {item['origin']}")
    else:
        print("[+] No alerts triggered.")

    # Email (always send, even if "none")
    send_email_if_alerts(
        all_alerts or [{
            "rule": "none",
            "start": str(datetime.now()),
            "count": 0,
            "msg": "No alerts detected today, sir."
        }]
    )

if __name__ == "__main__":
    main()
