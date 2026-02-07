#!/usr/bin/env python3
"""
Windows Event Log Threat Hunter (SOC-style)

Input: CSV exported from PowerShell:
  TimeCreated, Id, MachineName, Message

Detects:
- Top failed-login source IPs (Event ID 4625)
- Top targeted accounts
- Failed login bursts per IP in a time window (brute-force indicator)
- Password-spray indicator (one IP tries many usernames)
- Optional allowlist of IP ranges to ignore (internal ranges etc.)

Safe/defensive: Reads your local exported logs only.
"""

import argparse
import csv
import ipaddress
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple


# --- Regex patterns (Windows Security log message text) ---
RE_IP = re.compile(r"Source Network Address:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", re.IGNORECASE)
RE_USER = re.compile(r"Account Name:\s*(.+)", re.IGNORECASE)
RE_LOGON_TYPE = re.compile(r"Logon Type:\s*(\d+)", re.IGNORECASE)

# Some events show "-" for missing fields
INVALID_USERS = {"-", "ANONYMOUS LOGON", "SYSTEM", ""}


@dataclass
class Event:
    t: datetime
    event_id: int
    ip: str
    user: str
    logon_type: str


def parse_time(s: str) -> Optional[datetime]:
    """
    PowerShell Export-Csv often outputs TimeCreated like:
      02/07/2026 10:30:15 PM
    or ISO-ish formats depending on locale.
    We'll try a few common formats.
    """
    s = (s or "").strip()
    if not s:
        return None

    fmts = [        
	"%d-%m-%Y %I.%M.%S %p",
        "%m-%d-%Y %I.%M.%S %p",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %I:%M:%S %p",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M:%S",
    ]
    for f in fmts:
        try:
            return datetime.strptime(s, f)
        except ValueError:
            pass

    # last resort: try trimming milliseconds/timezone
    try:
        return datetime.fromisoformat(s.split(".")[0].replace("Z", ""))
    except Exception:
        return None


def extract_fields(message: str) -> Tuple[str, str, str]:
    """
    Extract IP, username, logon type from the message block.
    Message has many lines. We'll:
    - pick "Source Network Address" IP if present, else "0.0.0.0"
    - pick the FIRST "Account Name" after "Account For Which Logon Failed" (best-effort)
    """
    msg = message or ""
    ip = "0.0.0.0"
    m = RE_IP.search(msg)
    if m:
        ip = m.group(1).strip()

    # Try to find a likely username: Windows message includes multiple "Account Name:"
    # We'll pick the one that appears after "Account For Which Logon Failed" if possible.
    user = "-"
    logon_type = "-"
    lines = msg.splitlines()

    # locate sections
    idx_failed = None
    for i, line in enumerate(lines):
        if "Account For Which Logon Failed" in line:
            idx_failed = i
            break

    # scan for user after that section
    start = idx_failed if idx_failed is not None else 0
    for i in range(start, min(start + 80, len(lines))):
        mu = RE_USER.search(lines[i])
        if mu:
            cand = mu.group(1).strip()
            # skip headers like "Account Name:" with blank
            if cand:
                user = cand
                break

    # logon type
    ml = RE_LOGON_TYPE.search(msg)
    if ml:
        logon_type = ml.group(1).strip()

    return ip, user, logon_type


def ip_in_allowlist(ip: str, allowlist: List[ipaddress._BaseNetwork]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in allowlist)
    except Exception:
        return False


def load_events(csv_path: str, allowlist: List[ipaddress._BaseNetwork]) -> List[Event]:
    events: List[Event] = []

    with open(csv_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            t = parse_time(row.get("TimeCreated", ""))
            if not t:
                continue

            try:
                event_id = int(str(row.get("Id", "")).strip())
            except Exception:
                continue

            msg = row.get("Message", "") or ""
            ip, user, logon_type = extract_fields(msg)

            # normalize
            user = user.strip()
            if user.upper() in INVALID_USERS:
                user = "-"

            # filter allowlisted IPs (optional)
            if ip != "0.0.0.0" and allowlist and ip_in_allowlist(ip, allowlist):
                continue

            events.append(Event(t=t, event_id=event_id, ip=ip, user=user, logon_type=logon_type))

    # sort by time
    events.sort(key=lambda e: e.t)
    return events


def bursts_by_ip(events: List[Event], window_min: int, burst_threshold: int) -> List[Tuple[str, int, datetime, datetime]]:
    """
    For failed logons (4625), compute max count within any sliding window per IP.
    Returns list of (ip, max_count, window_start, window_end) for those exceeding threshold.
    """
    window = timedelta(minutes=window_min)
    by_ip: Dict[str, List[datetime]] = defaultdict(list)

    for e in events:
        if e.event_id == 4625 and e.ip and e.ip != "0.0.0.0":
            by_ip[e.ip].append(e.t)

    alerts = []
    for ip, times in by_ip.items():
        j = 0
        best = (0, None, None)
        for i in range(len(times)):
            while times[i] - times[j] > window:
                j += 1
            cnt = i - j + 1
            if cnt > best[0]:
                best = (cnt, times[j], times[i])
        if best[0] >= burst_threshold:
            alerts.append((ip, best[0], best[1], best[2]))
    alerts.sort(key=lambda x: x[1], reverse=True)
    return alerts


def spray_indicator(events: List[Event], user_threshold: int = 6) -> List[Tuple[str, int]]:
    """
    Password spray: one IP attempting many distinct usernames (failed logons).
    Returns list of (ip, distinct_user_count) >= threshold.
    """
    users_by_ip: Dict[str, set] = defaultdict(set)
    for e in events:
        if e.event_id == 4625 and e.ip and e.ip != "0.0.0.0" and e.user and e.user != "-":
            users_by_ip[e.ip].add(e.user)

    suspects = [(ip, len(users)) for ip, users in users_by_ip.items() if len(users) >= user_threshold]
    suspects.sort(key=lambda x: x[1], reverse=True)
    return suspects


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True, help="Path to exported CSV (PowerShell Export-Csv)")
    ap.add_argument("--window-min", type=int, default=5, help="Sliding window minutes for burst detection (default 5)")
    ap.add_argument("--burst-threshold", type=int, default=8, help="Failed logons within window to alert (default 8)")
    ap.add_argument("--spray-users", type=int, default=6, help="Distinct usernames from one IP to flag spray (default 6)")
    ap.add_argument("--allow", action="append", default=[], help="Allowlist CIDR to ignore, can repeat. Example: --allow 10.0.0.0/8")
    ap.add_argument("--out", help="Optional path to save report as text")
    args = ap.parse_args()

    allowlist = []
    for cidr in args.allow:
        try:
            allowlist.append(ipaddress.ip_network(cidr, strict=False))
        except Exception:
            pass

    events = load_events(args.csv, allowlist)

    # Basic stats
    failed = [e for e in events if e.event_id == 4625]
    success = [e for e in events if e.event_id == 4624]

    time_range = (events[0].t, events[-1].t) if events else (None, None)

    top_ip = Counter(e.ip for e in failed if e.ip and e.ip != "0.0.0.0").most_common(10)
    top_users = Counter(e.user for e in failed if e.user and e.user != "-").most_common(10)
    top_success_ip = Counter(e.ip for e in success if e.ip and e.ip != "0.0.0.0").most_common(10)
    logon_types = Counter(e.logon_type for e in success if e.logon_type and e.logon_type !="-").most_common(10)

    burst_alerts = bursts_by_ip(events, args.window_min, args.burst_threshold)
    spray_alerts = spray_indicator(events, args.spray_users)

    lines: List[str] = []
    lines.append("Windows Event Log Threat Hunter (SOC-style)")
    lines.append("=" * 48)
    if time_range[0]:
        lines.append(f"Time window: {time_range[0]}  ->  {time_range[1]}")
    lines.append(f"Total events parsed: {len(events)}")
    lines.append(f"Failed logons (4625): {len(failed)}")
    lines.append(f"Successful logons (4624): {len(success)}")
    lines.append("")

    lines.append("Top Failed-Logon Source IPs:")
    if top_ip:
        for ip, c in top_ip:
            lines.append(f"  {ip:15}  {c}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append("Top Targeted Usernames (Failed Logons):")
    if top_users:
        for u, c in top_users:
            lines.append(f"  {u:30}  {c}")
    else:
        lines.append("  (none or usernames missing)")
    lines.append("")

    lines.append(f"Burst Alerts (>= {args.burst_threshold} failed logons within {args.window_min} minutes):")
    if burst_alerts:
        for ip, cnt, start, end in burst_alerts[:10]:
            lines.append(f"  {ip:15}  {cnt}  window: {start} -> {end}")
    else:
        lines.append("  (none)")
    lines.append("")

    lines.append(f"Password Spray Indicator (>= {args.spray_users} distinct usernames from one IP):")
    if spray_alerts:
        for ip, n in spray_alerts[:10]:
            lines.append(f"  {ip:15}  distinct users: {n}")
    else:
        lines.append("  (none)")
    lines.append("")
    lines.append("Successful Logon Summary (4624):")
    if logon_types:
        lines.append("Logon Types (count):")
        for lt, c in logon_types:
            lines.append(f"  Type {lt:>2}  {c}")
    else:
        lines.append("Logon Types: (none)")

    lines.append("")
    lines.append("Top Source IPs for Successful Logons:")
    if top_success_ip:
        for ip, c in top_success_ip:
            lines.append(f"  {ip:15}  {c}")
    else:
        lines.append("  (none or not recorded)")
    lines.append("")

    report = "\n".join(lines)
    print(report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(report)
        print(f"\nSaved report: {args.out}")


if __name__ == "__main__":
    main()