#!/usr/bin/env python3
"""Web access-log attack detector (Apache/Nginx combined format).

Detects SQL injection, XSS, path traversal, command injection, scanner user-agents
and aggressive 404 scanning. Requests are URL-decoded (twice) before matching so
simple encoding tricks don't hide payloads. Outputs findings grouped per source IP.
"""
import argparse
import re
import sys
from collections import defaultdict
from urllib.parse import unquote_plus

LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" (?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)
RULES = [
    ("SQLI", "T1190", re.compile(r"(union\s+select|or\s+1\s*=\s*1|'\s*or\s*'|sleep\(\d|information_schema|--\s|;\s*drop\s+table)", re.I)),
    ("XSS", "T1189", re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src)", re.I)),
    ("PATH_TRAVERSAL", "T1083", re.compile(r"(\.\./|\.\.\\|/etc/passwd|boot\.ini|win\.ini)", re.I)),
    ("CMD_INJECTION", "T1059", re.compile(r"(;|\|\||&&|\|)\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b", re.I)),
]
SCANNER_UA = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wfuzz|acunetix|nessus|zgrab)", re.I)
SCAN_404_THRESHOLD = 20


def decode(s):
    return unquote_plus(unquote_plus(s))


def analyze(lines, scan_404=SCAN_404_THRESHOLD):
    hits = defaultdict(lambda: defaultdict(list))   # ip -> type -> [paths]
    mitre = {}
    not_found = defaultdict(int)
    for line in lines:
        m = LOG_RE.match(line)
        if not m:
            continue
        ip, path, status, ua = m["ip"], decode(m["path"]), m["status"], m["ua"]
        for name, tech, rx in RULES:
            if rx.search(path):
                hits[ip][name].append(path)
                mitre[name] = tech
        if SCANNER_UA.search(ua):
            hits[ip]["SCANNER_UA"].append(ua)
            mitre["SCANNER_UA"] = "T1595"
        if status == "404":
            not_found[ip] += 1
    for ip, n in not_found.items():
        if n >= scan_404:
            hits[ip]["SCAN_404"].append(f"{n} not-found responses")
            mitre["SCAN_404"] = "T1595.003"
    out = []
    for ip, types in hits.items():
        for name, items in types.items():
            sev = "HIGH" if name in ("SQLI", "CMD_INJECTION") else "MEDIUM"
            out.append({"ip": ip, "type": name, "mitre": mitre[name], "severity": sev,
                        "count": len(items), "example": items[0][:70]})
    return sorted(out, key=lambda f: (f["severity"] != "HIGH", f["ip"], f["type"]))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("logfile")
    a = ap.parse_args()
    with open(a.logfile, errors="replace") as f:
        res = analyze(f)
    if not res:
        print("No attacks detected.")
        return 0
    print(f"{'SEV':<7}{'IP':<15}{'TYPE':<16}{'MITRE':<11}{'N':<4}EXAMPLE")
    for r in res:
        print(f"{r['severity']:<7}{r['ip']:<15}{r['type']:<16}{r['mitre']:<11}{r['count']:<4}{r['example']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
