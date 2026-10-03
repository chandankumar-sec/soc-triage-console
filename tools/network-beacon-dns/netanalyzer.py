#!/usr/bin/env python3
"""Network traffic analyzer: finds C2 beaconing and DNS tunneling in CSV logs.

conn.csv columns: ts,src,dst,dport,bytes     (ts = epoch seconds)
dns.csv  columns: ts,src,query,qtype

Beaconing (T1071): >= MIN_CONN connections src->dst:port with regular timing
  (coefficient of variation of intervals < CV_MAX).
DNS tunneling (T1071.004/T1048): per parent domain, many unique long/high-entropy
  subdomains, or TXT/NULL-heavy lookups.
"""
import argparse
import csv
import math
import statistics
import sys
from collections import Counter, defaultdict

MIN_CONN, CV_MAX = 10, 0.2
MIN_UNIQUE_SUBS, ENTROPY_MIN, LABEL_LEN_MIN = 10, 3.3, 20


def entropy(s):
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values()) if s else 0.0


def beacons(rows, min_conn=MIN_CONN, cv_max=CV_MAX):
    groups = defaultdict(list)
    for r in rows:
        groups[(r["src"], r["dst"], r["dport"])].append(float(r["ts"]))
    out = []
    for (src, dst, port), ts in groups.items():
        ts.sort()
        if len(ts) < min_conn:
            continue
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        mean = statistics.mean(gaps)
        if mean < 1:
            continue
        cv = statistics.pstdev(gaps) / mean
        if cv < cv_max:
            out.append({"type": "BEACON", "src": src, "dst": f"{dst}:{port}", "mitre": "T1071",
                        "severity": "HIGH" if cv < 0.05 else "MEDIUM",
                        "detail": f"{len(ts)} conns, every ~{mean:.0f}s, jitter cv={cv:.3f}"})
    return out


def parent_domain(q):
    parts = q.lower().rstrip(".").split(".")
    return ".".join(parts[-2:]), ".".join(parts[:-2])


def dns_tunnels(rows, min_unique=MIN_UNIQUE_SUBS):
    subs = defaultdict(set)
    txt = Counter()
    total = Counter()
    for r in rows:
        parent, sub = parent_domain(r["query"])
        total[parent] += 1
        if r["qtype"].upper() in ("TXT", "NULL"):
            txt[parent] += 1
        if sub:
            subs[parent].add(sub)
    out = []
    for parent, s in subs.items():
        sus = [x for x in s if len(x.replace(".", "")) >= LABEL_LEN_MIN and entropy(x) >= ENTROPY_MIN]
        if len(sus) >= min_unique:
            out.append({"type": "DNS_TUNNEL", "src": "-", "dst": parent, "mitre": "T1071.004",
                        "severity": "HIGH",
                        "detail": f"{len(sus)} long high-entropy subdomains (e.g. {sus[0][:30]}...)"})
        elif txt[parent] >= 10 and txt[parent] / total[parent] > 0.8:
            out.append({"type": "DNS_TXT_ABUSE", "src": "-", "dst": parent, "mitre": "T1071.004",
                        "severity": "MEDIUM", "detail": f"{txt[parent]}/{total[parent]} queries are TXT"})
    return out


def load(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--conn")
    ap.add_argument("--dns")
    a = ap.parse_args()
    findings = []
    if a.conn:
        findings += beacons(load(a.conn))
    if a.dns:
        findings += dns_tunnels(load(a.dns))
    if not findings:
        print("No suspicious network activity found.")
        return 0
    print(f"{'SEV':<7}{'TYPE':<14}{'SRC':<14}{'DST':<26}{'MITRE':<11}DETAIL")
    for f in sorted(findings, key=lambda x: x["severity"] != "HIGH"):
        print(f"{f['severity']:<7}{f['type']:<14}{f['src']:<14}{f['dst']:<26}{f['mitre']:<11}{f['detail']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
