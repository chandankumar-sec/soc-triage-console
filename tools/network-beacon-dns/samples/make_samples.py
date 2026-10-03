"""Generates synthetic sample logs (fixed seed). Documentation IPs / .example domains only."""
import csv, random, base64
random.seed(7)
t0 = 1790000000
conn = []
# beacon: every 60s +-2s
for i in range(40):
    conn.append((t0 + i * 60 + random.uniform(-2, 2), "10.0.0.15", "203.0.113.77", 443, 312))
# normal browsing: irregular
t = t0
for _ in range(60):
    t += random.expovariate(1 / 45)
    conn.append((t, "10.0.0.22", random.choice(["192.0.2.10", "192.0.2.11", "198.51.100.5"]), 443, random.randint(500, 90000)))
conn.sort()
with open("conn.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["ts", "src", "dst", "dport", "bytes"]); w.writerows([(f"{a:.2f}", *r) for a, *r in conn])
dns = []
for i in range(25):
    sub = base64.b32encode(random.randbytes(18)).decode().lower().rstrip("=")
    dns.append((t0 + i * 3, "10.0.0.15", f"{sub}.t.badtunnel.example", "A"))
for i, h in enumerate(["www", "mail", "intranet", "www", "docs", "www"] * 4):
    dns.append((t0 + i * 20, "10.0.0.22", f"{h}.corp.example", "A"))
dns.sort()
with open("dns.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["ts", "src", "query", "qtype"]); w.writerows(dns)
