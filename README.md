# SOC Triage Console

A small L1 SOC lab: three Python detectors and a browser console that runs the same detections and shows a MITRE ATT&CK-mapped alert queue with next steps for the analyst.

All sample data is synthetic (RFC 5737 documentation IPs, `.example` domains). Python tools use only the standard library; `pytest` is needed for tests.

## About

I built this project to practise the day-to-day work of a Level 1 SOC analyst: reading logs, spotting attacks, deciding severity and knowing when to escalate.

It has two parts. Three small Python detectors find attacks in network, web-server and Windows logs. A browser console then collects every alert in one queue, maps it to MITRE ATT&CK, and shows the evidence and the L1 next steps for that alert.

What I wanted to show:
- I can turn raw logs into clear, explainable detections (no black box, every alert says why it fired).
- I think about false positives, so each rule has thresholds and a benign case in its tests.
- I document the way an analyst hands over a case: evidence, technique, action.

Everything runs locally on synthetic data, so it is safe to try.

| Tool | Input | Detects | MITRE |
|---|---|---|---|
| [network-beacon-dns](tools/network-beacon-dns) | conn/dns CSV | C2 beaconing, DNS tunneling, TXT abuse | T1071, T1071.004 |
| [web-log-attacks](tools/web-log-attacks) | Apache/Nginx logs | SQLi, XSS, path traversal, command injection, scanners, 404 scans | T1190, T1189, T1083, T1059, T1595 |
| [windows-event-hunter](tools/windows-event-hunter) | Security events (JSONL) | Brute force success, new admin account, Office spawning shell, encoded PowerShell, log clearing | T1110, T1136, T1204, T1059, T1070 |
| [console](console/index.html) | any of the above | Alert queue, filters, ATT&CK matrix, L1 playbook per alert | all |

## Run
```bash
python3 tools/network-beacon-dns/netanalyzer.py --conn tools/network-beacon-dns/samples/conn.csv --dns tools/network-beacon-dns/samples/dns.csv
python3 tools/web-log-attacks/webdetect.py tools/web-log-attacks/samples/access.log
python3 tools/windows-event-hunter/winhunt.py tools/windows-event-hunter/samples/security.jsonl
for d in tools/*; do python3 -m pytest -q $d/tests; done
```
Open `console/index.html` in a browser. Analysis runs locally; logs are never uploaded. The detectors exit with code 1 when they find something.

## Design notes
- Beaconing uses the coefficient of variation of connection intervals; DNS tunneling combines label length, entropy and unique-subdomain count.
- Web requests are URL-decoded twice before matching so double-encoded payloads are caught.
- Windows detections correlate events (create user then add to Administrators; failures then success) instead of alerting on single IDs.
- The console shows log text as plain text, because log content can come from an attacker.

## Limits
Rule-based, threshold-driven, tested on simulated logs only. The console is a JavaScript port of the Python detectors; they should be kept in sync.
