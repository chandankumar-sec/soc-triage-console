#!/usr/bin/env python3
"""Windows Security event hunter. Input: JSON Lines, one event per line, e.g.
  {"EventID":4625,"TimeCreated":"2026-10-03T09:00:01","TargetUserName":"admin","IpAddress":"203.0.113.5","LogonType":3}

Detections:
  4625xN then 4624 (same IP)          -> brute force success      T1110 / T1078
  4720 then 4732 (Administrators)     -> new account made admin   T1136.001 / T1098
  4688 Office parent -> shell child   -> macro execution          T1204.002 / T1059
  4688 powershell with -enc           -> obfuscated PowerShell    T1059.001
  1102 / 104                          -> audit log cleared        T1070.001
"""
import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timedelta

OFFICE = ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe")
SHELLS = ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe")


def t(e):
    return datetime.fromisoformat(e["TimeCreated"])


def base(path):
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].lower()


def hunt(events, fail_threshold=5, window_min=10):
    events = sorted(events, key=t)
    out = []
    fails = defaultdict(list)
    created = {}
    for e in events:
        eid = e.get("EventID")
        if eid == 4625:
            fails[e.get("IpAddress")].append(t(e))
        elif eid == 4624 and e.get("LogonType") in (3, 10):
            ip = e.get("IpAddress")
            recent = [x for x in fails.get(ip, []) if t(e) - x <= timedelta(minutes=window_min)]
            if len(recent) >= fail_threshold:
                out.append(("HIGH", "BRUTE_FORCE_SUCCESS", "T1110/T1078", t(e),
                            f"{len(recent)} failed logons then success for {e.get('TargetUserName')} from {ip}"))
        elif eid == 4720:
            created[e.get("TargetUserName")] = t(e)
        elif eid == 4732 and "administrators" in str(e.get("GroupName", "")).lower():
            user = e.get("MemberName")
            if user in created and t(e) - created[user] <= timedelta(hours=1):
                out.append(("HIGH", "NEW_ADMIN_ACCOUNT", "T1136.001/T1098", t(e),
                            f"account '{user}' created and added to Administrators within an hour"))
        elif eid == 4688:
            parent, child = base(e.get("ParentProcessName")), base(e.get("NewProcessName"))
            cmd = (e.get("CommandLine") or "").lower()
            if parent in OFFICE and child in SHELLS:
                out.append(("HIGH", "OFFICE_SPAWNS_SHELL", "T1204.002/T1059", t(e), f"{parent} -> {child}"))
            if child in ("powershell.exe", "pwsh.exe") and any(x in cmd for x in (" -enc", " -encodedcommand")):
                out.append(("MEDIUM", "ENCODED_POWERSHELL", "T1059.001", t(e), e.get("CommandLine", "")[:70]))
        elif eid in (1102, 104):
            out.append(("HIGH", "AUDIT_LOG_CLEARED", "T1070.001", t(e), f"by {e.get('SubjectUserName', '?')}"))
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("jsonl")
    a = ap.parse_args()
    with open(a.jsonl) as f:
        events = [json.loads(l) for l in f if l.strip()]
    res = hunt(events)
    if not res:
        print("No suspicious activity found.")
        return 0
    for sev, name, mitre, ts, detail in res:
        print(f"{sev:<7}{name:<22}{mitre:<16}{ts:%H:%M:%S}  {detail}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
