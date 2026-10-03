import json, os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from winhunt import hunt
S = os.path.join(os.path.dirname(__file__), "..", "samples", "security.jsonl")


def names():
    with open(S) as f:
        return [r[1] for r in hunt([json.loads(l) for l in f])]


def test_all_expected_detections():
    assert sorted(names()) == sorted(["BRUTE_FORCE_SUCCESS", "NEW_ADMIN_ACCOUNT", "OFFICE_SPAWNS_SHELL",
                                      "ENCODED_POWERSHELL", "AUDIT_LOG_CLEARED"])


def test_few_failures_then_success_is_benign():
    ev = [{"EventID": 4625, "TimeCreated": "2026-10-03T08:00:00", "IpAddress": "1.1.1.1"},
          {"EventID": 4624, "TimeCreated": "2026-10-03T08:00:05", "IpAddress": "1.1.1.1", "LogonType": 3}]
    assert hunt(ev) == []


def test_admin_add_without_creation_not_flagged():
    ev = [{"EventID": 4732, "TimeCreated": "2026-10-03T08:00:00", "MemberName": "old", "GroupName": "Administrators"}]
    assert hunt(ev) == []
