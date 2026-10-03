import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from webdetect import analyze
LOG = os.path.join(os.path.dirname(__file__), "..", "samples", "access.log")


def found():
    with open(LOG) as f:
        return {(x["ip"], x["type"]) for x in analyze(f)}


def test_expected_detections():
    s = found()
    for e in [("198.51.100.20", "SQLI"), ("198.51.100.21", "XSS"), ("198.51.100.22", "PATH_TRAVERSAL"),
              ("198.51.100.23", "CMD_INJECTION"), ("203.0.113.9", "SCANNER_UA"), ("203.0.113.9", "SCAN_404"),
              ("203.0.113.10", "SCANNER_UA")]:
        assert e in s, e


def test_double_encoded_traversal_caught():
    line = '198.51.100.22 - - [x] "GET /d?f=%252e%252e%252fetc/passwd HTTP/1.1" 404 1 "-" "curl"'
    assert any(x["type"] == "PATH_TRAVERSAL" for x in analyze([line]))


def test_benign_user_clean():
    assert all(ip != "192.0.2.30" for ip, _ in found())
