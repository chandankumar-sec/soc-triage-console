import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netanalyzer import beacons, dns_tunnels, load, entropy
S = os.path.join(os.path.dirname(__file__), "..", "samples")


def test_beacon_found_and_browsing_ignored():
    f = beacons(load(os.path.join(S, "conn.csv")))
    assert [x["src"] for x in f] == ["10.0.0.15"]
    assert f[0]["dst"] == "203.0.113.77:443"


def test_dns_tunnel_found_and_normal_ignored():
    f = dns_tunnels(load(os.path.join(S, "dns.csv")))
    assert [x["dst"] for x in f] == ["badtunnel.example"]


def test_too_few_connections_not_beacon():
    rows = [{"ts": str(i * 60), "src": "a", "dst": "b", "dport": "443"} for i in range(5)]
    assert beacons(rows) == []


def test_entropy_ordering():
    assert entropy("aaaa") < entropy("a1b2c3d4e5")
