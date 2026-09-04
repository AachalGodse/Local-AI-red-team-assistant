"""Tests for target normalization / type detection."""
from ghostops.agent.targets import normalize


def test_url_splits_into_clean_host_and_url():
    t = normalize("https://example.com:8443/admin?id=1")
    assert t.kind == "url"
    assert t.host == "example.com"        # no scheme, port, or path
    assert t.url == "https://example.com:8443/admin?id=1"
    assert t.scheme == "https" and t.port == 8443


def test_http_url_simple():
    t = normalize("http://10.0.0.5/")
    assert t.kind == "url" and t.host == "10.0.0.5"
    assert t.url == "http://10.0.0.5/"


def test_bare_ip():
    t = normalize("10.0.0.5")
    assert t.kind == "ip" and t.host == "10.0.0.5" and t.url is None


def test_cidr_stays_a_network_target():
    t = normalize("10.0.0.0/24")
    assert t.kind == "ip" and t.host == "10.0.0.0/24" and t.url is None


def test_bare_hostname():
    t = normalize("scanme.nmap.org")
    assert t.kind == "host" and t.host == "scanme.nmap.org" and t.url is None


def test_host_with_port_no_scheme():
    t = normalize("10.0.0.5:8080")
    assert t.host == "10.0.0.5" and t.port == 8080 and t.url is None


def test_host_with_path_becomes_web():
    t = normalize("example.com/dashboard")
    assert t.kind == "url" and t.host == "example.com"
    assert t.url == "http://example.com/dashboard"


def test_host_never_carries_scheme_or_path():
    # the invariant nmap depends on: .host is always a bare host/IP
    for raw in ("https://a.com:9000/x/y?z=1", "http://1.2.3.4/p", "a.com/p"):
        t = normalize(raw)
        assert "://" not in t.host
        assert "/" not in t.host
