import pytest
from osintcc.policy.targets import TargetError, canonicalize, detect_target, domain_of


@pytest.mark.parametrize("raw,expected", [
    ("Example.COM", "example.com"), ("example.com.", "example.com"), ("bücher.de", "xn--bcher-kva.de"),
    ("EXAMPLE.co.uk", "example.co.uk"),
])
def test_domains(raw, expected):
    assert detect_target(raw).canonical == expected
    assert canonicalize("domain", expected) == expected  # idempotent


@pytest.mark.parametrize("bad", [
    "", " ", "a", "-bad.com", "bad-.com", "a..com", "exa mple.com", "x" * 64 + ".com", "example.123", "a.com\nb.com",
    "example.com;rm -rf /", "$(id).com", "`id`.com", "ex\x00ample.com", "a" * 3000,
])
def test_invalid_domains_rejected(bad):
    with pytest.raises(TargetError):
        detect_target(bad, "domain")


def test_detects_ip_url_email():
    assert detect_target("2001:DB8::1").type == "ip"
    assert detect_target("192.168.0.1").canonical == "192.168.0.1"
    u = detect_target("https://Example.com:443/a?b=1")
    assert u.type == "url" and u.canonical == "https://example.com/a?b=1"
    e = detect_target("Jane.Doe+tag@Example.COM")
    assert e.type == "email" and e.canonical == "Jane.Doe+tag@example.com"  # local part case preserved
    assert "username" in e.ambiguous_with


@pytest.mark.parametrize("bad", ["ftp://x.com", "javascript:alert(1)", "file:///etc/passwd", "http://u:p@x.com/",
                                 "http://", "https://exa mple.com"])
def test_bad_urls(bad):
    with pytest.raises(TargetError):
        canonicalize("url", bad)


def test_username_requires_explicit_type():
    with pytest.raises(TargetError):
        detect_target("some_handle")
    assert detect_target("@Some_Handle", "username").canonical == "Some_Handle"  # case preserved
    for bad in ("a b", "x;y", "a/b", "", "é" * 80):
        with pytest.raises(TargetError):
            canonicalize("username", bad)


def test_canonicalization_is_stable():
    for t, v in [("domain", "BÜCHER.de"), ("url", "HTTP://Example.com/x"), ("ip", "::ffff:1.2.3.4")]:
        c = canonicalize(t, v)
        assert canonicalize(t, c) == c


def test_domain_of():
    assert domain_of("email", "a@example.com") == "example.com"
    assert domain_of("url", "https://sub.example.com/x") == "sub.example.com"
    assert domain_of("url", "https://1.2.3.4/x") is None


@pytest.mark.parametrize("flag", ["--help", "-oX", "-h", "--version", "-"])
def test_option_like_usernames_rejected(flag):
    with pytest.raises(TargetError):
        canonicalize("username", flag)
