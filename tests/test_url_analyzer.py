
import pytest
from core.url_analyzer import analyze_url


def test_https_url_is_parsed_correctly():
    result = analyze_url("https://example.com/login")

    assert result["scheme"] == "https"
    assert result["hostname"] == "example.com"
    assert result["path"] == "/login"
    assert result["is_https"] is True


def test_http_url_is_not_https():
    result = analyze_url("http://example.com")

    assert result["is_https"] is False


def test_url_without_scheme_defaults_to_https():
    result = analyze_url("example.com")

    assert result["original_url"] == "https://example.com"
    assert result["scheme"] == "https"


def test_ip_address_is_detected():
    result = analyze_url("http://192.168.1.1/login")

    assert result["is_ip_address"] is True


def test_subdomains_are_counted():
    result = analyze_url("https://login.account.example.com")

    assert result["subdomain_count"] == 2


def test_at_symbol_is_detected():
    result = analyze_url("https://example.com@evil.com")

    assert result["has_at_symbol"] is True


def test_hyphen_is_detected():
    result = analyze_url("https://secure-login.com")

    assert result["has_dash"] is True


def test_encoded_characters_are_detected():
    result = analyze_url("https://example.com/%20login")

    assert result["has_encoded_characters"] is True


@pytest.mark.parametrize("url", ["", "   "])
def test_empty_url_raises_error(url):
    with pytest.raises(ValueError, match="Please enter a URL"):
        analyze_url(url)


def test_missing_hostname_raises_error():
    with pytest.raises(ValueError):
        analyze_url("https://")


def test_control_characters_are_rejected():
    with pytest.raises(ValueError):
        analyze_url("https://example.com/\nlogin")
