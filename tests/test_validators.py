
import pytest
from utils.validators import validate_url


@pytest.mark.parametrize("url", [
    "https://example.com",
    "http://example.com",
    "example.com",
    "https://sub.example.com/login",
])
def test_valid_urls(url):
    assert validate_url(url) is True


@pytest.mark.parametrize("url", [
    "",
    "   ",
    None,
    "https://",
    "ftp://example.com",
    "https://example.com:99999",
    "https://example.com/\nlogin",
])
def test_invalid_urls(url):
    assert validate_url(url) is False
