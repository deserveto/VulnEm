import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vulnem.scope import Scope, ScopeError


def test_parses_full_url():
    scope = Scope.from_target("http://juice-shop:3000")
    assert scope.host == "juice-shop"
    assert scope.port == 3000
    assert scope.scheme == "http"
    assert "juice-shop" in scope.allowed_hosts


def test_adds_scheme_when_missing():
    scope = Scope.from_target("example.com")
    assert scope.scheme == "http"
    assert scope.host == "example.com"
    assert scope.target_url == "http://example.com"


def test_default_port_https():
    scope = Scope.from_target("https://example.com")
    assert scope.port == 443


def test_rejects_non_http_scheme():
    with pytest.raises(ScopeError):
        Scope.from_target("ftp://example.com")


def test_rejects_empty_host():
    with pytest.raises(ScopeError):
        Scope.from_target("http://")


def test_extra_hosts_lowercase_deduped():
    scope = Scope.from_target("http://App.Example", extra_hosts=["API.Example", "app.example"])
    assert scope.allowed_hosts == ("app.example", "api.example")


def test_prompt_block_lists_all_hosts():
    scope = Scope.from_target("http://target", extra_hosts=["extra"])
    text = scope.describe_for_prompt()
    assert "http://target" in text
    assert "- target" in text
    assert "- extra" in text
