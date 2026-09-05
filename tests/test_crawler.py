"""Crawler tests. Start the test app first: python labs/vulnerable_app/app.py"""
import pytest

from proofscan.config import OutOfScopeError, Scope
from proofscan.crawler import Crawler
from proofscan.http_client import HttpClient

BASE = "http://127.0.0.1:5001"


@pytest.fixture(scope="module")
def crawl_result():
    scope = Scope.from_url(BASE)
    with HttpClient(scope) as client:
        try:
            client.get(BASE)
        except Exception:
            pytest.skip("test app not running")
        yield Crawler(client, scope).crawl(BASE)


def test_finds_every_page(crawl_result):
    paths = {url.replace(BASE, "").split("?")[0] or "/" for url in crawl_result.pages}
    for expected in ["/", "/product", "/safe-product", "/search",
                     "/safe-search", "/comment", "/plain", "/jitter", "/login"]:
        assert expected in paths, f"crawler missed {expected}"


def test_finds_query_parameters(crawl_result):
    params = {p.param for p in crawl_result.injection_points if p.source == "query"}
    assert "id" in params
    assert "q" in params


def test_finds_form_fields(crawl_result):
    form_points = [p for p in crawl_result.injection_points if p.source == "form"]
    names = {p.param for p in form_points}
    assert "username" in names
    assert "password" in names
    assert all(p.method == "POST" for p in form_points if p.param == "username")


def test_scope_blocks_outside_hosts():
    scope = Scope.from_url(BASE)
    assert scope.allows(f"{BASE}/product")
    assert not scope.allows("http://example.com/")
    with HttpClient(scope) as client:
        with pytest.raises(OutOfScopeError):
            client.get("http://example.com/")
