"""Auth-forwarding: SECUREVECTOR_API_KEY -> Authorization: Bearer.

The SDK talks to the local app over loopback by default (no auth). When the app
is a remote, token-gated deployment (e.g. the Terraform self-host modules), the
client forwards SECUREVECTOR_API_KEY as a Bearer credential. These tests pin
that contract without needing a running app.
"""

import urllib.request

from securevector_sdk_langgraph.client import LocalAppClient
from securevector_sdk_langgraph.config import Config


class _FakeResp:
    def __init__(self, payload=b"{}"):
        self._payload = payload

    def read(self):
        return self._payload

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _capture_headers(monkeypatch):
    captured = {}

    def fake_urlopen(req, timeout=None):
        captured.update({k.lower(): v for k, v in req.header_items()})
        return _FakeResp()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    return captured


def test_api_key_forwarded_as_bearer(monkeypatch):
    headers = _capture_headers(monkeypatch)
    LocalAppClient(Config.from_env(api_key="svpk_explicit"))._get("/health")
    assert headers.get("authorization") == "Bearer svpk_explicit"


def test_api_key_read_from_env(monkeypatch):
    monkeypatch.setenv("SECUREVECTOR_API_KEY", "svpk_fromenv")
    headers = _capture_headers(monkeypatch)
    LocalAppClient(Config.from_env())._get("/health")
    assert headers.get("authorization") == "Bearer svpk_fromenv"


def test_no_auth_header_when_unset(monkeypatch):
    monkeypatch.delenv("SECUREVECTOR_API_KEY", raising=False)
    headers = _capture_headers(monkeypatch)
    LocalAppClient(Config.from_env(api_key=""))._get("/health")
    assert "authorization" not in headers
