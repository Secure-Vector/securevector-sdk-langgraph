"""Unified engine-endpoint resolution (#190).

SECUREVECTOR_ENGINE_ENDPOINT is the one var for the engine across SDKs + native
plugins. SECUREVECTOR_SDK_APP_URL stays as a legacy alias. Neither is the cloud
URL — the SDK never talks to the SecureVector cloud directly.
"""
import os
import pytest
from securevector_sdk_langgraph.config import Config, DEFAULT_BASE_URL

_VARS = ("SECUREVECTOR_ENGINE_ENDPOINT", "SECUREVECTOR_SDK_APP_URL")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for v in _VARS:
        monkeypatch.delenv(v, raising=False)
    yield


def test_unified_var_wins_over_legacy(monkeypatch):
    monkeypatch.setenv("SECUREVECTOR_ENGINE_ENDPOINT", "https://engine.example")
    monkeypatch.setenv("SECUREVECTOR_SDK_APP_URL", "https://legacy.example")
    assert Config.from_env().base_url == "https://engine.example"


def test_legacy_alias_honored_when_unified_unset(monkeypatch):
    monkeypatch.setenv("SECUREVECTOR_SDK_APP_URL", "https://legacy.example")
    assert Config.from_env().base_url == "https://legacy.example"


def test_default_when_both_unset():
    assert Config.from_env().base_url == DEFAULT_BASE_URL


def test_empty_unified_falls_through_to_legacy(monkeypatch):
    monkeypatch.setenv("SECUREVECTOR_ENGINE_ENDPOINT", "")
    monkeypatch.setenv("SECUREVECTOR_SDK_APP_URL", "https://legacy2.example")
    assert Config.from_env().base_url == "https://legacy2.example"
