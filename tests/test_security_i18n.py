from __future__ import annotations

import socket
from pathlib import Path

import pytest

from cloud_data_sanitizer.i18n import SUPPORTED_LOCALES, Translator, normalize_locale
from cloud_data_sanitizer.service import sanitize_dataset

KNOWN_KEY = bytes.fromhex("33" * 32)


def test_locale_catalog_parity() -> None:
    translator = Translator("en-US")
    keys = translator.keys()
    assert keys
    for locale in SUPPORTED_LOCALES:
        translator.set_locale(locale)
        assert translator.t("app.title")
        assert translator.t("action.pseudonymize")
        # Chinese catalogs must not fall back to English for core keys
        if locale != "en-US":
            assert translator.t("action.pseudonymize") != "Stable Pseudonymization"


def test_zh_tw_aliases_to_zh_hk() -> None:
    assert normalize_locale("zh-TW") == "zh-HK"
    assert normalize_locale("zh_TW") == "zh-HK"


def test_zh_hk_uses_traditional_wording() -> None:
    translator = Translator("zh-HK")
    text = translator.t("file.choose")
    assert "選擇" in text
    assert "选择" not in text


def test_processing_makes_no_network_calls(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def deny(*_args, **_kwargs):  # type: ignore[no-untyped-def]
        raise AssertionError("network access is forbidden during sanitization")

    monkeypatch.setattr(socket, "socket", deny)
    monkeypatch.setattr(socket, "create_connection", deny)
    monkeypatch.setattr(socket, "getaddrinfo", deny)

    source = tmp_path / "billing.csv"
    source.write_text(
        "Service,Cost,Currency,UsageDate,ResourceId\n"
        "Compute,1.00,USD,2026-07-01,vm-1\n",
        encoding="utf-8",
    )
    sanitize_dataset(
        source,
        tmp_path / "out.csv",
        keep_potential=True,
        customer_key=KNOWN_KEY,
    )


def test_no_http_clients_imported() -> None:
    import sys

    import cloud_data_sanitizer as package

    forbidden = {
        "requests",
        "httpx",
        "urllib3",
        "aiohttp",
        "boto3",
        "botocore",
        "azure",
        "google.cloud",
        "alibabacloud",
    }
    loaded = {name for name in sys.modules if any(name == f or name.startswith(f + ".") for f in forbidden)}
    assert not loaded
    assert package.__name__ == "cloud_data_sanitizer"
