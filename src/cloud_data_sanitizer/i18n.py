from __future__ import annotations

import json
from pathlib import Path
from typing import Any

SUPPORTED_LOCALES = ("en-US", "zh-CN", "zh-HK")
DEFAULT_LOCALE = "en-US"


def normalize_locale(locale: str | None) -> str:
    if not locale:
        return DEFAULT_LOCALE
    raw = locale.strip().replace("_", "-")
    # Historical compatibility only: zh-TW resolves to zh-HK (no Taiwan terminology).
    if raw.lower() in {"zh-tw", "zhtw"}:
        return "zh-HK"
    for supported in SUPPORTED_LOCALES:
        if raw.lower() == supported.lower():
            return supported
    language = raw.split("-", 1)[0].lower()
    if language == "zh":
        if "cn" in raw.lower() or "hans" in raw.lower():
            return "zh-CN"
        return "zh-HK"
    if language == "en":
        return "en-US"
    return DEFAULT_LOCALE


def _catalog_dir() -> Path:
    here = Path(__file__).resolve()
    candidates = [
        here.parent / "locales",
        here.parents[2] / "locales",
        Path.cwd() / "locales",
    ]
    for candidate in candidates:
        if candidate.is_dir() and (candidate / "en-US.json").is_file():
            return candidate
    raise FileNotFoundError("Locale catalogs were not found.")


class Translator:
    def __init__(self, locale: str = DEFAULT_LOCALE) -> None:
        self._catalogs: dict[str, dict[str, str]] = {}
        self._load_all()
        self.set_locale(locale)

    def _load_all(self) -> None:
        root = _catalog_dir()
        for locale in SUPPORTED_LOCALES:
            path = root / f"{locale}.json"
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                raise TypeError(f"Locale catalog {locale} must be a JSON object.")
            self._catalogs[locale] = {str(k): str(v) for k, v in payload.items()}
        self._validate_parity()

    def _validate_parity(self) -> None:
        base_keys = set(self._catalogs[DEFAULT_LOCALE])
        for locale, catalog in self._catalogs.items():
            keys = set(catalog)
            missing = base_keys - keys
            extra = keys - base_keys
            if missing or extra:
                raise ValueError(
                    f"Locale {locale} key mismatch. missing={sorted(missing)} "
                    f"extra={sorted(extra)}"
                )

    def set_locale(self, locale: str) -> str:
        self.locale = normalize_locale(locale)
        return self.locale

    def t(self, key: str, **params: Any) -> str:
        catalog = self._catalogs.get(self.locale, {})
        fallback = self._catalogs[DEFAULT_LOCALE]
        template = catalog.get(key) or fallback.get(key) or key
        try:
            return template.format(**params) if params else template
        except KeyError:
            return template

    def keys(self) -> set[str]:
        return set(self._catalogs[DEFAULT_LOCALE])


_translator: Translator | None = None


def get_translator(locale: str | None = None) -> Translator:
    global _translator
    if _translator is None:
        _translator = Translator(locale or DEFAULT_LOCALE)
    elif locale:
        _translator.set_locale(locale)
    return _translator
