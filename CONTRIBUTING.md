# Contributing

Thank you for contributing to Cloud Data Sanitizer.

## Scope

This repository contains only the local desktop sanitizer. Please keep changes inside
this repository and within Free MVP scope:

- CSV / XLSX local processing
- Stable Pseudonymization and integrity checks
- Desktop UI and `en-US` / `zh-CN` / `zh-HK` locales
- Build and CI for macOS arm64, macOS x64, and Windows x64

Do not add cloud connectors, credential collection, automatic upload, telemetry, or
FinOps analysis features.

## Documentation

| Kind | Location | Commit? |
| --- | --- | --- |
| Public product docs | `docs/public/` | Yes |
| Root security / contributor docs | `README.md`, `SECURITY.md`, `THREAT-MODEL.md`, `CONTRIBUTING.md` | Yes |
| Internal engineering notes | `docs/internal/` | No |

If you are unsure whether a Markdown file is public, place it under `docs/internal/`
and ask a maintainer before publishing.

## Local checks

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock.txt
pip install '.[dev,desktop]'
pytest
ruff check src tests scripts
```

## Pull requests

- Prefer small, reviewable changes with tests
- Use synthetic fixtures only — never commit customer billing data, keys, or mappings
- Do not commit files under `docs/internal/`
- Confirm `git ls-files` does not list internal workflow, validation, or implementation-skill documents before requesting review
