# MOTOC Cloud Data Sanitizer

Privacy-first desktop software for preparing cloud billing files before FinOps
analysis.

Cloud Data Sanitizer runs entirely on your device. It helps you inspect CSV and
XLSX billing exports, protect sensitive identifiers, and produce an
analysis-ready copy—without uploading data or connecting to cloud accounts.

## Why it exists

FinOps analysis needs billing facts such as cost, currency, service, and usage
period. It does not need raw account identifiers, host names, or credential-like
columns.

This tool prepares that safer local copy so you can share sanitized billing data
on your own terms.

## What you get

- **Local-first processing** — files never leave your device during sanitization
- **CSV and XLSX support** — common cloud billing export formats
- **Sensitive identifier protection** — HMAC-SHA-256 Stable Pseudonymization
  (稳定假名化) with your local key
- **Restricted credential handling** — credential-like columns are dropped, not
  masked and treated as safe
- **Integrity checks** — SHA-256 sidecar for every sanitized output
- **Languages** — `en-US`, `zh-CN`, `zh-HK`
- **Platforms** — macOS Apple Silicon, macOS Intel, Windows x64

## What it does not do

- Connect to Azure, AWS, Alibaba Cloud, or other cloud APIs
- Request cloud access keys, tokens, or passwords
- Upload files automatically
- Calculate savings, Findings, or FinOps recommendations

Technical security detail: [Security Design](docs/public/SECURITY-DESIGN.md).

## Documentation

| Document | Audience |
| --- | --- |
| [Architecture Overview](docs/public/ARCHITECTURE.md) | Users, contributors, reviewers |
| [User Guide](docs/public/USER-GUIDE.md) | End users |
| [Security Design](docs/public/SECURITY-DESIGN.md) | Security reviewers |
| [Threat Model](THREAT-MODEL.md) | Security reviewers |
| [Security Policy](SECURITY.md) | Vulnerability reporters |
| [Contributing](CONTRIBUTING.md) | Contributors |

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock.txt
pip install '.[dev,desktop]'
pytest
cloud-data-sanitizer
```

CLI:

```bash
cloud-sanitize inspect billing.csv --json
cloud-sanitize sanitize billing.csv billing_sanitized.csv \
  --keep-potential --rule 'ResourceId=pseudonymize' --key-hex <64-hex-chars>
cloud-sanitize verify billing_sanitized.csv
```

## Releases

Download signed platform packages from GitHub Releases when published. Verify
checksums before use. Release candidates are for evaluation and are not a final
production declaration until maintainers confirm acceptance.

## License

All Rights Reserved pending an explicit public licensing decision by the repository
owner. See `LICENSE`.
