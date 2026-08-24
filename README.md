# MOTOC Cloud Data Sanitizer

Local-first desktop tool that sanitizes cloud billing CSV/XLSX files on the customer
device using **HMAC-SHA-256 Stable Pseudonymization** (稳定假名化).

## Features

- Local CSV and XLSX processing (no cloud upload)
- Field detection and explicit sanitization choices
- Stable Pseudonymization with a customer-local key
- SHA-256 integrity sidecar for sanitized outputs
- Desktop UI locales: `en-US`, `zh-CN`, `zh-HK`
- Free MVP platforms: macOS arm64, macOS x64, Windows x64

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

## Security terms

Use **Stable Pseudonymization / 稳定假名化**. Do not describe the control as irreversible
anonymization.

## License

All Rights Reserved pending an explicit public licensing decision by the repository
owner. See `LICENSE`.
