# MOTOC Cloud Data Sanitizer

**Securely prepare cloud billing data for FinOps analysis.**

Process CSV and XLSX billing exports locally on your device, protect sensitive
identifiers, and preserve the billing dimensions required for FinOps analysis—
without uploading data or connecting to cloud accounts.

## Why it exists

FinOps analysis needs billing facts such as cost, currency, service, and usage
period. It does not need raw account identifiers, host names, or credential-like
columns.

This application prepares a safer local copy so you can share sanitized billing
data on your own terms.

## What you get

- **Local-first processing** — files never leave your device during sanitization
- **CSV and XLSX support** — common cloud billing export formats
- **Sensitive identifier protection** — HMAC-SHA-256 Stable Pseudonymization for
  identifier protection without sharing original values
- **Restricted credential handling** — credential-like columns are dropped, not
  masked and treated as safe
- **Integrity checks** — SHA-256 sidecar for every sanitized output
- **Languages** — English (`en-US`), Simplified Chinese (`zh-CN`), and Hong Kong
  Traditional Chinese (`zh-HK`)
- **Platforms** — macOS Apple Silicon, macOS Intel, and Windows x64

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

## Desktop Application Quick Start

1. Download the platform package from [GitHub Releases](https://github.com/motocmo/motoc-cloud-data-sanitizer/releases)
2. Verify the SHA-256 checksum
3. Launch the desktop application
4. Select a CSV/XLSX billing export
5. Generate sanitized billing output locally

For step-by-step usage, see the [User Guide](docs/public/USER-GUIDE.md).

> **Unsigned evaluation build:** Current macOS packages have an ad-hoc integrity
> seal but no Apple Developer ID signature or notarization. The Windows package
> does not include an Authenticode signature. Your operating system may display
> an unknown-publisher or security warning.
> Do not disable Gatekeeper, SmartScreen, or antivirus protections globally.

## Releases

Evaluation prereleases provide:

- Platform packages for macOS arm64, macOS x64, and Windows x64
- SHA-256 checksums
- A release manifest
- Security metadata such as SBOM and provenance records

Verify checksums before use. These packages are unsigned and intended for
evaluation only. They are not production-ready releases. Publisher signing and
macOS notarization may be added after product demand is validated.

## Developer Setup

For contributors and developers only.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock.txt
pip install '.[dev,desktop]'
pytest
cloud-data-sanitizer
```

CLI helpers for local development:

```bash
cloud-sanitize inspect billing.csv --json
cloud-sanitize sanitize billing.csv billing_sanitized.csv \
  --keep-potential --rule 'ResourceId=pseudonymize' --key-hex <64-hex-chars>
cloud-sanitize verify billing_sanitized.csv
```

See [Contributing](CONTRIBUTING.md) for contribution guidelines.

## License

See [LICENSE](LICENSE) for usage terms.
