# Architecture Overview

Cloud Data Sanitizer is a local-first desktop application that prepares cloud
billing CSV and XLSX files for later analysis. It runs entirely on the customer
device and does not perform FinOps analysis itself.

## Product boundary

| In scope | Out of scope |
| --- | --- |
| Local CSV / XLSX inspection and export | Cloud connectors or provider APIs |
| Field classification and sanitization | Automatic upload to MOTOC or any SaaS |
| HMAC-SHA-256 stable pseudonymization | Cloud credentials or account login |
| Local SHA-256 integrity sidecars | Telemetry, remote rules, or AI processing |
| Desktop UI with `en-US`, `zh-CN`, `zh-HK` | Linux / mobile / browser editions |

## Runtime architecture

```text
Customer Device
  ├── Desktop UI (PySide6)
  ├── Core services (Qt-independent)
  │     ├── CSV / XLSX readers
  │     ├── Field detection and classification
  │     ├── Stable Pseudonymization (HMAC-SHA-256)
  │     ├── Integrity validation
  │     └── Exporters + SHA-256 sidecar
  └── Local key material (session memory or OS key store)
```

The desktop UI calls the same typed services exercised by automated tests. Masking
and financial reconciliation logic do not live in widget code.

## Platforms and formats

- macOS Apple Silicon (arm64)
- macOS Intel (x64)
- Windows (x64)
- Input / output: CSV and XLSX only

## Data flow

```text
Select local billing file
        ↓
Inspect and classify fields
        ↓
Choose keep / remove / stable pseudonymize
        ↓
Validate financial integrity locally
        ↓
Export sanitized file + SHA-256 sidecar
        ↓
(Optional, user-driven) Upload sanitized file elsewhere
```

The application never uploads on the user's behalf.

## Versioning and packages

Releases use Semantic Versioning (`vMAJOR.MINOR.PATCH`). A complete release set
includes platform ZIP archives, per-file `.sha256` checksums, aggregate
`SHA256SUMS.txt`, and a release manifest.

## Related public documents

- [User Guide](USER-GUIDE.md)
- [Security Design](SECURITY-DESIGN.md)
- [Threat Model](../../THREAT-MODEL.md)
- [Security Policy](../../SECURITY.md)
