# Threat Model — Cloud Data Sanitizer

## Assets

- Customer billing CSV/XLSX contents
- Customer-local HMAC key material
- Optional mapping data (Restricted; disabled by default)
- Sanitized outputs and SHA-256 sidecars

## Trust boundary

```text
Customer Device
  -> Local inspection / classification
  -> Stable Pseudonymization (HMAC-SHA-256)
  -> Export sanitized file + SHA-256
  -> (Future, user-driven) Upload to MOTOC
```

The application must not cross the network boundary while processing.

## Adversaries

| Adversary | Goal | Mitigations |
| --- | --- | --- |
| Honest-but-curious analyst receiving sanitized files | Recover identifiers | Domain-separated HMAC, no shared product key, no mapping beside output |
| Malware on customer device | Steal key / raw files | OS key store; never log keys; session-key option |
| Supply-chain attacker | Trojans in release | Signed builds, checksums, provenance (release pipeline) |
| Accidental operator | Overwrite source / leak secrets | Refuse overwrite; Restricted columns dropped; safe errors |

## Explicit non-goals (Phase 1)

- Protecting against a fully compromised customer OS
- Guaranteeing irreversible anonymization
- Cloud credential vaulting or KMS
- Automatic updates (deferred to avoid ambiguous network paths)

## Residual risks

- Low-entropy identifiers may remain linkable within one customer key context
- Key rotation intentionally breaks correlation; users must understand this
- Unsigned local developer builds are not release evidence for CR-007
