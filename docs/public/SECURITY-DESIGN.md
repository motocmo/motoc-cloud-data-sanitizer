# Security Design

This document describes the public security design of Cloud Data Sanitizer for users,
contributors, and security reviewers.

## Goals

- Keep raw billing data on the customer device during processing
- Prevent accidental retention of cloud credentials in exported files
- Provide stable, correlatable identifier tokens without publishing a mapping file
- Prove output integrity with SHA-256 sidecars

## Local-first boundary

All inspection, classification, transformation, validation, and export execute locally.

During processing the application must not:

- call cloud APIs
- upload billing data
- send telemetry or crash content containing customer values
- require cloud credentials

Downloading an installer is outside the processing boundary. Automatic update is not
part of the Free MVP design so the runtime network path remains unambiguous.

## Stable Pseudonymization

Approved control name: **Stable Pseudonymization** / **稳定假名化**.

For correlatable identifiers:

```text
token = label + Base32(
  HMAC-SHA-256(
    customer_key,
    encode(policy_version, provider, correlation_domain, original_value)
  )[:16]
)
```

Properties:

- customer-local key with at least 256 bits
- length-prefixed domain separation
- at least 128 bits of digest retained in the token
- same key/domain/value → same token
- different key or correlation domain → different token
- collision detection stops export
- key material is never written to reports, manifests, logs, or sanitized output

Mapping files that contain original values are Restricted, disabled by default, and
must not be placed beside sanitized upload bundles.

## Restricted credential handling

Credential-like column names or values (access keys, secrets, tokens, passwords, and
similar patterns) are classified as Restricted. Export must physically remove the
column or stop. Masking a credential column and treating it as safe is not allowed.

Credential detection scans the full column, not only a short sample window.

## Key storage

- No product-wide default key
- Optional persistence through the OS key store (macOS Keychain / Windows Credential Manager)
- Session-only keys are supported with an explicit warning that future runs will not correlate
- Keys are never accepted as a long-lived default shared across customers

## Integrity

Every sanitized export produces a sidecar:

```text
<lowercase-sha256>  <exact-filename>
```

Use `cloud-sanitize verify` (or an equivalent independent SHA-256 check) before trusting
an output file.

## Packaged dependency posture

The processing path does not import HTTP clients or cloud SDKs.

The desktop build may still include Qt Network libraries as part of the PySide6 Widgets
stack even when application code never imports them. Optional network plugins are
stripped where possible. Reviewers should treat residual Qt Network binaries as a
packaging dependency, not as an authorization for outbound communication.

## Reporting vulnerabilities

See [SECURITY.md](../../SECURITY.md). Use synthetic data only; never attach customer
billing files, keys, or mappings.

## Related documents

- [Architecture Overview](ARCHITECTURE.md)
- [Threat Model](../../THREAT-MODEL.md)
- [User Guide](USER-GUIDE.md)
