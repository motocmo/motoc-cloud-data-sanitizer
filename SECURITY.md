# Security Policy

## Local-first boundary

Cloud Data Sanitizer processes billing files only on the customer device. It must not
request cloud credentials, open network connections during processing, or upload data.

## Reporting a vulnerability

Email security reports to the MOTOC maintainers through the private security contact
configured on the GitHub repository (Security Advisories preferred).

Please include:

- affected version / commit SHA
- reproduction with **synthetic** data only
- impact assessment

Do not attach customer billing files, keys, mappings, or credentials.

## Out of scope for reporters

- social engineering
- denial-of-service against GitHub or MOTOC SaaS
- physical attacks

## Key and mapping handling

- Customer HMAC keys must never appear in issues, logs, or pull requests
- Mapping files are Restricted and disabled by default
- Rotate keys intentionally; rotation breaks cross-run correlation
