# User Guide

Cloud Data Sanitizer helps you create a privacy-preserving local copy of cloud
billing CSV or XLSX files before you share them for analysis.

## Before you start

- Work only with files stored on your device
- Keep your original billing file unchanged; the tool always writes a new output
- Decide whether identifier correlation across future runs is required
  - Persist the key in the OS key store if you need stable correlation later
  - Use a session-only key if you do not want future runs to correlate

## Install / launch

### Released desktop package

1. Download the ZIP for your platform from the GitHub Releases page
2. Verify the published SHA-256 checksum
3. Extract and launch `Cloud Data Sanitizer`

Current packages are unsigned evaluation builds:

- macOS packages are not code-signed or notarized. macOS may block the first
  launch; use the standard Finder **Open** or **Privacy & Security** confirmation
  flow if you trust the downloaded checksum.
- The Windows package has no Authenticode signature. Microsoft Defender
  SmartScreen may show **Unknown publisher**.
- Do not disable Gatekeeper, SmartScreen, or antivirus protections globally.

### Development install

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.lock.txt
pip install '.[desktop]'
cloud-data-sanitizer
```

## Desktop workflow

1. Choose language: `en-US`, `zh-CN`, or `zh-HK`
2. Select a local `.csv` or `.xlsx` file
3. Review field classifications and recommended actions
4. For each field, choose:
   - **Stable Pseudonymization** — replace identifiers with HMAC-based tokens
   - **Remove column** — physically drop Restricted / unwanted columns
   - **Keep** — retain the value unchanged
5. Optionally persist the local key in the OS key store
6. Generate the sanitized copy
7. Keep the `.sha256` sidecar with the output if you need integrity verification later

## CLI workflow

Inspect without modifying the file:

```bash
cloud-sanitize inspect billing.csv --json
```

Create a sanitized copy:

```bash
cloud-sanitize sanitize billing.csv billing_sanitized.csv \
  --keep-potential \
  --rule 'ResourceId=pseudonymize' \
  --key-hex <64-hex-characters>
```

Verify integrity:

```bash
cloud-sanitize verify billing_sanitized.csv
```

## Field guidance

| Classification | Typical action |
| --- | --- |
| Analysis required (cost, currency, service, dates, …) | Keep |
| Sensitive identifiers (resource id, account id, owner, …) | Stable Pseudonymization |
| Potentially sensitive (resource group, team, environment, …) | Explicit keep / remove / pseudonymize decision |
| Restricted credential-like columns | Remove column (required) |

## Language notes

- Supported locales: `en-US`, `zh-CN`, `zh-HK`
- `zh-HK` is Hong Kong Traditional Chinese
- A historical `zh-TW` preference, if present, resolves to `zh-HK`

## Security wording

Use **Stable Pseudonymization** (稳定假名化). Do not describe the control as
guaranteed irreversible anonymization.

## What this tool does not do

- Connect to Azure, AWS, Alibaba Cloud, or other cloud accounts
- Request access keys, tokens, or passwords for cloud APIs
- Upload files automatically
- Calculate savings, Findings, or FinOps recommendations
