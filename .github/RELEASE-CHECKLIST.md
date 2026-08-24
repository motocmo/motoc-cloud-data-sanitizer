# Release preparation checklist (operators)
#
# This file is operational guidance for maintainers preparing a GitHub Release.
# It is not an automatic publish trigger.

## Bound candidate

- Commit: a0b71be89edd2b0d4fb45ea8e6ce731480a45093
- Tag: v0.1.0-rc.1
- Notes: .github/release-notes/v0.1.0-rc.1.md

## Required GitHub Environments / secrets

### macos-notarization

- MACOS_CODESIGN_IDENTITY
- MACOS_NOTARY_PROFILE (notarytool keychain profile on the runner)

### windows-signing

- WINDOWS_CERT_PATH
- WINDOWS_CERT_PASSWORD (optional if cert has no password)

## Artifact contract

Must exist after a successful protected release workflow:

- CloudDataSanitizer-macos-arm64.zip (+ .sha256)
- CloudDataSanitizer-macos-x64.zip (+ .sha256)
- CloudDataSanitizer-windows-x64.zip (+ .sha256)
- SHA256SUMS.txt
- release-manifest.json
- SBOM.json
- sbom.cdx.json
- provenance.json

## Gates

- Unsigned smoke packages must not be published as production assets
- Release workflow creates a **draft** release; Codex/maintainers promote after CR-007
- Do not mark website downloads available until signed assets and checksums verify
