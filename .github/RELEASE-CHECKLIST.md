# Release Checklist

Operational guidance for maintainers preparing a GitHub Release.
This file is not an automatic publish trigger.

## Purpose

Use this checklist before publishing platform packages for MOTOC Cloud Data
Sanitizer. Confirm tag integrity, artifact completeness, security metadata, and
documentation alignment.

## Pre-release verification

- Verify the release tag
- Verify the commit SHA bound to that tag
- Verify release notes exist for the tag under `.github/release-notes/`
- Confirm documentation intended for public users is accurate and free of
  internal process language

## Evaluation build status

- macOS packages are unsigned and not notarized
- Windows packages do not include an Authenticode signature
- Packages are for evaluation only and may trigger operating system warnings
- Do not describe evaluation packages as production-ready or enterprise releases

## Artifact verification

After a successful protected release workflow, confirm these assets exist:

- `CloudDataSanitizer-macos-arm64.zip` (+ `.sha256`)
- `CloudDataSanitizer-macos-x64.zip` (+ `.sha256`)
- `CloudDataSanitizer-windows-x64.zip` (+ `.sha256`)
- `SHA256SUMS.txt`
- `release-manifest.json`
- `SBOM.json`
- `sbom.cdx.json`
- `provenance.json`

Also verify:

- Artifact integrity against published checksums
- Manifest version and commit SHA match the release tag
- Security metadata is present and consistent

## Security verification

- No automatic upload behavior in the product boundary
- No cloud credential collection in the product boundary
- Every artifact must report `signature_status: unsigned_evaluation`
- macOS artifacts must report `notarization_status: not_attempted`
- Unsigned evaluation packages must not be published as production assets

## Documentation review

- README and public docs describe local-first CSV/XLSX preparation clearly
- Release notes state Release Candidate status when applicable
- Public docs do not expose internal workflow or private validation process details

## Release approval

Owner: Release Validation Maintainer

Steps:

1. Complete artifact verification
2. Complete security verification
3. Complete documentation review
4. Perform Release Validation Review
5. Promote the draft release only after approval

Do not present website downloads as production-ready. Display the unsigned
evaluation warning next to every download link.
