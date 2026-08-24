#!/usr/bin/env python3
"""Assemble release checksums, manifest, SBOM, and provenance.

FAIL CLOSED rules:
- all three platform ZIPs required
- source tag + full 40-char commit required
- every artifact trust.json must report signature_status=verified
- pending/unsigned/unverified states abort publication
- no absolute developer paths in emitted metadata
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
from datetime import UTC, datetime
from pathlib import Path

REQUIRED = [
    "CloudDataSanitizer-macos-arm64.zip",
    "CloudDataSanitizer-macos-x64.zip",
    "CloudDataSanitizer-windows-x64.zip",
]

COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
# Accept SemVer tags including prerelease (e.g. v0.1.0, v0.1.0-rc.1).
TAG_RE = re.compile(
    r"^v(?P<version>\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?)$"
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def find_file(input_dir: Path, name: str) -> Path:
    matches = list(input_dir.rglob(name))
    if not matches:
        raise SystemExit(f"FAIL CLOSED: missing required artifact: {name}")
    if len(matches) > 1:
        raise SystemExit(f"FAIL CLOSED: duplicate artifact candidates for {name}")
    return matches[0]


def load_trust(input_dir: Path, zip_name: str) -> dict[str, str]:
    trust_name = zip_name.removesuffix(".zip") + ".trust.json"
    matches = list(input_dir.rglob(trust_name))
    if not matches:
        raise SystemExit(f"FAIL CLOSED: missing trust metadata: {trust_name}")
    payload = json.loads(matches[0].read_text(encoding="utf-8"))
    signature = payload.get("signature_status")
    notarization = payload.get("notarization_status")
    if signature != "verified":
        raise SystemExit(
            f"FAIL CLOSED: {zip_name} signature_status={signature!r} (required verified)"
        )
    if zip_name.startswith("CloudDataSanitizer-macos-") and notarization != "verified":
        raise SystemExit(
            f"FAIL CLOSED: {zip_name} notarization_status={notarization!r} "
            "(required verified)"
        )
    if any(
        token in str(value).lower()
        for value in payload.values()
        for token in ("pending", "unsigned", "not_attempted")
    ):
        raise SystemExit(
            f"FAIL CLOSED: {trust_name} contains pending/unverified trust state: {payload}"
        )
    return {
        "signature_status": str(signature),
        "notarization_status": str(notarization),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--input-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--allow-incomplete", action="store_true")
    args = parser.parse_args()

    if args.allow_incomplete:
        raise SystemExit(
            "FAIL CLOSED: --allow-incomplete is not permitted for release aggregation"
        )
    if not TAG_RE.match(args.tag):
        raise SystemExit(f"FAIL CLOSED: invalid release tag: {args.tag}")
    if not COMMIT_RE.match(args.commit):
        raise SystemExit(
            f"FAIL CLOSED: source commit must be full 40-char SHA, got {args.commit!r}"
        )
    if args.version != args.tag.lstrip("v"):
        raise SystemExit(
            f"FAIL CLOSED: version {args.version!r} does not match tag {args.tag!r}"
        )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    artifacts = []
    sums_lines: list[str] = []
    meta = {
        "CloudDataSanitizer-macos-arm64.zip": ("macOS", "arm64"),
        "CloudDataSanitizer-macos-x64.zip": ("macOS", "x64"),
        "CloudDataSanitizer-windows-x64.zip": ("Windows", "x64"),
    }

    for filename in REQUIRED:
        source = find_file(args.input_dir, filename)
        destination = args.output_dir / filename
        shutil.copy2(source, destination)
        digest = sha256_file(destination)
        if destination.stat().st_size <= 0:
            raise SystemExit(f"FAIL CLOSED: zero-size artifact {filename}")
        sidecar = args.output_dir / f"{filename}.sha256"
        sidecar.write_text(f"{digest}  {filename}\n", encoding="utf-8")
        sums_lines.append(f"{digest}  {filename}")
        trust = load_trust(args.input_dir, filename)
        os_name, arch = meta[filename]
        artifacts.append(
            {
                "filename": filename,
                "os": os_name,
                "architecture": arch,
                "size_bytes": destination.stat().st_size,
                "sha256": digest,
                "signature_status": trust["signature_status"],
                "notarization_status": trust["notarization_status"],
            }
        )

    (args.output_dir / "SHA256SUMS.txt").write_text(
        "\n".join(sums_lines) + "\n", encoding="utf-8"
    )

    build_time = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "schema_version": "1.0",
        "product": "Cloud Data Sanitizer",
        "version": args.version,
        "repository": "https://github.com/motocmo/motoc-cloud-data-sanitizer",
        "source_tag": args.tag,
        "source_commit": args.commit,
        "policy_version": "cds-policy-1",
        "locales": ["en-US", "zh-CN", "zh-HK"],
        "formats": ["csv", "xlsx"],
        "build_time": build_time,
        "sbom": "SBOM.json",
        "sbom_cyclonedx": "sbom.cdx.json",
        "provenance": "provenance.json",
        "artifacts": artifacts,
    }
    # Hard reject absolute paths / usernames in serialized metadata.
    serialized = json.dumps(manifest, indent=2)
    if "/Users/" in serialized or "C:\\\\Users\\\\" in serialized:
        raise SystemExit("FAIL CLOSED: manifest contains absolute user paths")
    (args.output_dir / "release-manifest.json").write_text(
        serialized + "\n", encoding="utf-8"
    )

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": build_time,
            "component": {
                "type": "application",
                "name": "Cloud Data Sanitizer",
                "version": args.version,
            },
        },
        "components": [
            {
                "type": "file",
                "name": item["filename"],
                "version": args.version,
                "hashes": [{"alg": "SHA-256", "content": item["sha256"]}],
            }
            for item in artifacts
        ],
    }
    sbom_text = json.dumps(sbom, indent=2) + "\n"
    (args.output_dir / "sbom.cdx.json").write_text(sbom_text, encoding="utf-8")
    (args.output_dir / "SBOM.json").write_text(sbom_text, encoding="utf-8")

    provenance = {
        "schema_version": "1.0",
        "product": "Cloud Data Sanitizer",
        "version": args.version,
        "source_tag": args.tag,
        "source_commit": args.commit,
        "build_time": build_time,
        "artifact_count": len(artifacts),
        "artifact_sha256": {item["filename"]: item["sha256"] for item in artifacts},
        "notes": "Built on native GitHub-hosted runners with fail-closed signing gates.",
    }
    (args.output_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
    )
    print("Release aggregation complete (fail-closed gates passed)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
