#!/usr/bin/env python3
"""Inspect a packaged ZIP for disallowed network components (CDS-V-005).

Policy:
- HTTP clients / cloud SDKs are forbidden and fail closed.
- PySide6 may still ship QtNetwork as a reviewed unavoidable dependency of Qt
  Widgets (see docs/NETWORK-BOUNDARY.md). Optional network *plugins* must be
  stripped by the build script.
"""

from __future__ import annotations

import argparse
import sys
import zipfile
from pathlib import Path

FORBIDDEN_NAME_FRAGMENTS = (
    "requests/",
    "urllib3/",
    "httpx/",
    "aiohttp/",
    "boto3/",
    "botocore/",
    "azure/",
    "google/cloud",
    "qtwebengine",
    "qtwebsockets",
    "qthttpserver",
    "plugins/networkinformation",
    "libqapplenetworkinformation",
)

# Present only when documented as unavoidable; still reported for audit.
REVIEWED_UNAVOIDABLE = ("qtnetwork",)


def inspect_zip(path: Path) -> tuple[list[str], list[str]]:
    forbidden: list[str] = []
    reviewed: list[str] = []
    with zipfile.ZipFile(path) as archive:
        for name in archive.namelist():
            lowered = name.lower()
            if any(fragment in lowered for fragment in FORBIDDEN_NAME_FRAGMENTS):
                forbidden.append(name)
                continue
            if any(fragment in lowered for fragment in REVIEWED_UNAVOIDABLE):
                reviewed.append(name)
    return sorted(set(forbidden)), sorted(set(reviewed))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("package", type=Path)
    args = parser.parse_args(argv)
    if not args.package.is_file():
        print(f"FAIL: package not found: {args.package}", file=sys.stderr)
        return 2
    forbidden, reviewed = inspect_zip(args.package)
    if forbidden:
        print("FAIL CLOSED: forbidden network components in package:", file=sys.stderr)
        for hit in forbidden[:50]:
            print(f"  {hit}", file=sys.stderr)
        return 1
    if reviewed:
        print(
            "PASS with reviewed unavoidable QtNetwork dependency "
            f"({len(reviewed)} paths). See docs/public/SECURITY-DESIGN.md"
        )
    else:
        print(f"PASS: no network components in {args.package.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
