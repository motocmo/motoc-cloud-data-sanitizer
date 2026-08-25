#!/usr/bin/env python3
"""Native PyInstaller packaging helper (no cross-compilation).

Signed release builds (unsigned flags omitted) FAIL CLOSED unless native signing
and verification succeed. Smoke and public evaluation builds are explicitly
marked unsigned and must never be represented as production-ready artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "packaging" / "dist"
WORK = ROOT / "packaging" / "work"
APP_NAME = "CloudDataSanitizer"
PRODUCT_VERSION = "0.1.0"

# Modules that must not appear in the Free MVP processing binary.
EXCLUDED_MODULES = [
    "PySide6.QtNetwork",
    "PySide6.QtBluetooth",
    "PySide6.QtNfc",
    "PySide6.QtWebEngineCore",
    "PySide6.QtWebEngineWidgets",
    "PySide6.QtWebSockets",
    "PySide6.QtHttpServer",
    "requests",
    "httpx",
    "urllib3",
    "aiohttp",
    "boto3",
    "botocore",
]


def detect_target() -> tuple[str, str]:
    system = platform.system().lower()
    machine = platform.machine().lower()
    if system == "darwin":
        os_name = "macos"
        arch = "arm64" if machine in {"arm64", "aarch64"} else "x64"
    elif system == "windows":
        os_name = "windows"
        arch = "x64"
    else:
        raise SystemExit(f"Unsupported build host: {system}/{machine}")
    return os_name, arch


def artifact_name(os_name: str, arch: str) -> str:
    return f"CloudDataSanitizer-{os_name}-{arch}.zip"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def require_cpython_312(*, unsigned: bool) -> None:
    if unsigned:
        return
    if sys.version_info[:2] != (3, 12):
        raise SystemExit(
            f"Release builds require CPython 3.12; found {sys.version.split()[0]}"
        )


def write_version_info(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "product": "Cloud Data Sanitizer",
                "version": PRODUCT_VERSION,
                "policy_version": "cds-policy-1",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )


def embed_macos_version(info_path: Path) -> None:
    with info_path.open("rb") as handle:
        info = plistlib.load(handle)
    info["CFBundleShortVersionString"] = PRODUCT_VERSION
    info["CFBundleVersion"] = PRODUCT_VERSION
    with info_path.open("wb") as handle:
        plistlib.dump(info, handle, sort_keys=False)


def seal_unsigned_macos_bundle(app_bundle: Path) -> None:
    """Restore integrity after packaging without establishing publisher identity."""
    subprocess.check_call(
        ["codesign", "--force", "--deep", "--sign", "-", str(app_bundle)]
    )
    subprocess.check_call(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app_bundle)]
    )


def archive_macos_bundle(app_bundle: Path, zip_path: Path) -> None:
    """Create and round-trip verify a macOS archive while preserving symlinks."""
    subprocess.check_call(
        [
            "ditto",
            "-c",
            "-k",
            "--sequesterRsrc",
            "--keepParent",
            str(app_bundle),
            str(zip_path),
        ]
    )
    with tempfile.TemporaryDirectory(prefix="cds-package-verify-") as temporary:
        subprocess.check_call(["ditto", "-x", "-k", str(zip_path), temporary])
        extracted = Path(temporary) / app_bundle.name
        subprocess.check_call(
            [
                "codesign",
                "--verify",
                "--deep",
                "--strict",
                "--verbose=2",
                str(extracted),
            ]
        )


def strip_optional_network_plugins(bundle: Path) -> None:
    """Remove optional Qt networkinformation plugins (not required for Widgets UI)."""
    victims = []
    for path in bundle.rglob("*"):
        name = path.name.lower()
        rel = str(path).lower()
        if "networkinformation" in rel or name.startswith("libqapplenetworkinformation"):
            victims.append(path)
    for path in sorted(victims, key=lambda p: len(p.parts), reverse=True):
        if path.is_file() or path.is_symlink():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            shutil.rmtree(path, ignore_errors=True)


def inspect_bundle_for_forbidden_network(bundle: Path) -> list[str]:
    """Fail closed if cloud/HTTP SDKs or optional network plugins remain."""
    hits: list[str] = []
    patterns = (
        "plugins/networkinformation",
        "libqapplenetworkinformation",
        "QtWebEngine",
        "QtWebSockets",
        "QtHttpServer",
        "urllib3",
        "requests",
        "httpx",
        "aiohttp",
        "boto3",
        "botocore",
    )
    for path in bundle.rglob("*"):
        rel = str(path.relative_to(bundle)).replace("\\", "/")
        lowered = rel.lower()
        for pattern in patterns:
            if pattern.lower() in lowered:
                hits.append(rel)
                break
    return sorted(set(hits))


def sign_macos(app_bundle: Path) -> dict[str, str]:
    identity = os.environ.get("MACOS_CODESIGN_IDENTITY", "").strip()
    if not identity:
        raise SystemExit(
            "FAIL CLOSED: MACOS_CODESIGN_IDENTITY is required for release builds"
        )
    subprocess.check_call(
        [
            "codesign",
            "--force",
            "--options",
            "runtime",
            "--timestamp",
            "--deep",
            "--sign",
            identity,
            str(app_bundle),
        ]
    )
    subprocess.check_call(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=2", str(app_bundle)]
    )
    # Notarization + staple (fail closed).
    profile = os.environ.get("MACOS_NOTARY_PROFILE", "").strip()
    if not profile:
        raise SystemExit(
            "FAIL CLOSED: MACOS_NOTARY_PROFILE is required for release builds"
        )
    zip_for_notary = app_bundle.with_suffix(".notarize.zip")
    if zip_for_notary.exists():
        zip_for_notary.unlink()
    shutil.make_archive(
        str(zip_for_notary.with_suffix("")),
        "zip",
        root_dir=app_bundle.parent,
        base_dir=app_bundle.name,
    )
    subprocess.check_call(
        [
            "xcrun",
            "notarytool",
            "submit",
            str(zip_for_notary),
            "--keychain-profile",
            profile,
            "--wait",
        ]
    )
    subprocess.check_call(["xcrun", "stapler", "staple", str(app_bundle)])
    subprocess.check_call(["xcrun", "stapler", "validate", str(app_bundle)])
    zip_for_notary.unlink(missing_ok=True)
    return {
        "signature_status": "verified",
        "notarization_status": "verified",
    }


def sign_windows(exe_or_dir: Path) -> dict[str, str]:
    cert = os.environ.get("WINDOWS_CERT_PATH", "").strip()
    password = os.environ.get("WINDOWS_CERT_PASSWORD", "").strip()
    if not cert:
        raise SystemExit(
            "FAIL CLOSED: WINDOWS_CERT_PATH is required for release builds"
        )
    targets = []
    if exe_or_dir.is_file():
        targets = [exe_or_dir]
    else:
        targets = list(exe_or_dir.rglob("*.exe"))
    if not targets:
        raise SystemExit("FAIL CLOSED: no Windows executable found to sign")
    for target in targets:
        cmd = [
            "signtool",
            "sign",
            "/fd",
            "SHA256",
            "/tr",
            "http://timestamp.digicert.com",
            "/td",
            "SHA256",
            "/f",
            cert,
        ]
        if password:
            cmd.extend(["/p", password])
        cmd.append(str(target))
        subprocess.check_call(cmd)
        subprocess.check_call(["signtool", "verify", "/pa", str(target)])
    return {
        "signature_status": "verified",
        "notarization_status": "n/a",
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--os", dest="os_name")
    parser.add_argument("--arch")
    unsigned_group = parser.add_mutually_exclusive_group()
    unsigned_group.add_argument(
        "--unsigned",
        action="store_true",
        help="CI/smoke only. Release builds must omit this flag.",
    )
    unsigned_group.add_argument(
        "--unsigned-evaluation",
        action="store_true",
        help="Build a public evaluation artifact explicitly marked unsigned.",
    )
    args = parser.parse_args()

    is_unsigned = args.unsigned or args.unsigned_evaluation

    host_os, host_arch = detect_target()
    os_name = args.os_name or host_os
    arch = args.arch or host_arch
    if (os_name, arch) != (host_os, host_arch):
        raise SystemExit(
            f"Refusing cross-compile: host={host_os}/{host_arch} requested={os_name}/{arch}"
        )
    require_cpython_312(unsigned=is_unsigned)

    DIST.mkdir(parents=True, exist_ok=True)
    WORK.mkdir(parents=True, exist_ok=True)
    locales = ROOT / "locales"
    version_file = WORK / "version.json"
    write_version_info(version_file)

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--windowed",
        "--name",
        APP_NAME,
        "--paths",
        str(ROOT / "src"),
        "--add-data",
        f"{locales}{';' if os_name == 'windows' else ':'}locales",
        "--add-data",
        f"{version_file}{';' if os_name == 'windows' else ':'}.",
        "--distpath",
        str(WORK / "dist"),
        "--workpath",
        str(WORK / "build"),
        "--specpath",
        str(WORK),
        "--osx-bundle-identifier=com.motoc.clouddatasanitizer",
    ]
    for module in EXCLUDED_MODULES:
        cmd.extend(["--exclude-module", module])
    cmd.append(str(ROOT / "src" / "cloud_data_sanitizer" / "desktop.py"))
    subprocess.check_call(cmd, cwd=ROOT)

    bundle = WORK / "dist" / APP_NAME
    if os_name == "macos":
        bundle = WORK / "dist" / f"{APP_NAME}.app"
        info = bundle / "Contents" / "Info.plist"
        if info.is_file():
            embed_macos_version(info)

    strip_optional_network_plugins(bundle)
    network_hits = inspect_bundle_for_forbidden_network(bundle)
    if network_hits:
        raise SystemExit(
            "FAIL CLOSED: packaged forbidden network components remain:\n"
            + "\n".join(network_hits[:50])
        )

    trust: dict[str, str]
    if is_unsigned:
        if os_name == "macos":
            seal_unsigned_macos_bundle(bundle)
        trust = {
            "signature_status": (
                "unsigned_evaluation"
                if args.unsigned_evaluation
                else "unsigned_smoke"
            ),
            "notarization_status": "not_attempted"
            if os_name == "macos"
            else "n/a",
        }
    elif os_name == "macos":
        trust = sign_macos(bundle)
    else:
        trust = sign_windows(bundle)

    zip_path = DIST / artifact_name(os_name, arch)
    if zip_path.exists():
        zip_path.unlink()
    if os_name == "macos":
        archive_macos_bundle(bundle, zip_path)
    elif bundle.is_dir():
        archive_base = DIST / zip_path.stem
        shutil.make_archive(
            str(archive_base), "zip", root_dir=bundle.parent, base_dir=bundle.name
        )
    else:
        shutil.copy2(bundle, DIST / bundle.name)
        shutil.make_archive(
            str(DIST / zip_path.stem),
            "zip",
            root_dir=DIST,
            base_dir=bundle.name,
        )
        (DIST / bundle.name).unlink(missing_ok=True)

    digest = sha256_file(zip_path)
    (DIST / f"{zip_path.name}.sha256").write_text(
        f"{digest}  {zip_path.name}\n", encoding="utf-8"
    )
    meta_path = DIST / f"{zip_path.stem}.trust.json"
    meta_path.write_text(
        json.dumps(
            {
                "filename": zip_path.name,
                "os": os_name,
                "architecture": arch,
                "version": PRODUCT_VERSION,
                "sha256": digest,
                **trust,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    if not is_unsigned and trust["signature_status"] != "verified":
        raise SystemExit("FAIL CLOSED: signature_status is not verified")
    print(
        f"Built {zip_path.name} "
        f"(signature={trust['signature_status']}, "
        f"notarization={trust['notarization_status']}) sha256={digest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
