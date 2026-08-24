from __future__ import annotations

import ast
import zipfile
from pathlib import Path

import pytest

from scripts.inspect_package_network import inspect_zip

ROOT = Path(__file__).resolve().parents[1]


def test_assemble_release_accepts_prerelease_tag_shape() -> None:
    import re

    from scripts import assemble_release as mod

    assert mod.TAG_RE.match("v0.1.0")
    assert mod.TAG_RE.match("v0.1.0-rc.1")
    assert not mod.TAG_RE.match("0.1.0-rc.1")
    assert re.fullmatch(mod.TAG_RE, "v0.1.0-rc.1")


def test_assemble_release_fails_closed_without_verified_trust(tmp_path: Path) -> None:
    import subprocess
    import sys

    input_dir = tmp_path / "in"
    output_dir = tmp_path / "out"
    input_dir.mkdir()
    for name in (
        "CloudDataSanitizer-macos-arm64.zip",
        "CloudDataSanitizer-macos-x64.zip",
        "CloudDataSanitizer-windows-x64.zip",
    ):
        (input_dir / name).write_bytes(b"placeholder")
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "assemble_release.py"),
            "--version",
            "0.1.0-rc.1",
            "--tag",
            "v0.1.0-rc.1",
            "--commit",
            "a" * 40,
            "--input-dir",
            str(input_dir),
            "--output-dir",
            str(output_dir),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode != 0
    assert "FAIL CLOSED" in proc.stderr + proc.stdout


def test_build_script_fails_closed_without_signing_env(monkeypatch: pytest.MonkeyPatch) -> None:
    import importlib

    monkeypatch.delenv("MACOS_CODESIGN_IDENTITY", raising=False)
    monkeypatch.delenv("MACOS_NOTARY_PROFILE", raising=False)
    build = importlib.import_module("scripts.build_pyinstaller")
    with pytest.raises(SystemExit, match="FAIL CLOSED"):
        build.sign_macos(Path("/tmp/CloudDataSanitizer.app"))


def test_source_never_imports_qtnetwork_or_http_clients() -> None:
    forbidden = {"requests", "httpx", "urllib3", "aiohttp", "boto3", "botocore"}
    hits: list[str] = []
    for path in (ROOT / "src" / "cloud_data_sanitizer").rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                root_name = name.split(".", 1)[0]
                if "QtNetwork" in name or root_name in forbidden:
                    hits.append(f"{path.name}:{name}")
    assert not hits


def test_packaged_zip_network_inspection_when_present() -> None:
    dist = ROOT / "packaging" / "dist"
    zips = sorted(dist.glob("CloudDataSanitizer-*.zip"))
    if not zips:
        pytest.skip("No local package available for CDS-V-005 inspection")
    for package in zips:
        forbidden, _reviewed = inspect_zip(package)
        assert not forbidden, (
            f"{package.name} still contains forbidden network components: {forbidden[:10]}"
        )


def test_inspect_zip_detects_forbidden_and_allows_reviewed_qtnetwork(tmp_path: Path) -> None:
    package = tmp_path / "sample.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("App/Frameworks/QtNetwork.framework/QtNetwork", b"x")
        archive.writestr("App/site-packages/requests/api.py", b"x")
    forbidden, reviewed = inspect_zip(package)
    assert any("requests" in item for item in forbidden)
    assert any("QtNetwork" in item for item in reviewed)
