from __future__ import annotations

import hashlib
from pathlib import Path

from cloud_data_sanitizer.models import SanitizerError


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    source = Path(path)
    with source.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_sha256_sidecar(path: str | Path) -> tuple[str, Path]:
    source = Path(path).expanduser().resolve()
    if not source.is_file():
        raise SanitizerError("checksum_missing", "Cannot checksum a missing file.")
    digest = sha256_file(source)
    sidecar = source.with_suffix(source.suffix + ".sha256")
    # lowercase digest, two spaces, exact filename (ADR contract)
    sidecar.write_text(f"{digest}  {source.name}\n", encoding="utf-8")
    return digest, sidecar


def verify_sha256_sidecar(path: str | Path, sidecar: str | Path | None = None) -> bool:
    source = Path(path).expanduser().resolve()
    checksum_path = (
        Path(sidecar).expanduser().resolve()
        if sidecar
        else source.with_suffix(source.suffix + ".sha256")
    )
    if not checksum_path.is_file():
        return False
    line = checksum_path.read_text(encoding="utf-8").strip()
    parts = line.split("  ", 1)
    if len(parts) != 2:
        return False
    expected, filename = parts
    if filename != source.name:
        return False
    if len(expected) != 64 or expected != expected.lower():
        return False
    return sha256_file(source) == expected
