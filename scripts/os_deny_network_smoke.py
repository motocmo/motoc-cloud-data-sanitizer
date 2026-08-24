#!/usr/bin/env python3
"""OS-level / interpreter outbound-deny smoke for local sanitization (CDS-V-005)."""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

MAC_SANDBOX = """
(version 1)
(deny default)
(allow process*)
(allow sysctl-read)
(allow file-read*)
(allow file-write* (subpath "/private/tmp") (subpath "/tmp") (subpath "/var") (subpath "{work}"))
(deny network*)
"""


def run_with_socket_denial(input_path: Path, output_path: Path) -> subprocess.CompletedProcess[str]:
    code = f"""
import socket
import sys
sys.path.insert(0, {str(ROOT / 'src')!r})

def _deny(*_a, **_k):
    raise OSError('network denied')

socket.socket = _deny  # type: ignore[assignment]
socket.create_connection = _deny  # type: ignore[assignment]
socket.getaddrinfo = _deny  # type: ignore[assignment]

from cloud_data_sanitizer.cli import main
raise SystemExit(main([
    'sanitize',
    {str(input_path)!r},
    {str(output_path)!r},
    '--keep-potential',
    '--allow-remove',
    '--key-hex',
    {'44' * 32!r},
]))
"""
    return subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args()
    if not args.input.is_file():
        raise SystemExit(f"input missing: {args.input}")

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        output = work / "sanitized.csv"
        result: subprocess.CompletedProcess[str] | None = None

        if platform.system() == "Darwin":
            profile = work / "deny-network.sb"
            profile.write_text(MAC_SANDBOX.format(work=work), encoding="utf-8")
            cmd = [
                "sandbox-exec",
                "-f",
                str(profile),
                sys.executable,
                "-m",
                "cloud_data_sanitizer",
                "sanitize",
                str(args.input),
                str(output),
                "--keep-potential",
                "--allow-remove",
                "--key-hex",
                "44" * 32,
            ]
            result = subprocess.run(
                cmd,
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
                env={**os.environ, "PYTHONPATH": str(ROOT / "src")},
            )
            if result.returncode != 0:
                print("sandbox-exec unavailable/failed; using interpreter socket denial")
                result = run_with_socket_denial(args.input, output)
        else:
            result = run_with_socket_denial(args.input, output)

        assert result is not None
        if result.returncode != 0:
            print(result.stdout)
            print(result.stderr, file=sys.stderr)
            raise SystemExit(result.returncode)
        if not output.is_file():
            raise SystemExit("FAIL: sanitized output missing under network denial")
        print("PASS: sanitization completed under network-denial smoke")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
