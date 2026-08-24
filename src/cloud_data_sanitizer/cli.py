from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from cloud_data_sanitizer.checksum import verify_sha256_sidecar
from cloud_data_sanitizer.models import SanitizerError
from cloud_data_sanitizer.service import inspect_dataset, sanitize_dataset


def _rule(value: str) -> tuple[str, str]:
    if "=" not in value:
        raise argparse.ArgumentTypeError("Rules must use COLUMN=ACTION.")
    column, action = value.split("=", 1)
    if not column.strip() or not action.strip():
        raise argparse.ArgumentTypeError("Rules must use COLUMN=ACTION.")
    return column.strip(), action.strip().lower()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloud-sanitize",
        description=(
            "Locally inspect and sanitize cloud billing datasets. "
            "No network access. No cloud credentials."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)

    inspect = commands.add_parser(
        "inspect", help="Classify columns without changing the file."
    )
    inspect.add_argument("input", type=Path)
    inspect.add_argument("--sheet")
    inspect.add_argument("--json", action="store_true", dest="as_json")

    sanitize = commands.add_parser(
        "sanitize",
        help="Create a sanitized copy, audit report, and SHA-256 sidecar.",
    )
    sanitize.add_argument("input", type=Path)
    sanitize.add_argument("output", type=Path)
    sanitize.add_argument("--sheet")
    sanitize.add_argument("--rule", action="append", type=_rule, default=[])
    sanitize.add_argument("--keep-potential", action="store_true")
    sanitize.add_argument("--allow-remove", action="store_true")
    sanitize.add_argument("--report", type=Path)
    sanitize.add_argument("--provider", default="generic")
    sanitize.add_argument(
        "--key-hex",
        help="Optional 256-bit customer key as hex (preferred: OS key store / UI).",
    )

    verify = commands.add_parser(
        "verify", help="Verify a sanitized output against its .sha256 sidecar."
    )
    verify.add_argument("output", type=Path)
    verify.add_argument("--checksum", type=Path)
    return parser


def _print_inspection(payload: dict[str, object]) -> None:
    print(f"Input: {payload['input']}")
    print("Processing: LOCAL ONLY")
    warning = payload.get("warning")
    if warning:
        print(f"\n{warning}")
    print("\nWorksheets:")
    for sheet in payload["sheets"]:  # type: ignore[union-attr]
        marker = "Y" if sheet["suitable"] else "o"
        print(
            f"  {marker} {sheet['name']}: {sheet['row_count']} rows, "
            f"{sheet['column_count']} columns"
        )
    columns = payload["columns"]
    if columns:
        print("\nColumns:")
        for column in columns:  # type: ignore[union-attr]
            print(
                f"  {column['column']}: {column['classification']} "
                f"-> {column['recommended_action']}"
            )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "inspect":
            payload = inspect_dataset(args.input, args.sheet)
            if args.as_json:
                print(json.dumps(payload, indent=2, ensure_ascii=False))
            else:
                _print_inspection(payload)
            return 0
        if args.command == "verify":
            ok = verify_sha256_sidecar(args.output, args.checksum)
            print("PASS" if ok else "FAIL")
            return 0 if ok else 1
        key = bytes.fromhex(args.key_hex) if args.key_hex else None
        result = sanitize_dataset(
            args.input,
            args.output,
            sheet_name=args.sheet,
            rules=dict(args.rule),
            keep_potential=args.keep_potential,
            allow_remove=args.allow_remove,
            report_path=args.report,
            customer_key=key,
            provider=args.provider,
        )
        print(json.dumps(asdict(result), indent=2, ensure_ascii=False, default=str))
        return 0
    except SanitizerError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
