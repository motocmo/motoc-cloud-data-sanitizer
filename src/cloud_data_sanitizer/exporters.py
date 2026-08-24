from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path
from typing import Any

from openpyxl import Workbook
from openpyxl.cell import WriteOnlyCell

from cloud_data_sanitizer.models import Dataset, SanitizerError


def _destination(path: str | Path, extensions: set[str]) -> Path:
    destination = Path(path).expanduser().resolve()
    if destination.suffix.lower() not in extensions:
        expected = " or ".join(sorted(extensions))
        raise SanitizerError(
            "output_extension",
            f"Output file must use {expected}.",
        )
    if not destination.parent.is_dir():
        raise SanitizerError(
            "output_dir_missing",
            "Output directory does not exist.",
        )
    return destination


def _temporary_path(destination: Path) -> Path:
    descriptor, name = tempfile.mkstemp(
        prefix=f".{destination.stem}-",
        suffix=destination.suffix,
        dir=destination.parent,
    )
    os.close(descriptor)
    return Path(name)


def write_dataset(dataset: Dataset, path: str | Path) -> Path:
    destination = _destination(path, {".csv", ".xlsx"})
    temporary = _temporary_path(destination)
    try:
        if destination.suffix.lower() == ".csv":
            with temporary.open("w", encoding="utf-8-sig", newline="") as handle:
                writer = csv.DictWriter(
                    handle, fieldnames=dataset.headers, delimiter=dataset.delimiter
                )
                writer.writeheader()
                writer.writerows(dataset.rows)
        else:
            workbook = Workbook(write_only=True)
            worksheet = workbook.create_sheet(dataset.sheet_name or "SanitizedData")
            worksheet.append(
                [_excel_value(worksheet, value) for value in dataset.headers]
            )
            for row in dataset.rows:
                worksheet.append(
                    [
                        _excel_value(worksheet, row.get(header))
                        for header in dataset.headers
                    ]
                )
            workbook.save(temporary)
            workbook.close()
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def _excel_value(worksheet: Any, value: Any) -> Any:
    if not isinstance(value, str):
        return value
    cell = WriteOnlyCell(worksheet, value=value)
    cell.data_type = "s"
    return cell


def write_json(payload: dict[str, Any], path: str | Path) -> Path:
    destination = _destination(path, {".json"})
    temporary = _temporary_path(destination)
    try:
        temporary.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return destination
