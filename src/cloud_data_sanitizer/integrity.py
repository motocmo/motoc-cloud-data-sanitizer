from __future__ import annotations

import re
from collections import defaultdict
from datetime import date, datetime
from decimal import Decimal, InvalidOperation
from typing import Any

from cloud_data_sanitizer.detection import detect_field
from cloud_data_sanitizer.models import Dataset, IntegritySnapshot, ValidationCheck


def _decimal(value: Any) -> Decimal | None:
    if value is None or str(value).strip() == "":
        return None
    cleaned = re.sub(r"[^0-9.()\-+]", "", str(value).strip())
    if cleaned.startswith("(") and cleaned.endswith(")"):
        cleaned = f"-{cleaned[1:-1]}"
    try:
        return Decimal(cleaned)
    except InvalidOperation:
        return None


def _date_text(value: Any) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    if isinstance(value, datetime):
        return value.date().isoformat()
    if isinstance(value, date):
        return value.isoformat()
    text = str(value).strip()
    for candidate in (text, text[:10], f"{text[:7]}-01"):
        try:
            return date.fromisoformat(candidate).isoformat()
        except ValueError:
            continue
    return text


def snapshot(dataset: Dataset) -> IntegritySnapshot:
    fields = {header: detect_field(header) for header in dataset.headers}
    cost_totals: defaultdict[str, Decimal] = defaultdict(Decimal)
    currencies: set[str] = set()
    dates: defaultdict[str, list[str]] = defaultdict(list)
    services: defaultdict[str, set[str]] = defaultdict(set)
    for row in dataset.rows:
        for header, field in fields.items():
            value = row.get(header)
            if field == "cost":
                numeric = _decimal(value)
                if numeric is not None:
                    cost_totals[header] += numeric
            elif field == "currency" and value is not None and str(value).strip():
                currencies.add(str(value).strip().upper())
            elif field == "usage_date":
                normalized = _date_text(value)
                if normalized:
                    dates[header].append(normalized)
            elif field == "service" and value is not None and str(value).strip():
                services[header].add(str(value).strip())
    return IntegritySnapshot(
        row_count=len(dataset.rows),
        cost_totals={key: str(value) for key, value in sorted(cost_totals.items())},
        currencies=tuple(sorted(currencies)),
        date_ranges={
            key: (min(values), max(values))
            for key, values in sorted(dates.items())
            if values
        },
        service_counts={key: len(values) for key, values in sorted(services.items())},
    )


def validate(before: Dataset, after: Dataset) -> list[ValidationCheck]:
    # Compare only retained analysis fields that still exist in the output.
    retained_headers = set(after.headers)
    filtered_before = Dataset(
        source=before.source,
        file_type=before.file_type,
        headers=[h for h in before.headers if h in retained_headers],
        rows=[
            {h: row.get(h) for h in before.headers if h in retained_headers}
            for row in before.rows
        ],
        sheet_name=before.sheet_name,
        delimiter=before.delimiter,
    )
    original = snapshot(filtered_before)
    sanitized = snapshot(after)
    return [
        ValidationCheck(
            "row_count",
            original.row_count == sanitized.row_count,
            original.row_count,
            sanitized.row_count,
        ),
        ValidationCheck(
            "cost_totals",
            original.cost_totals == sanitized.cost_totals,
            original.cost_totals,
            sanitized.cost_totals,
        ),
        ValidationCheck(
            "currencies",
            original.currencies == sanitized.currencies,
            original.currencies,
            sanitized.currencies,
        ),
        ValidationCheck(
            "date_ranges",
            original.date_ranges == sanitized.date_ranges,
            original.date_ranges,
            sanitized.date_ranges,
        ),
        ValidationCheck(
            "service_counts",
            original.service_counts == sanitized.service_counts,
            original.service_counts,
            sanitized.service_counts,
        ),
    ]
