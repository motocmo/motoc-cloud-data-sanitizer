from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any


class Classification(StrEnum):
    SENSITIVE = "sensitive"
    POTENTIALLY_SENSITIVE = "potentially_sensitive"
    ANALYSIS_REQUIRED = "analysis_required"
    RESTRICTED = "restricted"
    UNKNOWN = "unknown"


class MaskingAction(StrEnum):
    PSEUDONYMIZE = "pseudonymize"
    REMOVE = "remove"
    KEEP = "keep"

    # Compatibility aliases accepted by CLI / UI rule parsing.
    REPLACE = "replace"
    HASH = "hash"


def normalize_action(raw: str | MaskingAction) -> MaskingAction:
    action = MaskingAction(str(raw).lower())
    if action in {MaskingAction.REPLACE, MaskingAction.HASH}:
        return MaskingAction.PSEUDONYMIZE
    return action


@dataclass(frozen=True, slots=True)
class ColumnFinding:
    column: str
    normalized_field: str | None
    classification: Classification
    recommended_action: MaskingAction
    reasons: tuple[str, ...]
    nonempty_count: int
    unique_count: int


@dataclass(slots=True)
class Dataset:
    source: Path
    file_type: str
    headers: list[str]
    rows: list[dict[str, Any]]
    sheet_name: str | None = None
    delimiter: str = ","


@dataclass(frozen=True, slots=True)
class SheetInfo:
    name: str
    row_count: int
    column_count: int
    detected_fields: tuple[str, ...]
    suitable: bool


@dataclass(frozen=True, slots=True)
class IntegritySnapshot:
    row_count: int
    cost_totals: dict[str, str]
    currencies: tuple[str, ...]
    date_ranges: dict[str, tuple[str | None, str | None]]
    service_counts: dict[str, int]


@dataclass(frozen=True, slots=True)
class ValidationCheck:
    name: str
    passed: bool
    before: Any
    after: Any


@dataclass(slots=True)
class SanitizationResult:
    output_path: Path
    report_path: Path
    sha256_path: Path
    sha256: str
    mapping_path: Path | None
    processed_records: int
    masked_counts: dict[str, int]
    actions: dict[str, MaskingAction]
    validation: list[ValidationCheck]
    warnings: list[str] = field(default_factory=list)
    dropped_columns: list[str] = field(default_factory=list)


class SanitizerError(ValueError):
    """Safe, actionable error for invalid or unsafe sanitizer operations."""

    def __init__(self, code: str, message: str, **params: Any) -> None:
        self.code = code
        self.params = params
        super().__init__(message)
