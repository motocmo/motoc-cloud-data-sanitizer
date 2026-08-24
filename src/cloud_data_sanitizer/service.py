from __future__ import annotations

from dataclasses import asdict
from pathlib import Path
from typing import Any

from cloud_data_sanitizer.checksum import write_sha256_sidecar
from cloud_data_sanitizer.detection import classify_columns
from cloud_data_sanitizer.exporters import write_dataset, write_json
from cloud_data_sanitizer.integrity import validate
from cloud_data_sanitizer.keystore import KeyStore, MemoryKeyStore
from cloud_data_sanitizer.models import (
    Classification,
    MaskingAction,
    SanitizationResult,
    SanitizerError,
    normalize_action,
)
from cloud_data_sanitizer.pseudonym import apply_pseudonymization
from cloud_data_sanitizer.readers import inspect_sheets, read_dataset
from cloud_data_sanitizer.version import __version__


def inspect_dataset(path: str | Path, sheet_name: str | None = None) -> dict[str, Any]:
    sheets = inspect_sheets(path)
    columns: list[dict[str, Any]] = []
    warning: str | None = None
    try:
        dataset = read_dataset(path, sheet_name)
        columns = [
            asdict(item) for item in classify_columns(dataset.headers, dataset.rows)
        ]
    except SanitizerError as exc:
        if exc.code != "sheet_required":
            raise
        warning = str(exc)
    return {
        "input": Path(path).name,
        "processing": "local_only",
        "sheets": [asdict(sheet) for sheet in sheets],
        "selected_sheet": sheet_name,
        "columns": columns,
        "warning": warning,
    }


def _resolve_actions(
    findings: list[Any],
    rules: dict[str, str] | None,
    keep_potential: bool,
    allow_remove: bool,
) -> tuple[dict[str, MaskingAction], dict[str, str | None], list[str]]:
    explicit: dict[str, MaskingAction] = {}
    for column, raw_action in (rules or {}).items():
        try:
            explicit[column] = normalize_action(raw_action)
        except ValueError as exc:
            raise SanitizerError(
                "invalid_action",
                f"Invalid action '{raw_action}' for '{column}'. "
                "Use pseudonymize, remove, or keep.",
            ) from exc
    known_columns = {finding.column for finding in findings}
    unknown = set(explicit) - known_columns
    if unknown:
        raise SanitizerError(
            "unknown_columns",
            f"Rules reference unknown columns: {', '.join(sorted(unknown))}",
        )

    actions: dict[str, MaskingAction] = {}
    fields: dict[str, str | None] = {}
    unresolved: list[str] = []
    warnings: list[str] = []
    for finding in findings:
        fields[finding.column] = finding.normalized_field
        action = explicit.get(finding.column)

        if finding.classification is Classification.RESTRICTED:
            chosen = action or MaskingAction.REMOVE
            if chosen is not MaskingAction.REMOVE:
                raise SanitizerError(
                    "restricted_must_remove",
                    f"Restricted column '{finding.column}' must be physically removed.",
                )
            actions[finding.column] = MaskingAction.REMOVE
            continue

        if finding.classification is Classification.ANALYSIS_REQUIRED:
            if action and action is not MaskingAction.KEEP:
                raise SanitizerError(
                    "analysis_required",
                    f"'{finding.column}' is required for analysis and cannot be masked.",
                )
            actions[finding.column] = MaskingAction.KEEP
        elif finding.classification is Classification.SENSITIVE:
            actions[finding.column] = action or finding.recommended_action
            if action is MaskingAction.KEEP:
                warnings.append(
                    f"Sensitive column retained by explicit choice: {finding.column}"
                )
        else:
            if action:
                actions[finding.column] = action
            elif keep_potential:
                actions[finding.column] = MaskingAction.KEEP
            else:
                unresolved.append(finding.column)

    if unresolved:
        raise SanitizerError(
            "decision_required",
            "Potentially sensitive columns require a decision: "
            + ", ".join(unresolved),
        )
    removed = [
        column for column, action in actions.items() if action is MaskingAction.REMOVE
    ]
    if removed and not allow_remove:
        raise SanitizerError(
            "remove_confirmation",
            "Remove rules require explicit confirmation (--allow-remove): "
            + ", ".join(removed),
        )
    return actions, fields, warnings


def sanitize_dataset(
    input_path: str | Path,
    output_path: str | Path,
    *,
    sheet_name: str | None = None,
    rules: dict[str, str] | None = None,
    keep_potential: bool = False,
    allow_remove: bool = False,
    report_path: str | Path | None = None,
    customer_key: bytes | None = None,
    keystore: KeyStore | None = None,
    provider: str = "generic",
    persist_key: bool = False,
) -> SanitizationResult:
    source = Path(input_path).expanduser().resolve()
    output = Path(output_path).expanduser().resolve()
    if source == output:
        raise SanitizerError(
            "overwrite_forbidden",
            "Output must be a new file. The original file is never modified.",
        )

    if customer_key is None:
        store = keystore or MemoryKeyStore()
        if keystore is None and persist_key:
            from cloud_data_sanitizer.keystore import OSKeyStore

            store = OSKeyStore()
        customer_key = store.load_or_generate(persist=persist_key)

    dataset = read_dataset(source, sheet_name)
    findings = classify_columns(dataset.headers, dataset.rows)
    actions, fields, warnings = _resolve_actions(
        findings, rules, keep_potential, allow_remove
    )
    sanitized, masked_counts, dropped = apply_pseudonymization(
        dataset,
        actions,
        fields,
        customer_key=customer_key,
        provider=provider,
    )
    checks = validate(dataset, sanitized)
    failed = [check.name for check in checks if not check.passed]
    if failed:
        raise SanitizerError(
            "integrity_failed",
            "Integrity validation failed; no sanitized dataset was exported: "
            + ", ".join(failed),
        )

    destination = write_dataset(sanitized, output)
    digest, sha_path = write_sha256_sidecar(destination)
    report_destination = (
        Path(report_path).expanduser().resolve()
        if report_path
        else destination.with_suffix(".report.json")
    )
    report = {
        "tool": "Cloud Data Sanitizer",
        "version": __version__,
        "processing": "local_only",
        "pseudonymization": "HMAC-SHA-256 stable pseudonymization",
        "input": source.name,
        "output": destination.name,
        "output_sha256": digest,
        "selected_sheet": dataset.sheet_name,
        "processed_records": len(dataset.rows),
        "dropped_columns": dropped,
        "columns": [
            {
                "column": finding.column,
                "classification": finding.classification.value,
                "normalized_field": finding.normalized_field,
                "action": actions[finding.column].value,
                "masked_records": masked_counts.get(finding.column, 0),
                "reasons": list(finding.reasons),
            }
            for finding in findings
        ],
        "validation": [asdict(check) for check in checks],
        "mapping_generated": False,
        "warnings": warnings,
    }
    write_json(report, report_destination)
    return SanitizationResult(
        output_path=destination,
        report_path=report_destination,
        sha256_path=sha_path,
        sha256=digest,
        mapping_path=None,
        processed_records=len(dataset.rows),
        masked_counts=masked_counts,
        actions=actions,
        validation=checks,
        warnings=warnings,
        dropped_columns=dropped,
    )
