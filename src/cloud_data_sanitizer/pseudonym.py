from __future__ import annotations

import base64
import hashlib
import hmac
from collections.abc import Mapping
from typing import Any

from cloud_data_sanitizer.models import Dataset, MaskingAction, SanitizerError, normalize_action
from cloud_data_sanitizer.version import POLICY_VERSION

# Human-readable labels prepended to Base32 HMAC digests.
LABELS = {
    "subscription_id": "subscription",
    "tenant_id": "tenant",
    "account_id": "account",
    "project_id": "project",
    "resource_id": "resource-id",
    "resource_name": "resource",
    "host_name": "host",
    "ip_address": "ip",
    "owner": "owner",
    "application_name": "application",
    "tags": "tags",
}

# Retain at least 128 bits of the HMAC digest in the token.
OUTPUT_BITS = 128
OUTPUT_BYTES = OUTPUT_BITS // 8


def encode_length_prefixed(*parts: str) -> bytes:
    """Encode parts with unambiguous length-prefixed domain separation."""
    payload = bytearray()
    for part in parts:
        encoded = part.encode("utf-8")
        if len(encoded) > 0xFFFF:
            raise SanitizerError(
                "value_too_long",
                "A value exceeds the maximum length for stable pseudonymization.",
            )
        payload.extend(len(encoded).to_bytes(2, "big"))
        payload.extend(encoded)
    return bytes(payload)


def stable_pseudonym(
    customer_key: bytes,
    *,
    provider: str,
    correlation_domain: str,
    original_value: str,
    label: str,
    policy_version: str = POLICY_VERSION,
) -> str:
    """
    Stable Pseudonymization (稳定假名化):

        label + Base32(HMAC-SHA-256(customer_key, encode(...))[:16])
    """
    if len(customer_key) < 32:
        raise SanitizerError(
            "key_too_short",
            "Customer key must provide at least 256 bits of entropy.",
        )
    message = encode_length_prefixed(
        policy_version, provider, correlation_domain, original_value
    )
    digest = hmac.new(customer_key, message, hashlib.sha256).digest()[:OUTPUT_BYTES]
    token = base64.b32encode(digest).decode("ascii").rstrip("=").lower()
    return f"{label}-{token}"


def apply_pseudonymization(
    dataset: Dataset,
    actions: Mapping[str, MaskingAction],
    normalized_fields: Mapping[str, str | None],
    *,
    customer_key: bytes,
    provider: str = "generic",
) -> tuple[Dataset, dict[str, int], list[str]]:
    """Apply keep / remove (drop column) / stable pseudonymize decisions."""
    resolved = {column: normalize_action(action) for column, action in actions.items()}
    unknown = set(resolved) - set(dataset.headers)
    if unknown:
        raise SanitizerError(
            "unknown_columns",
            f"Rules reference unknown columns: {', '.join(sorted(unknown))}",
        )

    drop_columns = {
        column
        for column, action in resolved.items()
        if action is MaskingAction.REMOVE
    }
    output_headers = [header for header in dataset.headers if header not in drop_columns]
    masked_counts = {
        column: 0
        for column, action in resolved.items()
        if action is not MaskingAction.KEEP
    }
    collision_index: dict[tuple[str, str], str] = {}
    output_rows: list[dict[str, Any]] = []

    for row in dataset.rows:
        output: dict[str, Any] = {}
        for column in output_headers:
            value = row.get(column)
            action = resolved.get(column, MaskingAction.KEEP)
            if (
                action is MaskingAction.KEEP
                or value is None
                or str(value).strip() == ""
            ):
                output[column] = value
                continue
            if action is MaskingAction.PSEUDONYMIZE:
                original = str(value)
                field = normalized_fields.get(column) or "value"
                label = LABELS.get(field, "value")
                token = stable_pseudonym(
                    customer_key,
                    provider=provider,
                    correlation_domain=field,
                    original_value=original,
                    label=label,
                )
                prior = collision_index.get((field, token))
                if prior is not None and prior != original:
                    raise SanitizerError(
                        "pseudonym_collision",
                        "Stable pseudonym collision detected; export stopped.",
                    )
                collision_index[(field, token)] = original
                output[column] = token
                masked_counts[column] = masked_counts.get(column, 0) + 1
            else:
                output[column] = value
        output_rows.append(output)

    return (
        Dataset(
            source=dataset.source,
            file_type=dataset.file_type,
            headers=output_headers,
            rows=output_rows,
            sheet_name=dataset.sheet_name,
            delimiter=dataset.delimiter,
        ),
        masked_counts,
        sorted(drop_columns),
    )
