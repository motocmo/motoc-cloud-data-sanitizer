from __future__ import annotations

import secrets

import pytest

from cloud_data_sanitizer.models import Dataset, MaskingAction, SanitizerError
from cloud_data_sanitizer.pseudonym import (
    OUTPUT_BITS,
    apply_pseudonymization,
    encode_length_prefixed,
    stable_pseudonym,
)

KNOWN_KEY = bytes.fromhex("11" * 32)
KNOWN_VALUE = "vm-prod-01"


def dataset() -> Dataset:
    return Dataset(
        source=None,  # type: ignore[arg-type]
        file_type="csv",
        headers=["ResourceId", "Owner", "AccountId", "Cost", "AccessKey"],
        rows=[
            {
                "ResourceId": "vm-prod",
                "Owner": "a@example.com",
                "AccountId": "123",
                "Cost": "10",
                "AccessKey": "AKIA",
            },
            {
                "ResourceId": "vm-prod",
                "Owner": "b@example.com",
                "AccountId": "123",
                "Cost": "20",
                "AccessKey": "AKIA",
            },
        ],
    )


def test_known_answer_vector_is_stable() -> None:
    first = stable_pseudonym(
        KNOWN_KEY,
        provider="azure",
        correlation_domain="resource_id",
        original_value=KNOWN_VALUE,
        label="resource-id",
    )
    second = stable_pseudonym(
        KNOWN_KEY,
        provider="azure",
        correlation_domain="resource_id",
        original_value=KNOWN_VALUE,
        label="resource-id",
    )
    assert first == second
    assert first == "resource-id-icveoabcsk6dg4vcpyiih7j3da"
    assert first.startswith("resource-id-")
    token = first.split("-", 2)[-1]
    # Base32 without padding for 128 bits => 26 chars
    assert len(token) == 26
    assert OUTPUT_BITS >= 128


def test_domain_and_key_unlinkability() -> None:
    base = {
        "original_value": KNOWN_VALUE,
        "label": "resource-id",
    }
    a = stable_pseudonym(
        KNOWN_KEY, provider="azure", correlation_domain="resource_id", **base
    )
    b = stable_pseudonym(
        KNOWN_KEY, provider="aws", correlation_domain="resource_id", **base
    )
    c = stable_pseudonym(
        KNOWN_KEY, provider="azure", correlation_domain="account_id", **base
    )
    other_key = secrets.token_bytes(32)
    d = stable_pseudonym(
        other_key, provider="azure", correlation_domain="resource_id", **base
    )
    assert len({a, b, c, d}) == 4


def test_length_prefix_avoids_ambiguity() -> None:
    left = encode_length_prefixed("ab", "cd")
    right = encode_length_prefixed("a", "bcd")
    assert left != right


def test_pseudonymize_is_stable_across_rows_and_remove_drops_column() -> None:
    actions = {
        "ResourceId": MaskingAction.PSEUDONYMIZE,
        "AccessKey": MaskingAction.REMOVE,
        "Cost": MaskingAction.KEEP,
    }
    fields = {
        "ResourceId": "resource_id",
        "AccessKey": None,
        "Cost": "cost",
    }
    first, counts, dropped = apply_pseudonymization(
        dataset(), actions, fields, customer_key=KNOWN_KEY, provider="azure"
    )
    second, _, _ = apply_pseudonymization(
        dataset(), actions, fields, customer_key=KNOWN_KEY, provider="azure"
    )
    assert first.rows[0]["ResourceId"] == first.rows[1]["ResourceId"]
    assert first.rows == second.rows
    assert "AccessKey" not in first.headers
    assert dropped == ["AccessKey"]
    assert counts["ResourceId"] == 2
    assert first.rows[0]["Cost"] == "10"


def test_short_key_rejected() -> None:
    with pytest.raises(SanitizerError, match="256 bits"):
        stable_pseudonym(
            b"short",
            provider="azure",
            correlation_domain="resource_id",
            original_value="x",
            label="resource-id",
        )
