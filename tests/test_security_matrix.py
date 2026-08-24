from __future__ import annotations

import io
import logging
from pathlib import Path

import pytest

from cloud_data_sanitizer.detection import classify_columns
from cloud_data_sanitizer.keystore import MemoryKeyStore, OSKeyStore
from cloud_data_sanitizer.models import Classification, Dataset, MaskingAction, SanitizerError
from cloud_data_sanitizer.pseudonym import apply_pseudonymization, stable_pseudonym
from cloud_data_sanitizer.service import sanitize_dataset

# Published interoperable known-answer vector (CDS-V-006).
KAT_KEY = bytes.fromhex("11" * 32)
KAT_PROVIDER = "azure"
KAT_DOMAIN = "resource_id"
KAT_VALUE = "vm-prod-01"
KAT_LABEL = "resource-id"
KAT_POLICY = "cds-policy-1"
KAT_TOKEN = "resource-id-icveoabcsk6dg4vcpyiih7j3da"


def test_published_hmac_known_answer_vector() -> None:
    token = stable_pseudonym(
        KAT_KEY,
        provider=KAT_PROVIDER,
        correlation_domain=KAT_DOMAIN,
        original_value=KAT_VALUE,
        label=KAT_LABEL,
        policy_version=KAT_POLICY,
    )
    assert token == KAT_TOKEN


def test_forced_pseudonym_collision_stops_export(monkeypatch: pytest.MonkeyPatch) -> None:
    dataset = Dataset(
        source=None,  # type: ignore[arg-type]
        file_type="csv",
        headers=["ResourceId"],
        rows=[{"ResourceId": "alpha"}, {"ResourceId": "beta"}],
    )

    def colliding(_key, **kwargs):  # type: ignore[no-untyped-def]
        return "resource-id-COLLISIONTOKEN00000000"

    monkeypatch.setattr(
        "cloud_data_sanitizer.pseudonym.stable_pseudonym",
        colliding,
    )
    with pytest.raises(SanitizerError, match="collision"):
        apply_pseudonymization(
            dataset,
            {"ResourceId": MaskingAction.PSEUDONYMIZE},
            {"ResourceId": "resource_id"},
            customer_key=KAT_KEY,
            provider="azure",
        )


def test_late_row_credential_is_detected_as_restricted() -> None:
    rows = [{"Notes": "ok"} for _ in range(600)]
    rows.append({"Notes": "password=SuperSecret123"})
    findings = {item.column: item for item in classify_columns(["Notes"], rows)}
    assert findings["Notes"].classification is Classification.RESTRICTED
    assert findings["Notes"].recommended_action is MaskingAction.REMOVE


def test_key_and_raw_value_absent_from_report_and_output(tmp_path: Path) -> None:
    source = tmp_path / "billing.csv"
    source.write_text(
        "Service,Cost,Currency,UsageDate,ResourceId\n"
        "Compute,1.00,USD,2026-07-01,secret-resource-xyz\n",
        encoding="utf-8",
    )
    log_buffer = io.StringIO()
    handler = logging.StreamHandler(log_buffer)
    logging.getLogger().addHandler(handler)
    try:
        result = sanitize_dataset(
            source,
            tmp_path / "out.csv",
            keep_potential=True,
            customer_key=KAT_KEY,
            provider="azure",
        )
    finally:
        logging.getLogger().removeHandler(handler)

    output_text = result.output_path.read_text(encoding="utf-8")
    report_text = result.report_path.read_text(encoding="utf-8")
    logs = log_buffer.getvalue()
    assert "secret-resource-xyz" not in output_text
    assert KAT_KEY.hex() not in output_text
    assert KAT_KEY.hex() not in report_text
    assert "secret-resource-xyz" not in report_text
    assert KAT_KEY.hex() not in logs


def test_memory_keystore_lifecycle() -> None:
    store = MemoryKeyStore()
    assert store.load() is None
    key = store.generate()
    assert len(key) == 32
    assert store.load() == key
    store.delete()
    assert store.load() is None


def test_os_keystore_lifecycle_with_fake_backend(monkeypatch: pytest.MonkeyPatch) -> None:
    import sys
    import types

    backend: dict[tuple[str, str], str] = {}

    fake_keyring = types.ModuleType("keyring")

    def get_password(service: str, username: str) -> str | None:
        return backend.get((service, username))

    def set_password(service: str, username: str, password: str) -> None:
        backend[(service, username)] = password

    def delete_password(service: str, username: str) -> None:
        if (service, username) not in backend:
            raise PasswordDeleteError("missing")
        backend.pop((service, username), None)

    fake_keyring.get_password = get_password  # type: ignore[attr-defined]
    fake_keyring.set_password = set_password  # type: ignore[attr-defined]
    fake_keyring.delete_password = delete_password  # type: ignore[attr-defined]

    fake_errors = types.ModuleType("keyring.errors")

    class PasswordDeleteError(Exception):
        pass

    fake_errors.PasswordDeleteError = PasswordDeleteError  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "keyring", fake_keyring)
    monkeypatch.setitem(sys.modules, "keyring.errors", fake_errors)

    store = OSKeyStore()
    assert store.load() is None
    key = store.generate()
    assert store.load() == key
    store.delete()
    assert store.load() is None
