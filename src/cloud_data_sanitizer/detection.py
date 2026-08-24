from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Mapping
from difflib import get_close_matches
from typing import Any

from cloud_data_sanitizer.models import (
    Classification,
    ColumnFinding,
    MaskingAction,
)


def canonical(value: object) -> str:
    return "".join(
        character for character in str(value).strip().lower() if character.isalnum()
    )


FIELD_ALIASES: dict[str, set[str]] = {
    "provider": {"provider", "cloudprovider", "cloud"},
    "service": {
        "service",
        "servicename",
        "consumedservice",
        "productservicename",
        "productcode",
    },
    "resource_type": {"resourcetype", "metercategory", "productfamily", "producttype"},
    "sku": {"sku", "skuname", "metername", "usagetype", "productname"},
    "region": {"region", "resourcelocation", "productregion", "location"},
    "usage_date": {
        "usagedate",
        "date",
        "lineitemusagestartdate",
        "billingperiod",
        "billingcycle",
    },
    "usage_quantity": {
        "usagequantity",
        "quantity",
        "consumedquantity",
        "lineitemusageamount",
    },
    "cost": {
        "cost",
        "amount",
        "costinbillingcurrency",
        "pretaxcost",
        "lineitemunblendedcost",
        "pretaxamount",
    },
    "currency": {"currency", "billingcurrency", "currencycode"},
    "subscription_id": {"subscriptionid", "subscriptionguid"},
    "tenant_id": {"tenantid", "directoryid"},
    "account_id": {
        "accountid",
        "billpayeraccountid",
        "lineitemusageaccountid",
        "billingaccountid",
    },
    "project_id": {"projectid", "projectnumber"},
    "resource_id": {"resourceid", "lineitemresourceid", "instanceid"},
    "resource_name": {"resourcename", "resource", "instancename"},
    "host_name": {"hostname", "computername", "servername"},
    "ip_address": {"ip", "ipaddress", "privateip", "publicip"},
    "owner": {"owner", "owneremail", "createdby", "contact"},
    "application_name": {"application", "applicationname", "appname"},
    "tags": {"tags", "resourcetags", "labels", "internaltags"},
    "resource_group": {"resourcegroup", "resourcegroupname"},
    "namespace": {"namespace", "kubernetesnamespace"},
    "cluster_name": {"cluster", "clustername"},
    "database_name": {"database", "databasename", "dbname"},
    "environment": {"environment", "environmentname", "env", "stage"},
    "business_unit": {"businessunit", "costcenter", "department"},
    "team_name": {"team", "teamname"},
}

ANALYSIS_FIELDS = {
    "provider",
    "service",
    "resource_type",
    "sku",
    "region",
    "usage_date",
    "usage_quantity",
    "cost",
    "currency",
}
SENSITIVE_FIELDS = {
    "subscription_id",
    "tenant_id",
    "account_id",
    "project_id",
    "resource_id",
    "resource_name",
    "host_name",
    "ip_address",
    "owner",
    "application_name",
    "tags",
}
POTENTIAL_FIELDS = {
    "resource_group",
    "namespace",
    "cluster_name",
    "database_name",
    "environment",
    "business_unit",
    "team_name",
}

EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
SECRET_PATTERN = re.compile(
    r"(?:-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"\b(?:access[_-]?key|secret[_-]?key|api[_-]?key|token|password|passwd|credential)\b)",
    re.IGNORECASE,
)
RESTRICTED_HEADER_PATTERN = re.compile(
    r"(?:access[_-]?key|secret[_-]?key|api[_-]?key|token|password|passwd|"
    r"credential|private[_-]?key|client[_-]?secret)",
    re.IGNORECASE,
)


def detect_field(column: str, *, fuzzy: bool = True) -> str | None:
    normalized = canonical(column)
    exact = next(
        (field for field, aliases in FIELD_ALIASES.items() if normalized in aliases),
        None,
    )
    if exact or not fuzzy or len(normalized) < 5:
        return exact
    candidates = {
        alias: field for field, aliases in FIELD_ALIASES.items() for alias in aliases
    }
    matches = get_close_matches(normalized, candidates, n=1, cutoff=0.9)
    return candidates[matches[0]] if matches else None


def is_restricted_column(column: str, values: Iterable[Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if RESTRICTED_HEADER_PATTERN.search(str(column)):
        reasons.append("credential-like column name")
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        if SECRET_PATTERN.search(text):
            reasons.append("credential or secret-like values")
            break
    return bool(reasons), reasons


def _value_signals(values: Iterable[Any]) -> set[str]:
    signals: set[str] = set()
    for value in values:
        if value is None:
            continue
        text = str(value).strip()
        if not text:
            continue
        if EMAIL_PATTERN.match(text):
            signals.add("email-like values")
        try:
            ipaddress.ip_address(text)
            signals.add("IP address values")
        except ValueError:
            pass
        if SECRET_PATTERN.search(text):
            signals.add("credential or secret-like values")
    return signals


def classify_columns(
    headers: Iterable[str], rows: list[Mapping[str, Any]], sample_limit: int = 500
) -> list[ColumnFinding]:
    """Classify columns.

    Credential/Restricted detection scans the **full column** (fail-closed).
    Non-credential sampling remains bounded by ``sample_limit`` for performance.
    """
    findings: list[ColumnFinding] = []
    for column in headers:
        field = detect_field(column)
        # Full-column scan for Restricted / credential canaries (CDS-V-006).
        full_values = [row.get(column) for row in rows]
        sample_values = full_values[:sample_limit]
        restricted, restricted_reasons = is_restricted_column(column, full_values)
        signals = _value_signals(sample_values)
        reasons: list[str] = []

        if restricted:
            classification = Classification.RESTRICTED
            action = MaskingAction.REMOVE
            reasons.extend(restricted_reasons)
            reasons.append(
                "restricted columns must be physically dropped or export blocked"
            )
        elif field in ANALYSIS_FIELDS:
            classification = Classification.ANALYSIS_REQUIRED
            action = MaskingAction.KEEP
            reasons.append("required for FinOps analysis")
        elif field in SENSITIVE_FIELDS:
            classification = Classification.SENSITIVE
            action = MaskingAction.PSEUDONYMIZE
            reasons.append(f"recognized sensitive field: {field}")
        elif field in POTENTIAL_FIELDS:
            classification = Classification.POTENTIALLY_SENSITIVE
            action = MaskingAction.KEEP
            reasons.append(f"organization-dependent sensitive field: {field}")
        elif signals:
            classification = Classification.SENSITIVE
            action = MaskingAction.PSEUDONYMIZE
            reasons.append("sample values contain sensitive patterns")
        else:
            classification = Classification.POTENTIALLY_SENSITIVE
            action = MaskingAction.KEEP
            reasons.append(
                "field purpose is not recognized; an explicit sharing decision is required"
            )
        reasons.extend(sorted(signals - set(restricted_reasons)))
        nonempty = [
            value for value in full_values if value is not None and str(value).strip()
        ]
        findings.append(
            ColumnFinding(
                column=column,
                normalized_field=field,
                classification=classification,
                recommended_action=action,
                reasons=tuple(reasons),
                nonempty_count=len(nonempty),
                unique_count=len({str(value) for value in nonempty}),
            )
        )
    return findings
