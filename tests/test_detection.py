from __future__ import annotations

from cloud_data_sanitizer.detection import classify_columns, detect_field
from cloud_data_sanitizer.models import Classification, MaskingAction


def test_detects_multicloud_aliases() -> None:
    assert detect_field("CostInBillingCurrency") == "cost"
    assert detect_field("lineItem/UnblendedCost") == "cost"
    assert detect_field("Project ID") == "project_id"
    assert detect_field("InstanceName") == "resource_name"


def test_classifies_required_sensitive_restricted_and_unknown() -> None:
    rows = [
        {
            "Cost": "10",
            "ResourceId": "secret-resource",
            "Custom Metadata": "internal",
            "Contact": "owner@example.com",
            "AccessKey": "AKIAEXAMPLE",
        }
    ]
    findings = {item.column: item for item in classify_columns(rows[0], rows)}

    assert findings["Cost"].classification is Classification.ANALYSIS_REQUIRED
    assert findings["Cost"].recommended_action is MaskingAction.KEEP
    assert findings["ResourceId"].classification is Classification.SENSITIVE
    assert findings["ResourceId"].recommended_action is MaskingAction.PSEUDONYMIZE
    assert (
        findings["Custom Metadata"].classification
        is Classification.POTENTIALLY_SENSITIVE
    )
    assert findings["AccessKey"].classification is Classification.RESTRICTED
    assert findings["AccessKey"].recommended_action is MaskingAction.REMOVE
    assert "email-like values" in findings["Contact"].reasons
