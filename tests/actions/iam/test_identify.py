from unittest.mock import MagicMock

import pytest

from guardduty_soar.actions.iam.identify import IdentifyIamPrincipalAction


def test_identify_iam_user(iam_finding_factory, mock_app_config):
    """Tests that a finding with a UserType of 'IAMUser' is parsed correctly."""
    event = iam_finding_factory(user_type="IAMUser", user_name="test-user")
    action = IdentifyIamPrincipalAction(MagicMock(), mock_app_config)

    result = action.execute(event)

    assert result["status"] == "success"
    details = result["details"]
    assert details["user_type"] == "IAMUser"
    assert details["user_name"] == "test-user"
    assert details["principal_arn"] == "arn:aws:iam::123456789012:user/test-user"


def test_identify_assumed_role(iam_finding_factory, mock_app_config):
    """Tests that a finding with a UserType of 'AssumedRole' is parsed correctly."""
    event = iam_finding_factory(
        user_type="AssumedRole", user_name="test-role-name/session-name"
    )
    action = IdentifyIamPrincipalAction(MagicMock(), mock_app_config)

    result = action.execute(event)

    assert result["status"] == "success"
    details = result["details"]
    assert details["user_type"] == "AssumedRole"
    assert details["principal_arn"] == "arn:aws:iam::123456789012:role/test-role-name"


def test_identify_root_user(iam_finding_factory, mock_app_config):
    """Tests that a finding with a UserType of 'Root' is parsed correctly."""
    event = iam_finding_factory(user_type="Root", user_name="root")
    action = IdentifyIamPrincipalAction(MagicMock(), mock_app_config)

    result = action.execute(event)

    assert result["status"] == "success"
    details = result["details"]
    assert details["user_type"] == "Root"
    assert details["principal_arn"] == "arn:aws:iam::123456789012:root"


def test_identify_principal_key_error(mock_app_config):
    """Tests that the action fails gracefully if the event is malformed."""
    malformed_event = {
        "AccountId": "123456789012",
        "Resource": {},  # Missing AccessKeyDetails
    }
    action = IdentifyIamPrincipalAction(MagicMock(), mock_app_config)

    result = action.execute(malformed_event)

    assert result["status"] == "error"
    assert "missing expected key path" in result["details"]
