from datetime import datetime
from unittest.mock import ANY, MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.iam.tag import TagIamPrincipalAction


def test_tag_iam_user_success(mock_app_config, principal_identity_factory, mock_event):
    """Tests that an IAMUser is tagged successfully."""
    iam_client = boto3.client("iam")
    action = TagIamPrincipalAction(MagicMock(), mock_app_config)
    action.iam_client = iam_client

    identity = principal_identity_factory(user_type="IAMUser", user_name="test-user")
    expected_params = {"UserName": "test-user", "Tags": ANY}

    with Stubber(iam_client) as stubber:
        stubber.add_response("tag_user", {}, expected_params)
        result = action.execute(
            event=mock_event, principal_identity=identity, playbook_name="TestPlaybook"
        )

    assert result["status"] == "success"
    assert "Successfully added SOAR tags" in result["details"]


def test_tag_iam_role_success(mock_app_config, principal_identity_factory, mock_event):
    """Tests that an AssumedRole is tagged successfully, extracting the role name."""
    iam_client = boto3.client("iam")
    action = TagIamPrincipalAction(MagicMock(), mock_app_config)
    action.iam_client = iam_client

    # user_name for AssumedRole includes the session name, which must be stripped
    identity = principal_identity_factory(
        user_type="AssumedRole", user_name="test-role/session-name"
    )
    # The action must correctly extract 'test-role' as the RoleName
    expected_params = {"RoleName": "test-role", "Tags": ANY}

    with Stubber(iam_client) as stubber:
        stubber.add_response("tag_role", {}, expected_params)
        result = action.execute(
            event=mock_event, principal_identity=identity, playbook_name="TestPlaybook"
        )

    assert result["status"] == "success"
    assert "Successfully added SOAR tags" in result["details"]


def test_tag_skips_for_root_user(mock_app_config, principal_identity_factory):
    """Tests that the action is correctly skipped for the Root user."""
    action = TagIamPrincipalAction(MagicMock(), mock_app_config)
    identity = principal_identity_factory(user_type="Root", user_name="root")
    result = action.execute(event={}, principal_identity=identity)

    assert result["status"] == "skipped"
    assert "Root user cannot be tagged" in result["details"]


def test_tag_errors_on_unknown_type(mock_app_config, principal_identity_factory):
    """Tests that the action returns an error for an unsupported principal type."""
    action = TagIamPrincipalAction(MagicMock(), mock_app_config)
    identity = principal_identity_factory(user_type="FederatedUser", user_name="test")
    result = action.execute(event={}, principal_identity=identity)

    assert result["status"] == "error"
    assert "unknown principal type" in result["details"]


def test_tag_errors_on_missing_input(mock_app_config):
    """Tests that the action returns an error if the input dictionary is missing."""
    action = TagIamPrincipalAction(MagicMock(), mock_app_config)
    result = action.execute(event={})  # Missing principal_identity kwarg

    assert result["status"] == "error"
    assert "was not provided" in result["details"]


def test_tag_handles_client_error(
    mock_app_config, principal_identity_factory, mock_event
):
    """Tests the handling of a Boto3 ClientError during the API call."""
    iam_client = boto3.client("iam")
    action = TagIamPrincipalAction(MagicMock(), mock_app_config)
    action.iam_client = iam_client

    identity = principal_identity_factory(user_type="IAMUser", user_name="test-user")

    with Stubber(iam_client) as stubber:
        stubber.add_client_error("tag_user", service_error_code="NoSuchEntity")
        result = action.execute(
            event=mock_event, principal_identity=identity, playbook_name="TestPlaybook"
        )

    assert result["status"] == "error"
    assert "NoSuchEntity" in result["details"]
