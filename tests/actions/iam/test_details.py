import json
from datetime import datetime
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.iam.details import GetIamPrincipalDetailsAction


def test_get_iam_user_details_success(principal_details_factory, mock_app_config):
    """Tests the success path for fetching details for an IAMUser."""
    iam_client = boto3.client("iam")
    action = GetIamPrincipalDetailsAction(MagicMock(), mock_app_config)
    action.iam_client = iam_client

    user_details_input = principal_details_factory(
        user_type="IAMUser", user_name="test-user"
    )

    with Stubber(iam_client) as stubber:
        get_user_response = {
            "User": {
                "UserName": "test-user",
                "Path": "/",
                "UserId": "AIDA_TEST_USER_ID",
                "Arn": "arn:aws:iam::123456789012:user/test-user",
                "CreateDate": datetime(2025, 1, 1),
            }
        }
        stubber.add_response("get_user", get_user_response, {"UserName": "test-user"})
        stubber.add_response(
            "list_attached_user_policies",
            {"AttachedPolicies": []},
            {"UserName": "test-user"},
        )
        stubber.add_response(
            "list_user_policies", {"PolicyNames": []}, {"UserName": "test-user"}
        )

        result = action.execute(event={}, principal_details=user_details_input)

    assert result["status"] == "success"
    assert result["details"]["details"]["UserName"] == "test-user"


def test_get_iam_role_details_success(principal_details_factory, mock_app_config):
    """Tests the success path for fetching details for an AssumedRole."""
    iam_client = boto3.client("iam")
    action = GetIamPrincipalDetailsAction(MagicMock(), mock_app_config)
    action.iam_client = iam_client

    role_details_input = principal_details_factory(
        user_type="AssumedRole", user_name="test-role/session-name"
    )

    with Stubber(iam_client) as stubber:
        get_role_response = {
            "Role": {
                "RoleName": "test-role",
                "Path": "/",
                "RoleId": "AROA_TEST_ROLE_ID",
                "Arn": "arn:aws:iam::123456789012:role/test-role",
                "CreateDate": datetime(2025, 1, 1),
                "AssumeRolePolicyDocument": json.dumps(
                    {"Version": "2012-10-17"}
                ),  # Required
            }
        }
        stubber.add_response("get_role", get_role_response, {"RoleName": "test-role"})
        stubber.add_response(
            "list_attached_role_policies",
            {"AttachedPolicies": []},
            {"RoleName": "test-role"},
        )
        stubber.add_response(
            "list_role_policies", {"PolicyNames": []}, {"RoleName": "test-role"}
        )

        result = action.execute(event={}, principal_details=role_details_input)

    assert result["status"] == "success"
    assert result["details"]["details"]["RoleName"] == "test-role"


def test_get_details_missing_input(mock_app_config):
    """Tests that the action fails gracefully if input is missing."""
    action = GetIamPrincipalDetailsAction(MagicMock(), mock_app_config)
    result = action.execute(event={})  # Call without principal_details kwarg

    assert result["status"] == "error"
    assert "were not provided" in result["details"]


def test_get_details_client_error(principal_details_factory, mock_app_config):
    """Tests that a boto3 ClientError is handled correctly."""
    iam_client = boto3.client("iam")
    action = GetIamPrincipalDetailsAction(MagicMock(), mock_app_config)
    action.iam_client = iam_client

    user_details = principal_details_factory(user_type="IAMUser", user_name="test-user")

    with Stubber(iam_client) as stubber:
        stubber.add_client_error("get_user", service_error_code="NoSuchEntity")
        result = action.execute(event={}, principal_details=user_details)

    assert result["status"] == "error"
    assert "NoSuchEntity" in result["details"]
