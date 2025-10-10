import logging

import boto3
import pytest

from guardduty_soar.actions.iam.details import GetIamPrincipalDetailsAction

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)


def test_get_iam_user_details_integration(temporary_iam_user, real_app_config):
    """
    Tests that the action can successfully fetch details for a live IAM User.
    """
    user_name = temporary_iam_user["user_name"]
    policy_arn = temporary_iam_user["policy_arn"]

    principal_details_input = {
        "user_type": "IAMUser",
        "user_name": user_name,
    }

    session = boto3.Session()
    action = GetIamPrincipalDetailsAction(session, real_app_config)

    result = action.execute(event={}, principal_details=principal_details_input)

    assert result["status"] == "success"
    details = result["details"]

    assert details["details"]["UserName"] == user_name
    assert any(p["PolicyArn"] == policy_arn for p in details["attached_policies"])
    assert "gd-soar-test-inline-policy" in details["inline_policies"]
    logger.info(f"Successfully verified details were fetched for user {user_name}")


def test_get_iam_role_details_integration(temporary_iam_role, real_app_config):
    """
    Tests that the action can successfully fetch details for a live IAM Role.
    """
    role_name = temporary_iam_role["role_name"]
    principal_details_input = {
        "user_type": "AssumedRole",
        "user_name": role_name,  # For roles, user_name is just the role name
    }

    session = boto3.Session()
    action = GetIamPrincipalDetailsAction(session, real_app_config)

    result = action.execute(event={}, principal_details=principal_details_input)

    assert result["status"] == "success"
    details = result["details"]
    assert details["details"]["RoleName"] == role_name
    logger.info(f"Successfully verified details were fetched for role {role_name}")
