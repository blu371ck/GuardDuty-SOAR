import logging
import time

import boto3
import pytest

from guardduty_soar.actions.iam.details import GetIamPrincipalDetailsAction
from guardduty_soar.actions.iam.history import GetCloudTrailHistoryAction

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


def test_get_cloudtrail_history_integration(temporary_iam_user, real_app_config):
    """
    Tests that the action can successfully fetch a live CloudTrail event
    for a temporary IAM user.
    """
    session = boto3.Session()
    iam_client = session.client("iam")
    sts_client = session.client("sts")
    account_id = sts_client.get_caller_identity()["Account"]
    user_name = temporary_iam_user["user_name"]
    principal_arn = f"arn:aws:iam::{account_id}:user/{user_name}"

    # Step 1: Create a temporary access key for the user to perform an action.
    logger.info(f"Creating access key for temporary user {user_name}...")
    key_response = iam_client.create_access_key(UserName=user_name)
    access_key_id = key_response["AccessKey"]["AccessKeyId"]
    secret_access_key = key_response["AccessKey"]["SecretAccessKey"]
    logger.info("Waiting 10 seconds for IAM key propagation...")
    time.sleep(10)

    try:
        # Step 2: Perform an action as the temporary user to generate an event.
        logger.info(
            "Performing an API call as the user to generate a CloudTrail event..."
        )
        user_session = boto3.Session(
            aws_access_key_id=access_key_id,
            aws_secret_access_key=secret_access_key,
        )
        user_iam_client = user_session.client("iam")
        user_iam_client.list_account_aliases()  # A simple, read-only action

        # Step 3: Wait for the event to propagate to CloudTrail. This can take time.
        logger.info("Waiting 90 seconds for CloudTrail event propagation...")
        time.sleep(240)

        # Step 4: Execute the action to fetch the history.
        action = GetCloudTrailHistoryAction(session, real_app_config)
        result = action.execute(event={}, user_name=user_name)

        # Step 5: Validate the results.
        assert result["status"] == "success"
        details = result["details"]
        assert isinstance(details, list)
        assert (
            len(details) > 0
        ), "Expected at least one CloudTrail event, but found none."

        # Check if the specific action we performed is in the history
        event_found = any(
            event.get("EventName") == "ListAccountAliases" for event in details
        )
        assert (
            event_found
        ), "The 'ListAccountAliases' event was not found in the history."

        logger.info(f"Successfully verified CloudTrail history for user {user_name}")

    finally:
        # Step 6: Clean up the temporary access key.
        logger.info(f"Cleaning up access key for user {user_name}...")
        iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
