import dataclasses
import logging
import time

import boto3
import pytest

from guardduty_soar.actions.iam.analyze import AnalyzePermissionsAction
from guardduty_soar.actions.iam.details import GetIamPrincipalDetailsAction
from guardduty_soar.actions.iam.history import GetCloudTrailHistoryAction
from guardduty_soar.actions.iam.tag import TagIamPrincipalAction

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
    lookup_attributes = [{"AttributeKey": "Username", "AttributeValue": user_name}]

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
        result = action.execute(event={}, lookup_attributes=lookup_attributes)

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


def test_analyze_permissions_risky_integration(
    temporary_iam_user_with_risky_policy, real_app_config
):
    """
    Tests that the action correctly identifies a risky policy on a live IAM user.
    """
    user_name = temporary_iam_user_with_risky_policy["user_name"]
    session = boto3.Session()

    # Step 1: Run the prerequisite action to get the principal's policies
    details_action = GetIamPrincipalDetailsAction(session, real_app_config)
    details_result = details_action.execute(
        event={}, principal_details={"user_type": "IAMUser", "user_name": user_name}
    )
    assert details_result["status"] == "success"

    # Step 2: Run the analysis action on the results of the first action
    analyze_action = AnalyzePermissionsAction(session, real_app_config)
    analyze_result = analyze_action.execute(
        event={}, principal_policies=details_result["details"]
    )

    # Step 3: Validate the analysis
    assert analyze_result["status"] == "success"
    risks = analyze_result["details"]["risks_found"]
    assert len(risks) == 1
    assert "InlinePolicy: gd-soar-risky-inline-policy" in risks
    assert (
        "Allows all actions ('*') on all resources ('*')."
        in risks["InlinePolicy: gd-soar-risky-inline-policy"]
    )
    logger.info(f"Successfully verified risky policy for user {user_name}")


def test_analyze_permissions_clean_integration(temporary_iam_user, real_app_config):
    """
    Tests that the action finds no risks for a user with well-scoped policies.
    """
    user_name = temporary_iam_user["user_name"]
    session = boto3.Session()

    # Step 1: Get the principal's policies
    details_action = GetIamPrincipalDetailsAction(session, real_app_config)
    details_result = details_action.execute(
        event={}, principal_details={"user_type": "IAMUser", "user_name": user_name}
    )
    assert details_result["status"] == "success"

    # Step 2: Run the analysis action
    analyze_action = AnalyzePermissionsAction(session, real_app_config)
    analyze_result = analyze_action.execute(
        event={}, principal_policies=details_result["details"]
    )

    # Step 3: Validate that no risks were found
    assert analyze_result["status"] == "success"
    assert not analyze_result["details"][
        "risks_found"
    ]  # The risks dict should be empty
    logger.info(f"Successfully verified no risks for clean user {user_name}")


def test_analyze_permissions_skipped_integration(real_app_config):
    """
    Tests that the action correctly skips execution if disabled in the config.
    """
    # Create a copy of the real config and disable the action
    disabled_config = dataclasses.replace(
        real_app_config, analyze_iam_permissions=False
    )
    session = boto3.Session()

    action = AnalyzePermissionsAction(session, disabled_config)
    result = action.execute(
        event={}, principal_policies={}
    )  # Policies don't matter here

    assert result["status"] == "skipped"
    logger.info("Successfully verified action is skipped when disabled")


def test_tag_iam_user_integration(temporary_iam_user, real_app_config):
    """
    Tests that the action can successfully tag a live IAM User.
    """
    session = boto3.Session()
    iam_client = session.client("iam")
    user_name = temporary_iam_user["user_name"]

    # Prepare inputs for the action
    principal_identity = {"user_type": "IAMUser", "user_name": user_name}
    mock_event = {
        "Id": "test-finding-id-user",
        "Type": "Test:IAMUser/TaggingTest",
        "Severity": 7.5,  # HIGH
    }

    # Execute the action
    action = TagIamPrincipalAction(session, real_app_config)
    result = action.execute(
        event=mock_event,
        principal_identity=principal_identity,
        playbook_name="IAMUserTaggingPlaybook",
    )
    assert result["status"] == "success"

    # Verify the tags were actually applied in AWS
    response = iam_client.list_user_tags(UserName=user_name)
    tags = {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    assert "GUARDDUTY-SOAR-ID" in tags
    assert tags["SOAR-Finding-Severity"] == "HIGH"
    assert tags["SOAR-Playbook"] == "IAMUserTaggingPlaybook"
    logger.info(f"Successfully verified tags were applied to user {user_name}")


def test_tag_iam_role_integration(temporary_iam_role, real_app_config):
    """
    Tests that the action can successfully tag a live IAM Role.
    """
    session = boto3.Session()
    iam_client = session.client("iam")
    role_name = temporary_iam_role["role_name"]

    # Prepare inputs for the action
    principal_identity = {"user_type": "Role", "user_name": role_name}
    mock_event = {
        "Id": "test-finding-id-role",
        "Type": "Test:IAMRole/TaggingTest",
        "Severity": 2.0,  # LOW
    }

    # Execute the action
    action = TagIamPrincipalAction(session, real_app_config)
    result = action.execute(
        event=mock_event,
        principal_identity=principal_identity,
        playbook_name="IAMRoleTaggingPlaybook",
    )
    assert result["status"] == "success"

    # Verify the tags were actually applied in AWS
    response = iam_client.list_role_tags(RoleName=role_name)
    tags = {tag["Key"]: tag["Value"] for tag in response["Tags"]}

    assert tags["GUARDDUTY-SOAR-ID"] == "test-finding-id-role"
    assert tags["SOAR-Finding-Severity"] == "LOW"
    assert tags["SOAR-Status"] == "Remediation-In-Progress"
    logger.info(f"Successfully verified tags were applied to role {role_name}")


def test_tag_skips_root_user_integration(real_app_config):
    """
    Tests that the action correctly skips the Root principal, which cannot be tagged.
    """
    session = boto3.Session()
    principal_identity = {"user_type": "Root", "user_name": "root"}

    action = TagIamPrincipalAction(session, real_app_config)
    result = action.execute(event={}, principal_identity=principal_identity)

    assert result["status"] == "skipped"
    logger.info("Successfully verified action skips the Root user")
