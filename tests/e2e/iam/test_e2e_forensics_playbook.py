import json
import logging

import boto3
import pytest

from guardduty_soar import main

pytestmark = pytest.mark.e2e

logger = logging.getLogger(__name__)


def test_iam_forensics_playbook_e2e(
    temporary_iam_user_with_risky_policy,
    iam_finding_factory,
    valid_guardduty_event,
    e2e_notification_channel,
    sqs_poller,
):
    """
    Tests the full workflow of the IamForensicsPlaybook.

    It verifies that:
    1. A temporary IAM user is created with a risky policy.
    2. The playbook is triggered by a mock GuardDuty finding for that user.
    3. The IAM user is correctly tagged by the playbook.
    4. The risky permissions are identified and reported in the final notification.
    5. All expected actions are reported as successful in the final notification.
    """
    # 1. Set up test clients and craft the specific event
    session = boto3.Session()
    iam_client = session.client("iam")

    # Get details from the fixtures
    user_name = temporary_iam_user_with_risky_policy["user_name"]
    queue_url = e2e_notification_channel["queue_url"]

    # Use the finding factory to create a finding specific to our temporary user
    finding_detail = iam_finding_factory(user_type="IAMUser", user_name=user_name)

    # Create the final Lambda event by replacing the detail object
    test_event = valid_guardduty_event.copy()
    test_event["detail"] = finding_detail
    test_event["detail"]["Title"] = f"Test finding for risky user {user_name}"
    test_event["detail"][
        "Description"
    ] = "This is an E2E test for the IamForensicsPlaybook."

    logger.info(f"Starting E2E test for IamForensicsPlaybook on user '{user_name}'...")

    # 2. Invoke the main Lambda handler
    response = main.handler(test_event, {})
    assert response["statusCode"] == 200, "The Lambda handler failed to execute."

    logger.info("Verifying final state of resources and notifications...")

    # 3. Verify the results
    # First, verify that the playbook sent the 'starting' and 'complete' notifications
    messages = sqs_poller(queue_url=queue_url, expected_count=2)
    logger.info("Successfully received 2 notifications via SQS.")

    # Parse the notification bodies to perform detailed checks
    notification_bodies = [json.loads(msg["Body"]) for msg in messages]
    complete_notification = next(
        body
        for body in notification_bodies
        if body["event_type"] == "playbook_completed"
    )

    # Verify the contents of the 'complete' notification
    assert complete_notification["status_message"] == "Playbook completed successfully."
    summary = complete_notification["actions_summary"]
    assert "IdentifyPrincipal: SUCCESS" in summary
    assert "TagPrincipal: SUCCESS" in summary
    assert "GetIamPrincipalDetails: SUCCESS" in summary
    assert "GetIamCloudTrailHistory: SUCCESS" in summary
    assert "AnalyzeIamPermissions: SUCCESS" in summary
    logger.info(
        "Successfully verified all playbook actions reported success in notification."
    )

    # Verify that the permission analysis found the risky policy
    enriched_data = complete_notification.get("enriched_data", {})
    permission_analysis = enriched_data.get("permission_analysis", {})
    risks_found = permission_analysis.get("risks_found", {})

    # 1. Verify that the analysis results are present and not empty
    assert (
        risks_found
    ), "Permission analysis did not find any risks when it should have."

    # 2. Verify the specific wildcard risk was identified in the correct policy
    risky_policy_name = "InlinePolicy: gd-soar-risky-inline-policy"
    assert risky_policy_name in risks_found
    assert (
        "Allows all actions ('*') on all resources ('*')."
        in risks_found[risky_policy_name]
    )
    logger.info(
        "Successfully verified that risky permissions were detected and reported."
    )

    # Second, verify the IAM user was tagged directly via AWS API
    user_details = iam_client.get_user(UserName=user_name)
    tags = {tag["Key"]: tag["Value"] for tag in user_details["User"]["Tags"]}
    assert "SOAR-Status" in tags
    assert tags["SOAR-Status"] == "Remediation-In-Progress"
    assert tags["GUARDDUTY-SOAR-ID"] == "iam-finding-id"
    logger.info(f"Successfully verified tags were applied to user '{user_name}'.")
