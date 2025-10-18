import json
import logging
import time
from dataclasses import replace

import boto3
import pytest

from guardduty_soar.main import handler

pytestmark = pytest.mark.e2e

logger = logging.getLogger(__name__)


def test_s3_compromised_discovery_playbook_e2e(
    s3_compromise_e2e_setup,
    s3_guardduty_event,
    real_app_config,
    mocker,
    sqs_poller,
):
    """
    Tests the full S3 Compromised Discovery playbook from event trigger to final resource state.
    It verifies that the S3 bucket and IAM principal are tagged, the principal is quarantined,
    and notifications are sent.
    """
    session = boto3.Session()
    s3_client = session.client("s3")
    iam_client = session.client("iam")

    # Live resources and an enabled configuration
    bucket_name = s3_compromise_e2e_setup["bucket_name"]
    user_name = s3_compromise_e2e_setup["user_name"]
    queue_url = s3_compromise_e2e_setup["queue_url"]

    # Patch config to ensure IAM quarantine is allowed for this test
    test_config = replace(real_app_config, allow_iam_quarantine=True)
    mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

    logger.info(
        f"Starting E2E test for S3 Compromised Discovery on bucket {bucket_name} and user {user_name}..."
    )

    # Modify the finding event to point to our live resources
    test_event = s3_guardduty_event
    test_event["detail"]["Resource"]["S3BucketDetails"][0]["Name"] = bucket_name
    test_event["detail"]["Type"] = "Discovery:S3/AnomalousBehavior"
    test_event["detail"]["Resource"]["AccessKeyDetails"] = {
        "UserName": user_name,
        "UserType": "IAMUser",
        "AccessKeyId": "ASIA_DUMMY_KEY_FOR_TEST",
        "PrincipalId": "AIDA_DUMMY_ID_FOR_TEST",
    }

    # The Lambda handler is invoked with the S3 finding
    response = handler(test_event, {})
    assert response["statusCode"] == 200

    # Allow a few seconds for all AWS actions to propagate
    time.sleep(10)
    logger.info("Verifying final state of AWS resources...")

    # Verify the S3 bucket was tagged by the playbook
    s3_tags = {
        t["Key"]: t["Value"]
        for t in s3_client.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    }
    assert "SOAR-Status" in s3_tags
    assert s3_tags["SOAR-Status"] == "Remediation-In-Progress"
    logger.info(f"Bucket {bucket_name} was successfully tagged.")

    # Verify the IAM user was tagged by the playbook
    iam_tags = {
        t["Key"]: t["Value"]
        for t in iam_client.list_user_tags(UserName=user_name)["Tags"]
    }
    assert "SOAR-Status" in iam_tags
    assert iam_tags["SOAR-Status"] == "Remediation-In-Progress"
    logger.info(f"IAM user {user_name} was successfully tagged.")

    # Verify the IAM user was quarantined
    attached_policies = iam_client.list_attached_user_policies(UserName=user_name)[
        "AttachedPolicies"
    ]
    attached_arns = [p["PolicyArn"] for p in attached_policies]
    assert test_config.iam_deny_all_policy_arn in attached_arns
    logger.info(f"IAM user {user_name} was successfully quarantined.")

    # Verify both 'starting' and 'complete' notifications were sent
    all_messages = sqs_poller(queue_url=queue_url, expected_count=2, timeout=30)

    # Check for the completion message
    complete_message_body = [
        m for m in all_messages if "Playbook completed successfully" in m["Body"]
    ][0]

    notification_context = json.loads(complete_message_body["Body"])

    assert notification_context["playbook_name"] == "S3CompromisedDiscoveryPlaybook"
    assert notification_context["status_message"] == "Playbook completed successfully."
    assert notification_context["status_emoji"] == "✅"
    logger.info("SNS notifications were successfully verified.")
