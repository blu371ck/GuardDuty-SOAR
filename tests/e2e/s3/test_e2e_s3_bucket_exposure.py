import json
import logging
import time
from copy import replace

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.main import handler

logger = logging.getLogger(__name__)


def test_s3_bucket_exposure_playbook_e2e(
    s3_compromise_e2e_setup,
    s3_guardduty_event,
    real_app_config,
    mocker,
    sqs_poller,
):
    """
    Tests the full S3BucketExposurePlaybook, which inherits from the discovery
    playbook and adds the S3 block public access action.
    """
    session = boto3.Session()
    s3_client = session.client("s3")
    iam_client = session.client("iam")

    # Live resources and enabled configurations for all actions
    bucket_name = s3_compromise_e2e_setup["bucket_name"]
    user_name = s3_compromise_e2e_setup["user_name"]
    queue_url = s3_compromise_e2e_setup["queue_url"]

    # Patch config to ensure all remediation actions are allowed for this test
    test_config = replace(
        real_app_config, allow_iam_quarantine=True, allow_s3_public_block=True
    )
    mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

    logger.info(
        f"Starting E2E test for S3 Bucket Exposure on bucket {bucket_name} and user {user_name}..."
    )

    # Modify the finding event to point to our live resources and a relevant finding type
    test_event = s3_guardduty_event
    test_event["detail"]["Resource"]["S3BucketDetails"][0]["Name"] = bucket_name
    test_event["detail"][
        "Type"
    ] = "Policy:S3/BucketPublicAccessGranted"  # Use a registered type
    test_event["detail"]["Resource"]["AccessKeyDetails"] = {
        "UserName": user_name,
        "UserType": "IAMUser",
        "AccessKeyId": "ASIA_DUMMY_KEY_FOR_TEST",
        "PrincipalId": "AIDA_DUMMY_ID_FOR_TEST",
    }

    # The Lambda handler is invoked
    response = handler(test_event, {})
    assert response["statusCode"] == 200

    time.sleep(10)  # Allow actions to propagate
    logger.info("Verifying final state of AWS resources...")

    # Verify the S3 bucket was tagged
    s3_tags = {
        t["Key"]: t["Value"]
        for t in s3_client.get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    }
    assert "SOAR-Status" in s3_tags
    logger.info(f"Bucket {bucket_name} was successfully tagged.")

    # Verify the S3 bucket public access was blocked
    try:
        block_config = s3_client.get_public_access_block(Bucket=bucket_name)[
            "PublicAccessBlockConfiguration"
        ]
        assert block_config["BlockPublicAcls"] is True
        assert block_config["RestrictPublicBuckets"] is True
    except ClientError as e:
        pytest.fail(f"Failed to get public access block settings. Error: {e}")
    logger.info(f"Public access to bucket {bucket_name} was successfully blocked.")

    # Verify the IAM user was quarantined
    attached_policies = iam_client.list_attached_user_policies(UserName=user_name)[
        "AttachedPolicies"
    ]
    attached_arns = [p["PolicyArn"] for p in attached_policies]
    assert test_config.iam_deny_all_policy_arn in attached_arns
    logger.info(f"IAM user {user_name} was successfully quarantined.")

    # Verify notifications
    messages = sqs_poller(queue_url=queue_url, expected_count=2, timeout=30)
    completion_message = [
        m for m in messages if "Playbook completed successfully" in m["Body"]
    ][0]
    notification_content = json.loads(completion_message["Body"])

    assert notification_content["playbook_name"] == "S3BucketExposurePlaybook"
    assert "S3BlockPublicAccess" in notification_content["actions_summary"]
    logger.info("SNS notifications were successfully verified.")
