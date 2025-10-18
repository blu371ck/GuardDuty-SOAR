import json
import logging
import time
from copy import replace

import boto3

from guardduty_soar.main import handler

logger = logging.getLogger(__name__)


def test_s3_data_loss_prevention_playbook_e2e(
    s3_compromise_e2e_setup,
    s3_guardduty_event,
    real_app_config,
    mocker,
    sqs_poller,
):
    """
    Tests the full S3DataLossPreventionPlaybook, which inherits from the discovery
    playbook and adds an S3-specific CloudTrail history lookup.
    """
    session = boto3.Session()
    iam_client = session.client("iam")
    access_key_id = None  # Define for cleanup

    try:
        # Live resources and a generated S3 CloudTrail event
        bucket_name = s3_compromise_e2e_setup["bucket_name"]
        user_name = s3_compromise_e2e_setup["user_name"]
        queue_url = s3_compromise_e2e_setup["queue_url"]

        # Step 1: Create an access key and perform an S3 action as the user
        logger.info(f"Creating access key for user {user_name} to generate an event...")
        key_res = iam_client.create_access_key(UserName=user_name)
        access_key_id = key_res["AccessKey"]["AccessKeyId"]
        secret_key = key_res["AccessKey"]["SecretAccessKey"]
        time.sleep(15)  # Allow IAM key to propagate

        user_s3_client = boto3.client(
            "s3", aws_access_key_id=access_key_id, aws_secret_access_key=secret_key
        )
        user_s3_client.list_buckets()  # A simple, read-only S3 action
        logger.info("Performed S3 API call to generate a CloudTrail event.")

        # Step 2: Patch config and modify the finding event
        test_config = replace(real_app_config, allow_iam_quarantine=True)
        mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

        test_event = s3_guardduty_event
        test_event["detail"]["Resource"]["S3BucketDetails"][0]["Name"] = bucket_name
        # Use a finding type registered with the new playbook
        test_event["detail"]["Type"] = "Exfiltration:S3/AnomalousBehavior"
        test_event["detail"]["Resource"]["AccessKeyDetails"] = {
            "UserName": user_name,
            "UserType": "IAMUser",
        }

        # Step 3: Wait for the event to appear in CloudTrail. This can be slow.
        logger.info("Waiting 90 seconds for CloudTrail event propagation...")
        time.sleep(150)

        # The Lambda handler is invoked
        response = handler(test_event, {})
        assert response["statusCode"] == 200

        # Verify all actions from the parent AND child playbooks
        # (Verification for tagging and quarantine is done in the other E2E test,
        # here we focus on verifying the *new* step's output in the notification)
        logger.info("Polling for notifications to verify playbook results...")
        messages = sqs_poller(queue_url=queue_url, expected_count=2, timeout=30)

        completion_message = [
            m for m in messages if "Playbook completed successfully" in m["Body"]
        ][0]
        notification_content = json.loads(completion_message["Body"])

        # Assert that the correct playbook ran and the new data is present
        assert notification_content["playbook_name"] == "S3DataLossPreventionPlaybook"
        assert "s3_cloudtrail_history" in notification_content["enriched_data"]

        s3_history = notification_content["enriched_data"]["s3_cloudtrail_history"]
        assert (
            len(s3_history) > 0
        ), "Expected to find S3 events in CloudTrail history, but found none."

        # Verify that the specific event we generated was found
        assert any(event["EventName"] == "ListBuckets" for event in s3_history)
        logger.info(
            "Successfully verified S3 CloudTrail history in the final notification."
        )

    finally:
        # Cleanup the temporary access key
        if access_key_id:
            logger.info(f"Cleaning up temporary access key for {user_name}...")
            iam_client.delete_access_key(UserName=user_name, AccessKeyId=access_key_id)
