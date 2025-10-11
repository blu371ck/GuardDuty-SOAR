import json
import logging
import time
from dataclasses import replace

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.main import handler

pytestmark = pytest.mark.e2e  # Mark all tests in this file as 'e2e'

logger = logging.getLogger(__name__)


def test_ec2_instance_compromise_playbook_e2e(
    compromised_instance_e2e_setup,
    valid_guardduty_event,
    real_app_config,
    mocker,
    sqs_poller,
):
    """
    Tests the full EC2 Instance Compromise playbook from event trigger to final resource state.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")
    iam_client = session.client("iam")

    instance_id = compromised_instance_e2e_setup["instance_id"]
    queue_url = compromised_instance_e2e_setup["queue_url"]
    role_name = compromised_instance_e2e_setup["role_name"]
    temp_quarantine_sg_id = compromised_instance_e2e_setup["quarantine_sg_id"]

    test_config = replace(
        real_app_config,
        quarantine_security_group_id=temp_quarantine_sg_id,
        allow_terminate=True,
    )
    mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

    logger.info(
        f"Starting E2E test for Instance Compromise Playbook on instance {instance_id}..."
    )

    # Modify the GuardDuty event to point to our live test instance
    valid_guardduty_event["detail"]["Resource"]["InstanceDetails"][
        "InstanceId"
    ] = instance_id

    # Trigger the main handler
    response = handler(valid_guardduty_event, {})
    assert response["statusCode"] == 200

    time.sleep(10)  # Give the playbook time to complete
    logger.info("Verifying final state...")

    # Verify a snapshot was created
    snapshots = ec2_client.describe_snapshots(
        Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
    )["Snapshots"]
    assert len(snapshots) > 0, "Snapshot was not created."
    logger.info(f"Snapshot {snapshots[0]['SnapshotId']} was successfully created.")

    # Verify the IAM role was quarantined
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
        "AttachedPolicies"
    ]
    attached_arns = [p["PolicyArn"] for p in attached_policies]
    assert (
        real_app_config.iam_deny_all_policy_arn in attached_arns
    ), "Deny-all policy was not attached to the IAM role."
    logger.info(f"IAM role {role_name} was successfully quarantined.")

    # The teardown of the `temporary_ec2_instance` fixture will confirm termination.

    # Poll the SQS queue in a loop. (Moved to fixture)
    all_messages = sqs_poller(queue_url=queue_url, expected_count=2)

    # Verify the content of the completion message
    complete_message_body = [
        json.loads(m["Body"]) for m in all_messages if "playbook_completed" in m["Body"]
    ][0]
    assert complete_message_body["status_message"] == "Playbook completed successfully."

    resource_details = complete_message_body["resource"]
    assert resource_details["instance_id"] == instance_id
    assert resource_details.get("vpc_id") is not None
    logger.info("SNS notifications were contain enriched data (VPC ID).")
