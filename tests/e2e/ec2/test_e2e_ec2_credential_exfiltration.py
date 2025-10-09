import copy
import logging
import time
from dataclasses import replace

import boto3
import pytest

from guardduty_soar import main

pytestmark = pytest.mark.e2e

logger = logging.getLogger(__name__)


def test_ec2_credential_exfiltration_playbook_e2e(
    compromised_instance_e2e_setup,
    valid_guardduty_event,
    real_app_config,
    mocker,
    sqs_poller,
):
    """
    Tests the full EC2CredentialExfiltrationPlaybook, verifying that the instance
    is tagged, isolated, its role is quarantined, a snapshot is taken, and
    notifications are sent.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")
    iam_client = session.client("iam")

    # Get resource IDs from our setup fixture
    test_resources = compromised_instance_e2e_setup
    instance_id = test_resources["instance_id"]
    role_name = test_resources["role_name"]
    queue_url = test_resources["queue_url"]
    temp_quarantine_sg_id = test_resources["quarantine_sg_id"]

    # Create a modified config for this test run and patch get_config()
    test_config = replace(real_app_config, quarantine_sg_id=temp_quarantine_sg_id)
    mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

    # Create the specific test event for this playbook
    test_event = copy.deepcopy(valid_guardduty_event)
    test_event["detail"]["Type"] = "UnauthorizedAccess:EC2/MetadataDNSRebind"
    test_event["detail"]["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

    logger.info(
        f"Starting E2E test for Credential Exfiltration on instance {instance_id}..."
    )
    response = main.handler(test_event, {})
    assert response["statusCode"] == 200

    time.sleep(15)  # Allow time for all playbook actions to complete
    logger.info("Verifying final state...")

    # Verify the instance was tagged
    tags = {
        t["Key"]: t["Value"]
        for t in ec2_client.describe_tags(
            Filters=[{"Name": "resource-id", "Values": [instance_id]}]
        )["Tags"]
    }
    assert "SOAR-Status" in tags, "Instance was not tagged."
    logger.info("Instance was successfully tagged.")

    # Verify the instance was isolated
    instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])[
        "Reservations"
    ][0]["Instances"][0]
    sg_ids = [sg["GroupId"] for sg in instance_info["SecurityGroups"]]
    assert sg_ids == [
        temp_quarantine_sg_id
    ], "Instance was not isolated to the quarantine SG."
    logger.info(f"Instance {instance_id} was successfully isolated.")

    # Verify the IAM role was quarantined
    attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
        "AttachedPolicies"
    ]
    attached_arns = [p["PolicyArn"] for p in attached_policies]
    assert (
        real_app_config.iam_deny_all_policy_arn in attached_arns
    ), "Deny-all policy was not attached."
    logger.info(f"IAM role {role_name} was successfully quarantined.")

    # Verify a snapshot was created
    snapshots = ec2_client.describe_snapshots(
        Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
    )["Snapshots"]
    assert len(snapshots) > 0, "Snapshot was not created."
    logger.info(f"Snapshot {snapshots[0]['SnapshotId']} was successfully created.")

    # E. Verify SNS notifications were sent
    all_messages = sqs_poller(queue_url=queue_url, expected_count=2)
    logger.info("SNS notifications were successfully verified via SQS.")
