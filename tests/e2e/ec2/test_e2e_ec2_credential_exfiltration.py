import copy
import json
import logging
import re
import time
from dataclasses import replace

import boto3
import pytest
from botocore.exceptions import ClientError

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
    is tagged, dynamically isolated, its role is quarantined, a snapshot is taken, and
    notifications are sent.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")
    iam_client = session.client("iam")
    new_sg_id = None
    # Define instance_id early so it's available in the finally block
    instance_id = compromised_instance_e2e_setup["instance_id"]

    try:
        test_resources = compromised_instance_e2e_setup
        role_name = test_resources["role_name"]
        queue_url = test_resources["queue_url"]
        vpc_id = test_resources["vpc_id"]

        test_event = copy.deepcopy(valid_guardduty_event)
        test_event["detail"]["Type"] = "UnauthorizedAccess:EC2/MetadataDNSRebind"
        test_event["detail"]["Resource"]["InstanceDetails"]["InstanceId"] = instance_id
        test_event["detail"]["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
            "VpcId"
        ] = vpc_id

        logger.info(
            f"Starting E2E test for Credential Exfiltration on instance {instance_id}..."
        )
        response = main.handler(test_event, {})
        assert response["statusCode"] == 200

        time.sleep(15)
        logger.info("Verifying final state...")

        tags = {
            t["Key"]: t["Value"]
            for t in ec2_client.describe_tags(
                Filters=[{"Name": "resource-id", "Values": [instance_id]}]
            )["Tags"]
        }
        assert "SOAR-Status" in tags, "Instance was not tagged."
        logger.info("Instance was successfully tagged.")

        instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])[
            "Reservations"
        ][0]["Instances"][0]
        sg_ids = [sg["GroupId"] for sg in instance_info["SecurityGroups"]]
        assert len(sg_ids) == 1, "Instance should be in exactly one quarantine SG."
        new_sg_id = sg_ids[0]

        quarantine_sg = ec2_client.describe_security_groups(GroupIds=[new_sg_id])[
            "SecurityGroups"
        ][0]
        assert not quarantine_sg.get("IpPermissions") and not quarantine_sg.get(
            "IpPermissionsEgress"
        )
        logger.info(f"Instance {instance_id} was successfully isolated.")

        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        attached_arns = [p["PolicyArn"] for p in attached_policies]
        assert (
            "arn:aws:iam::aws:policy/AWSDenyAll" in attached_arns
        ), "Deny-all policy was not attached."
        logger.info(f"IAM role {role_name} was successfully quarantined.")

        snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
        )["Snapshots"]
        assert len(snapshots) > 0, "Snapshot was not created."
        logger.info(f"Snapshot {snapshots[0]['SnapshotId']} was successfully created.")

        sqs_poller(queue_url=queue_url, expected_count=2)
        logger.info("SNS notifications were successfully verified via SQS.")

    finally:
        # Must happen in the correct order to remove dependencies.
        if new_sg_id:
            try:
                logger.info("Cleaning up from credential exfiltration test...")
                # 1. Revert the instance to its original security group to remove the dependency.
                original_sg_id = test_resources["default_sg_id"]
                ec2_client.modify_instance_attribute(
                    InstanceId=instance_id, Groups=[original_sg_id]
                )
                logger.info(
                    f"Reverted instance {instance_id} to original SG {original_sg_id}."
                )

                time.sleep(10)  # Allow time for the dependency to be released.

                # 2. Now that the SG is not in use, it can be deleted.
                logger.info(f"Deleting dynamically created security group: {new_sg_id}")
                ec2_client.delete_security_group(GroupId=new_sg_id)
            except ClientError as e:
                logger.warning(
                    f"Could not clean up resources. Manual cleanup may be required. Error: {e}"
                )
