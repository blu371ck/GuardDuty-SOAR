import json
import logging
import time
from dataclasses import replace

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.main import handler

pytestmark = pytest.mark.e2e

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
    new_sg_id = None
    instance_id = compromised_instance_e2e_setup[
        "instance_id"
    ]  # Define early for cleanup

    try:
        queue_url = compromised_instance_e2e_setup["queue_url"]
        role_name = compromised_instance_e2e_setup["role_name"]
        vpc_id = compromised_instance_e2e_setup["vpc_id"]

        # Patch config to allow termination
        test_config = replace(real_app_config, allow_terminate=True)
        mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

        logger.info(
            f"Starting E2E test for Instance Compromise Playbook on instance {instance_id}..."
        )

        # Modify the event to point to our live instance and include the VpcId
        test_event = valid_guardduty_event.copy()
        test_event["detail"]["Resource"]["InstanceDetails"]["InstanceId"] = instance_id
        test_event["detail"]["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
            "VpcId"
        ] = vpc_id

        response = handler(test_event, {})
        assert response["statusCode"] == 200

        time.sleep(15)
        logger.info("Verifying final state...")

        # Verify a snapshot was created
        snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
        )["Snapshots"]
        assert len(snapshots) > 0, "Snapshot was not created."
        logger.info(f"Snapshot {snapshots[0]['SnapshotId']} was successfully created.")

        # Verify the instance was dynamically isolated
        instance_info = ec2_client.describe_instances(InstanceIds=[instance_id])[
            "Reservations"
        ][0]["Instances"][0]
        sg_ids = [sg["GroupId"] for sg in instance_info["SecurityGroups"]]
        assert len(sg_ids) == 1, "Instance should be in exactly one quarantine SG."
        new_sg_id = sg_ids[0]  # Capture for cleanup

        quarantine_sg = ec2_client.describe_security_groups(GroupIds=[new_sg_id])[
            "SecurityGroups"
        ][0]
        assert not quarantine_sg.get(
            "IpPermissions"
        ), "Quarantine SG should have no inbound rules."
        assert not quarantine_sg.get(
            "IpPermissionsEgress"
        ), "Quarantine SG should have no outbound rules."
        logger.info(
            f"Instance {instance_id} was successfully isolated in new SG {new_sg_id}."
        )

        # Verify the IAM role was quarantined
        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        attached_arns = [p["PolicyArn"] for p in attached_policies]
        assert (
            real_app_config.iam_deny_all_policy_arn in attached_arns
        ), "Deny-all policy was not attached."
        logger.info(f"IAM role {role_name} was successfully quarantined.")

        # The teardown of the `temporary_ec2_instance` fixture will confirm termination.

        # Verify notifications
        all_messages = sqs_poller(queue_url=queue_url, expected_count=2)
        complete_message_body = [
            json.loads(m["Body"])
            for m in all_messages
            if "playbook_completed" in m["Body"]
        ][0]
        assert (
            complete_message_body["status_message"]
            == "Playbook completed successfully."
        )
        logger.info("SNS notifications were successfully verified.")

    finally:
        # Revert SG and delete the dynamically created one
        if new_sg_id:
            try:
                logger.info("Cleaning up from Compromise (SOURCE) test...")
                # 1. Wait for the instance to be fully terminated.
                waiter = ec2_client.get_waiter("instance_terminated")
                waiter.wait(InstanceIds=[instance_id])
                logger.info(f"Instance {instance_id} is confirmed terminated.")

                # 2. Now that the instance is gone, the SG dependency is removed.
                ec2_client.delete_security_group(GroupId=new_sg_id)
                logger.info(f"Cleaned up dynamic SG {new_sg_id}.")
            except ClientError as e:
                logger.warning(
                    f"Could not clean up resources. Manual cleanup may be required. Error: {e}"
                )
