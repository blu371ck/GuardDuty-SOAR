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


def test_ec2_brute_force_playbook_e2e_as_target(
    temporary_ec2_instance,
    ssh_brute_force_finding,
    valid_guardduty_event,
    e2e_notification_channel,
    sqs_poller,
):
    """
    Tests the 'TARGET' path of the EC2BruteForcePlaybook.
    Verifies the instance is tagged and the attacker's IP is blocked in the NACL.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")

    instance_id = temporary_ec2_instance["instance_id"]
    subnet_id = temporary_ec2_instance["subnet_id"]
    vpc_id = temporary_ec2_instance["vpc_id"]
    queue_url = e2e_notification_channel["queue_url"]
    malicious_ip = "198.51.100.111"

    nacl = ec2_client.describe_network_acls(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "default", "Values": ["true"]},
        ]
    )["NetworkAcls"][0]
    nacl_id = nacl["NetworkAclId"]

    test_event = copy.deepcopy(valid_guardduty_event)
    test_event["detail"] = copy.deepcopy(ssh_brute_force_finding)
    test_event["detail"]["Service"]["ResourceRole"] = "TARGET"
    test_event["detail"]["Resource"]["InstanceDetails"]["InstanceId"] = instance_id
    test_event["detail"]["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
        "SubnetId"
    ] = subnet_id
    test_event["detail"]["Service"]["Action"]["NetworkConnectionAction"][
        "RemoteIpDetails"
    ]["IpAddressV4"] = malicious_ip

    logger.info(
        f"Starting E2E test for Brute Force (TARGET) on instance {instance_id}..."
    )
    response = main.handler(test_event, {})
    assert response["statusCode"] == 200
    time.sleep(5)

    logger.info("Verifying final state for TARGET path...")
    # Verify tagging
    tags = {
        t["Key"]: t["Value"]
        for t in ec2_client.describe_tags(
            Filters=[{"Name": "resource-id", "Values": [instance_id]}]
        )["Tags"]
    }
    assert "SOAR-Status" in tags
    logger.info("Instance was successfully tagged.")

    # Verify NACL block
    updated_nacl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])[
        "NetworkAcls"
    ][0]
    deny_rules = [
        e
        for e in updated_nacl["Entries"]
        if e["RuleAction"] == "deny" and e["CidrBlock"] == f"{malicious_ip}/32"
    ]
    assert len(deny_rules) == 2
    logger.info(f"Malicious IP {malicious_ip} was successfully blocked.")

    # Verify notifications
    sqs_poller(queue_url=queue_url, expected_count=2)
    logger.info("SNS notifications were successfully verified.")


def test_ec2_brute_force_playbook_e2e_as_source(
    compromised_instance_e2e_setup,
    ssh_brute_force_finding,
    valid_guardduty_event,
    real_app_config,
    mocker,
    sqs_poller,
):
    """
    Tests the 'SOURCE' path, which triggers the full compromise workflow.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")
    iam_client = session.client("iam")
    new_sg_id = None
    instance_id = compromised_instance_e2e_setup[
        "instance_id"
    ]  # Define early for cleanup

    try:
        role_name = compromised_instance_e2e_setup["role_name"]
        queue_url = compromised_instance_e2e_setup["queue_url"]
        vpc_id = compromised_instance_e2e_setup["vpc_id"]

        test_config = replace(real_app_config, allow_terminate=True)
        mocker.patch("guardduty_soar.main.get_config", return_value=test_config)

        test_event = copy.deepcopy(valid_guardduty_event)
        test_event["detail"] = copy.deepcopy(ssh_brute_force_finding)
        test_event["detail"]["Service"]["ResourceRole"] = "SOURCE"
        test_event["detail"]["Resource"]["InstanceDetails"]["InstanceId"] = instance_id
        test_event["detail"]["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
            "VpcId"
        ] = vpc_id

        logger.info(
            f"Starting E2E test for Brute Force (SOURCE) on instance {instance_id}..."
        )
        response = main.handler(test_event, {})
        assert response["statusCode"] == 200

        logger.info("Verifying final state for SOURCE path...")
        time.sleep(5)

        # We need to find the SG ID before the instance is terminated.
        # Describe all SGs in the VPC tagged by the playbook for this finding ID.
        playbook_sgs = ec2_client.describe_security_groups(
            Filters=[
                {"Name": "vpc-id", "Values": [vpc_id]},
                {
                    "Name": "tag:GUARDDUTY-SOAR-ID",
                    "Values": [test_event["detail"]["Id"]],
                },
            ]
        )["SecurityGroups"]
        assert (
            len(playbook_sgs) == 1
        ), "Could not find dynamically created quarantine SG."
        new_sg_id = playbook_sgs[0]["GroupId"]
        logger.info(f"Instance was isolated in new SG {new_sg_id}.")

        # Other assertions from the compromise workflow...
        snapshots = ec2_client.describe_snapshots(
            Filters=[{"Name": "description", "Values": [f"*{instance_id}*"]}]
        )["Snapshots"]
        assert len(snapshots) > 0
        logger.info("Snapshot was successfully created.")

        attached_policies = iam_client.list_attached_role_policies(RoleName=role_name)[
            "AttachedPolicies"
        ]
        attached_arns = [p["PolicyArn"] for p in attached_policies]
        assert "arn:aws:iam::aws:policy/AWSDenyAll" in attached_arns
        logger.info("IAM role was successfully quarantined.")

        # Verify notifications
        sqs_poller(queue_url=queue_url, expected_count=2)
        logger.info("SNS notifications were successfully verified.")

    finally:
        # Cleanup
        if new_sg_id:
            try:
                logger.info("Cleaning up from Brute Force (SOURCE) test...")
                # 1. Wait for the instance to be fully terminated.
                waiter = ec2_client.get_waiter("instance_terminated")
                waiter.wait(InstanceIds=[instance_id])
                logger.info(f"Instance {instance_id} is confirmed terminated.")

                # 2. Now that the instance is gone, the SG dependency is removed.
                ec2_client.delete_security_group(GroupId=new_sg_id)
                logger.info(f"Cleaned up dynamic SG {new_sg_id}.")
            except ClientError as e:
                logger.warning(
                    f"Could not clean up SG {new_sg_id}. Manual cleanup may be required. Error: {e}"
                )
