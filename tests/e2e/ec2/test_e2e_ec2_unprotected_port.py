import copy
import json
import logging
import time

import boto3
import pytest

from guardduty_soar.main import handler

pytestmark = pytest.mark.e2e


logger = logging.getLogger(__name__)


def test_ec2_unprotected_port_playbook_e2e(
    temporary_sg_with_public_rule,
    port_probe_finding,
    valid_guardduty_event,
    e2e_notification_channel,
    real_app_config,
    sqs_poller,
):
    """
    Tests the full EC2 Unprotected Port playbook, verifying that a malicious IP
    is blocked in the NACL and the public security group rule is removed.
    """
    session = boto3.Session()
    ec2_client = session.client("ec2")

    # Get resource IDs from our fixtures
    test_resources = temporary_sg_with_public_rule
    instance_id = test_resources["instance_id"]
    sg_id = test_resources["sg_id"]
    subnet_id = test_resources["subnet_id"]
    vpc_id = test_resources["vpc_id"]
    queue_url = e2e_notification_channel["queue_url"]
    malicious_ip = "198.51.100.25"

    # Find the default NACL for the VPC
    nacl = ec2_client.describe_network_acls(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "default", "Values": ["true"]},
        ]
    )["NetworkAcls"][0]
    nacl_id = nacl["NetworkAclId"]

    # Create the test event
    test_event = copy.deepcopy(valid_guardduty_event)
    test_event["detail"] = copy.deepcopy(port_probe_finding)
    test_event["detail"]["Resource"]["InstanceDetails"]["InstanceId"] = instance_id
    test_event["detail"]["Resource"]["InstanceDetails"]["NetworkInterfaces"][0]["SubnetId"] = subnet_id
    
    # --- CORRECTED LINE ---
    # Use the correct path for a PortProbeAction finding
    test_event["detail"]["Service"]["Action"]["PortProbeAction"]["PortProbeDetails"][0]["RemoteIpDetails"]["IpAddressV4"] = malicious_ip

    logger.info(
        f"Starting E2E test for Unprotected Port Playbook on instance {instance_id}..."
    )
    response = handler(test_event, {})
    assert response["statusCode"] == 200

    time.sleep(5)
    logger.info("Verifying final state...")

    # Verify the malicious IP was blocked in the NACL
    updated_nacl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])["NetworkAcls"][0]
    new_deny_rules = [
        e
        for e in updated_nacl["Entries"]
        if e["RuleAction"] == "deny" and e["CidrBlock"] == f"{malicious_ip}/32"
    ]
    assert len(new_deny_rules) == 2, "Expected to find 2 new NACL deny rules"
    logger.info(f"Malicious IP {malicious_ip} was successfully blocked in NACL {nacl_id}.")

    # Verify the public rule was removed from the Security Group
    updated_sg = ec2_client.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    is_still_public = any(
        r.get("CidrIp") == "0.0.0.0/0"
        for p in updated_sg.get("IpPermissions", [])
        for r in p.get("IpRanges", [])
    )
    assert not is_still_public, "Public rule was not removed from the security group."
    logger.info(f"Public access rule was successfully removed from SG {sg_id}.")

    # Verify SNS notifications were sent
    all_messages = sqs_poller(queue_url=queue_url, expected_count=2)
    logger.info("SNS notifications were successfully verified via SQS.")
