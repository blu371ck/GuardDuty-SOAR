import logging
import time

import boto3
import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.ec2.block import BlockMaliciousIpAction
from guardduty_soar.actions.ec2.enrich import EnrichFindingWithInstanceMetadataAction
from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction
from guardduty_soar.actions.ec2.remove import RemovePublicAccessAction
from guardduty_soar.actions.ec2.snapshot import CreateSnapshotAction
from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.actions.ec2.terminate import TerminateInstanceAction

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)


def test_tag_instance_action_integration(
    temporary_ec2_instance, guardduty_finding_detail, real_app_config
):
    """Tests the TagInstanceAction against a temporary EC2 instance."""
    instance_id = temporary_ec2_instance["instance_id"]
    guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

    session = boto3.Session()
    action = TagInstanceAction(session, real_app_config)
    result = action.execute(
        guardduty_finding_detail, playbook_name="IntegrationTestPlaybook"
    )

    assert result["status"] == "success"
    time.sleep(2)  # Allow tags to propagate

    ec2_client = session.client("ec2")
    tags = {
        t["Key"]: t["Value"]
        for t in ec2_client.describe_tags(
            Filters=[{"Name": "resource-id", "Values": [instance_id]}]
        )["Tags"]
    }
    assert "SOAR-Status" in tags and tags["SOAR-Status"] == "Remediation-In-Progress"


def test_isolate_instance_action_integration(
    temporary_ec2_instance, guardduty_finding_detail, real_app_config
):
    """Tests the IsolateInstanceAction."""
    quarantine_sg_id = temporary_ec2_instance["quarantine_sg_id"]

    # Create a mutable copy of the config and set the quarantine ID for this test
    from dataclasses import replace

    test_config = replace(real_app_config, quarantine_sg_id=quarantine_sg_id)

    instance_id = temporary_ec2_instance["instance_id"]
    guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

    session = boto3.Session()
    action = IsolateInstanceAction(session, test_config)  # Use the modified config
    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"

    ec2_client = session.client("ec2")
    instance = ec2_client.describe_instances(InstanceIds=[instance_id])["Reservations"][
        0
    ]["Instances"][0]
    attached_sgs = [sg["GroupId"] for sg in instance["SecurityGroups"]]
    assert attached_sgs == [quarantine_sg_id]


def test_create_snapshot_action_integration(
    temporary_ec2_instance, guardduty_finding_detail, real_app_config, aws_region
):
    """Tests the CreateSnapshotAction against a temporary EC2 instance."""
    ec2_client = boto3.client("ec2", region_name=aws_region)
    instance_id = temporary_ec2_instance["instance_id"]
    guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

    session = boto3.Session()
    action = CreateSnapshotAction(session, real_app_config)

    created_snapshot_ids = []

    try:
        result = action.execute(guardduty_finding_detail)

        assert (
            result["status"] == "success"
        ), f"Action failed with details: {result['details']}"
        assert "Successfully created snapshots" in result["details"]

        time.sleep(5)

        response = ec2_client.describe_snapshots(
            Filters=[
                {
                    "Name": "tag:GuardDuty-SOAR-Source-Instance-ID",
                    "Values": [instance_id],
                }
            ]
        )

        snapshots = response.get("Snapshots", [])
        assert len(snapshots) >= 1, "No snapshot was found with the expected tags."

        created_snapshot_ids = [s["SnapshotId"] for s in snapshots]

    finally:
        # -- Teardown with waiter --
        if not created_snapshot_ids:
            logger.info("No snapshots to clean up.")
            return

        logger.info(
            f"Cleaning up snapshots: {created_snapshot_ids}. Waiting for completion..."
        )
        try:
            waiter = ec2_client.get_waiter("snapshot_completed")
            waiter.wait(SnapshotIds=created_snapshot_ids)
            logger.info("Snapshots are complete. Proceeding with deletion.")

            for snapshot_id in created_snapshot_ids:
                ec2_client.delete_snapshot(SnapshotId=snapshot_id)
                logger.info(f"Deleted snapshot: {snapshot_id}.")
        except ClientError as e:
            logger.info(
                f"Could not clean up snapshots. Manual cleanup may be required. Error: {e}."
            )


def test_enrich_finding_action_integration(
    temporary_ec2_instance, guardduty_finding_detail, real_app_config
):
    """Tests the EnrichFindingWithInstanceMetadataAction against a live instance."""
    instance_id = temporary_ec2_instance["instance_id"]
    guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

    session = boto3.Session()
    action = EnrichFindingWithInstanceMetadataAction(session, real_app_config)
    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    enriched_finding = result["details"]
    assert enriched_finding["instance_metadata"]["InstanceId"] == instance_id
    assert "VpcId" in enriched_finding["instance_metadata"]


def test_terminate_instance_action_integration(
    temporary_ec2_instance, guardduty_finding_detail, real_app_config
):
    """Tests the TerminateInstanceAction against a temporary EC2 instance."""
    instance_id = temporary_ec2_instance["instance_id"]
    guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

    from dataclasses import replace

    test_config = replace(real_app_config, allow_terminate=True)

    session = boto3.Session()
    action = TerminateInstanceAction(session, test_config)  # Use the modified config
    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"


@pytest.fixture
def temporary_sg_with_public_rule(temporary_ec2_instance):
    """Takes a temporary EC2 instance and adds a public rule to its security group."""
    ec2_client = boto3.client("ec2")
    sg_id = temporary_ec2_instance["default_sg_id"]

    ec2_client.authorize_security_group_ingress(
        GroupId=sg_id,
        IpPermissions=[
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    )
    temporary_ec2_instance["sg_id"] = sg_id
    yield temporary_ec2_instance


def test_remove_public_access_integration(
    temporary_sg_with_public_rule, guardduty_finding_detail, real_app_config
):
    """Tests that RemovePublicAccessAction can successfully find and revoke a public rule."""
    instance_id = temporary_sg_with_public_rule["instance_id"]
    sg_id = temporary_sg_with_public_rule["sg_id"]
    finding = guardduty_finding_detail
    finding["Resource"]["InstanceDetails"]["InstanceId"] = instance_id

    session = boto3.Session()
    action = RemovePublicAccessAction(session, real_app_config)
    result = action.execute(finding)

    assert result["status"] == "success"
    assert f"Removed 1 public rule(s) from {sg_id}" in result["details"]

    ec2_client = session.client("ec2")
    updated_sg = ec2_client.describe_security_groups(GroupIds=[sg_id])[
        "SecurityGroups"
    ][0]
    is_still_public = any(
        r.get("CidrIp") == "0.0.0.0/0"
        for p in updated_sg.get("IpPermissions", [])
        for r in p.get("IpRanges", [])
    )
    assert not is_still_public


@pytest.fixture
def temporary_nacl(temporary_vpc):
    """Takes a temporary VPC and identifies its default NACL."""
    ec2_client = boto3.client("ec2")
    vpc_id = temporary_vpc["vpc_id"]
    nacl = ec2_client.describe_network_acls(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "default", "Values": ["true"]},
        ]
    )["NetworkAcls"][0]

    resources = {**temporary_vpc, "nacl_id": nacl["NetworkAclId"]}
    yield resources


def test_block_malicious_ip_integration(
    port_probe_finding, temporary_nacl, real_app_config
):
    """Tests that BlockMaliciousIpAction can add deny rules to a NACL."""
    subnet_id = temporary_nacl["subnet_id"]
    nacl_id = temporary_nacl["nacl_id"]
    malicious_ip = "198.51.100.25"

    finding = port_probe_finding
    finding["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
        "SubnetId"
    ] = subnet_id
    finding["Service"]["Action"]["NetworkConnectionAction"]["RemoteIpDetails"][
        "IpAddressV4"
    ] = malicious_ip

    session = boto3.Session()
    action = BlockMaliciousIpAction(session, real_app_config)
    result = action.execute(finding)

    assert result["status"] == "success"

    ec2_client = session.client("ec2")
    updated_nacl = ec2_client.describe_network_acls(NetworkAclIds=[nacl_id])[
        "NetworkAcls"
    ][0]
    new_rules = [
        e
        for e in updated_nacl["Entries"]
        if e["RuleAction"] == "deny" and e["CidrBlock"] == f"{malicious_ip}/32"
    ]
    assert len(new_rules) == 2
