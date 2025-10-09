from unittest.mock import MagicMock

import boto3
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.remove import RemovePublicAccessAction


def test_remove_public_access_success(guardduty_finding_detail, mock_app_config):
    """
    Tests the success path where a public IPv4 rule is found and revoked.
    """
    mock_app_config.allow_remove_public_access = True
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]
    sg_id = "sg-1234567890abcdef0"

    ec2_client = boto3.client("ec2")
    action = RemovePublicAccessAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client  # Inject client for stubber

    public_rule = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    private_rule = {
        "IpProtocol": "tcp",
        "FromPort": 80,
        "ToPort": 80,
        "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
    }

    with Stubber(ec2_client) as stubber:
        # 1. Mock the describe_instances call
        stubber.add_response(
            "describe_instances",
            {
                "Reservations": [
                    {"Instances": [{"SecurityGroups": [{"GroupId": sg_id}]}]}
                ]
            },
            {"InstanceIds": [instance_id]},
        )
        # 2. Mock the describe_security_groups call
        stubber.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {"GroupId": sg_id, "IpPermissions": [public_rule, private_rule]}
                ]
            },
            {"GroupIds": [sg_id]},
        )
        # 3. Expect the revoke_security_group_ingress call with ONLY the public rule
        stubber.add_response(
            "revoke_security_group_ingress",
            {},
            {"GroupId": sg_id, "IpPermissions": [public_rule]},
        )

        result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    assert f"Removed 1 public rule(s) from {sg_id}" in result["details"]


def test_remove_public_access_no_public_rules(
    guardduty_finding_detail, mock_app_config
):
    """
    Tests the path where no public rules are found on the security group.
    """
    mock_app_config.allow_remove_public_access = True
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]
    sg_id = "sg-1234567890abcdef0"
    ec2_client = boto3.client("ec2")
    action = RemovePublicAccessAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client

    private_rule = {
        "IpProtocol": "tcp",
        "FromPort": 80,
        "ToPort": 80,
        "IpRanges": [{"CidrIp": "10.0.0.0/16"}],
    }

    with Stubber(ec2_client) as stubber:
        stubber.add_response(
            "describe_instances",
            {
                "Reservations": [
                    {"Instances": [{"SecurityGroups": [{"GroupId": sg_id}]}]}
                ]
            },
            {"InstanceIds": [instance_id]},
        )
        stubber.add_response(
            "describe_security_groups",
            {"SecurityGroups": [{"GroupId": sg_id, "IpPermissions": [private_rule]}]},
            {"GroupIds": [sg_id]},
        )

        # The revoke call is NOT expected to happen
        result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    assert "No public access rules found to remove" in result["details"]


def test_remove_public_access_ipv6_and_ipv4(guardduty_finding_detail, mock_app_config):
    """
    Tests that both public IPv4 and IPv6 rules are correctly identified and revoked.
    """
    mock_app_config.allow_remove_public_access = True
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]
    sg_id = "sg-1234567890abcdef0"
    ec2_client = boto3.client("ec2")
    action = RemovePublicAccessAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client

    public_rule_ipv4 = {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
    }
    public_rule_ipv6 = {
        "IpProtocol": "tcp",
        "FromPort": 443,
        "ToPort": 443,
        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
    }

    with Stubber(ec2_client) as stubber:
        stubber.add_response(
            "describe_instances",
            {
                "Reservations": [
                    {"Instances": [{"SecurityGroups": [{"GroupId": sg_id}]}]}
                ]
            },
            {"InstanceIds": [instance_id]},
        )
        stubber.add_response(
            "describe_security_groups",
            {
                "SecurityGroups": [
                    {
                        "GroupId": sg_id,
                        "IpPermissions": [public_rule_ipv4, public_rule_ipv6],
                    }
                ]
            },
            {"GroupIds": [sg_id]},
        )

        # Expect the revoke call with BOTH public rules
        stubber.add_response(
            "revoke_security_group_ingress",
            {},
            {"GroupId": sg_id, "IpPermissions": [public_rule_ipv4, public_rule_ipv6]},
        )

        result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    assert f"Removed 2 public rule(s) from {sg_id}" in result["details"]


def test_remove_public_access_disabled_by_config(
    guardduty_finding_detail, mock_app_config
):
    """
    Tests that the action is skipped if disabled in the configuration
    """

    mock_app_config.allow_remove_public_access = False
    mock_session = MagicMock()
    action = RemovePublicAccessAction(mock_session, mock_app_config)

    result = action.execute(guardduty_finding_detail)

    # Disabled actions return successful responses
    assert result["status"] == "success"
    assert "disabled in config" in result["details"]
    mock_session.client_assert_not_called()
