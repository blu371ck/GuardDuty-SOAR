import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.block import BlockMaliciousIpAction


def test_block_malicious_ip_success(port_probe_finding, mock_app_config):
    """
    Tests the success path where the NACL is found and both deny rules are created.
    """
    ec2_client = boto3.client("ec2")
    action = BlockMaliciousIpAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client

    # Get the subnet_id from the fixture itself.
    subnet_id = port_probe_finding["Resource"]["InstanceDetails"]["NetworkInterfaces"][
        0
    ]["SubnetId"]

    with Stubber(ec2_client) as stubber:
        # Use the dynamic subnet_id in the filter
        describe_filter = [{"Name": "association.subnet-id", "Values": [subnet_id]}]
        describe_response = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "nacl-abcdef12",
                    "Entries": [{"RuleNumber": 50, "Egress": False}],
                }
            ]
        }
        stubber.add_response(
            "describe_network_acls", describe_response, {"Filters": describe_filter}
        )

        # Expect the inbound create_network_acl_entry call
        inbound_params = {
            "NetworkAclId": "nacl-abcdef12",
            "RuleNumber": 51,  # 50 + 1
            "Protocol": "-1",
            "RuleAction": "deny",
            "Egress": False,
            "CidrBlock": "198.51.100.5/32",
        }
        stubber.add_response("create_network_acl_entry", {}, inbound_params)

        # Expect the outbound create_network_acl_entry call
        outbound_params = {
            "NetworkAclId": "nacl-abcdef12",
            "RuleNumber": 52,  # 50 + 2
            "Protocol": "-1",
            "RuleAction": "deny",
            "Egress": True,
            "CidrBlock": "198.51.100.5/32",
        }
        stubber.add_response("create_network_acl_entry", {}, outbound_params)

        result = action.execute(port_probe_finding)

        assert result["status"] == "success"
        assert "Successfully added" in result["details"]
        stubber.assert_no_pending_responses()


def test_block_malicious_ip_no_nacl_found(port_probe_finding, mock_app_config):
    """
    Tests the failure path where no NACL is associated with the subnet.
    """
    ec2_client = boto3.client("ec2")
    action = BlockMaliciousIpAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client

    # Get the subnet_id from the fixture itself.
    subnet_id = port_probe_finding["Resource"]["InstanceDetails"]["NetworkInterfaces"][
        0
    ]["SubnetId"]

    with Stubber(ec2_client) as stubber:
        expected_params = {
            "Filters": [{"Name": "association.subnet-id", "Values": [subnet_id]}]
        }
        stubber.add_response(
            "describe_network_acls", {"NetworkAcls": []}, expected_params
        )

        result = action.execute(port_probe_finding)

        assert result["status"] == "error"


def test_block_malicious_ip_client_error(port_probe_finding, mock_app_config):
    """
    Tests that a ClientError from a Boto3 call is handled gracefully.
    """
    ec2_client = boto3.client("ec2")
    action = BlockMaliciousIpAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client

    with Stubber(ec2_client) as stubber:
        stubber.add_client_error(
            "describe_network_acls", service_error_code="AccessDenied"
        )

        result = action.execute(port_probe_finding)

        assert result["status"] == "error"
        assert "AccessDenied" in result["details"]
