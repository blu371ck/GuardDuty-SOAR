import copy

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.block import BlockMaliciousIpAction

# --- Fixtures for different finding types ---


@pytest.fixture
def port_probe_finding_multiple_ips(port_probe_finding):
    """
    Creates a PortProbe finding with multiple probe details, including a duplicate IP,
    to test the multi-IP blocking logic.
    """
    finding = copy.deepcopy(port_probe_finding)
    finding["Service"]["Action"]["PortProbeAction"]["PortProbeDetails"] = [
        {"RemoteIpDetails": {"IpAddressV4": "198.51.100.5"}},
        {"RemoteIpDetails": {"IpAddressV4": "198.51.100.6"}},
        {"RemoteIpDetails": {"IpAddressV4": "198.51.100.5"}},  # Duplicate
    ]
    return finding


@pytest.fixture
def network_connection_finding(guardduty_finding_detail):
    """Creates a finding with a NETWORK_CONNECTION action type."""
    finding = copy.deepcopy(guardduty_finding_detail)
    finding["Service"] = {
        "Action": {
            "ActionType": "NETWORK_CONNECTION",
            "NetworkConnectionAction": {
                "RemoteIpDetails": {"IpAddressV4": "203.0.113.10"}
            },
        }
    }
    return finding


# --- Test Cases ---


def test_block_ip_success_with_port_probe(
    port_probe_finding_multiple_ips, mock_app_config
):
    """
    Tests blocking multiple unique IPs from a single PortProbe finding.
    """
    ec2_client = boto3.client("ec2")
    action = BlockMaliciousIpAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client
    subnet_id = "subnet-99999999"

    with Stubber(ec2_client) as stubber:
        # Expect the initial NACL lookup
        stubber.add_response(
            "describe_network_acls",
            {
                "NetworkAcls": [
                    {"NetworkAclId": "nacl-abcdef12", "Entries": [{"RuleNumber": 50}]}
                ]
            },
            {"Filters": [{"Name": "association.subnet-id", "Values": [subnet_id]}]},
        )

        # Expect rules for the FIRST unique IP (198.51.100.5)
        stubber.add_response(
            "create_network_acl_entry",
            {},
            {
                "NetworkAclId": "nacl-abcdef12",
                "RuleNumber": 51,
                "Egress": False,
                "CidrBlock": "198.51.100.5/32",
                "Protocol": "-1",
                "RuleAction": "deny",
            },
        )
        stubber.add_response(
            "create_network_acl_entry",
            {},
            {
                "NetworkAclId": "nacl-abcdef12",
                "RuleNumber": 52,
                "Egress": True,
                "CidrBlock": "198.51.100.5/32",
                "Protocol": "-1",
                "RuleAction": "deny",
            },
        )

        # Expect rules for the SECOND unique IP (198.51.100.6)
        stubber.add_response(
            "create_network_acl_entry",
            {},
            {
                "NetworkAclId": "nacl-abcdef12",
                "RuleNumber": 53,
                "Egress": False,
                "CidrBlock": "198.51.100.6/32",
                "Protocol": "-1",
                "RuleAction": "deny",
            },
        )
        stubber.add_response(
            "create_network_acl_entry",
            {},
            {
                "NetworkAclId": "nacl-abcdef12",
                "RuleNumber": 54,
                "Egress": True,
                "CidrBlock": "198.51.100.6/32",
                "Protocol": "-1",
                "RuleAction": "deny",
            },
        )

        result = action.execute(port_probe_finding_multiple_ips)
        assert result["status"] == "success"
        assert (
            "Successfully added inbound/outbound deny rules for 2 IP(s)"
            in result["details"]
        )


def test_block_ip_success_with_network_connection(
    network_connection_finding, mock_app_config
):
    """
    Tests blocking a single IP from a NETWORK_CONNECTION finding.
    """
    ec2_client = boto3.client("ec2")
    action = BlockMaliciousIpAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client
    subnet_id = "subnet-99999999"

    with Stubber(ec2_client) as stubber:
        stubber.add_response(
            "describe_network_acls",
            {
                "NetworkAcls": [
                    {"NetworkAclId": "nacl-abcdef12", "Entries": [{"RuleNumber": 1}]}
                ]
            },
            {"Filters": [{"Name": "association.subnet-id", "Values": [subnet_id]}]},
        )
        stubber.add_response(
            "create_network_acl_entry",
            {},
            {
                "NetworkAclId": "nacl-abcdef12",
                "RuleNumber": 2,
                "Egress": False,
                "CidrBlock": "203.0.113.10/32",
                "Protocol": "-1",
                "RuleAction": "deny",
            },
        )
        stubber.add_response(
            "create_network_acl_entry",
            {},
            {
                "NetworkAclId": "nacl-abcdef12",
                "RuleNumber": 3,
                "Egress": True,
                "CidrBlock": "203.0.113.10/32",
                "Protocol": "-1",
                "RuleAction": "deny",
            },
        )

        result = action.execute(network_connection_finding)
        assert result["status"] == "success"
        assert (
            "Successfully added inbound/outbound deny rules for 1 IP(s)"
            in result["details"]
        )


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
