from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.block import BlockMaliciousIpAction


@pytest.fixture
def port_probe_finding():
    """A mock GuardDuty finding for a port probe event."""
    return {
        "Resource": {
            "InstanceDetails": {"NetworkInterfaces": [{"SubnetId": "subnet-12345678"}]}
        },
        "Service": {
            "Action": {
                "NetworkConnectionAction": {
                    "RemoteIpDetails": {"IpAddressV4": "198.51.100.5"}
                }
            }
        },
    }


def test_get_next_available_rule_number():
    """
    Tests the helper method for finding the next rule number.
    """
    action = BlockMaliciousIpAction(boto3.Session(), MagicMock())

    # Sample NACL entries
    entries = [
        {"RuleNumber": 1, "Egress": False},
        {"RuleNumber": 99, "Egress": False},
        {"RuleNumber": 10, "Egress": True},
        {"RuleNumber": 32767, "Egress": False},  # Should be ignored
    ]

    # Test next inbound (egress=False) rule
    assert action._get_next_available_rule_number(entries, is_egress=False) == 100

    # Test next outbound (egress=True) rule
    assert action._get_next_available_rule_number(entries, is_egress=True) == 11

    # Test with no existing rules
    assert action._get_next_available_rule_number([], is_egress=False) == 1


def test_block_malicious_ip_success(port_probe_finding, mock_app_config):
    """
    Tests the success path where the NACL is found and both deny rules are created.
    """
    ec2_client = boto3.client("ec2")
    action = BlockMaliciousIpAction(boto3.Session(), mock_app_config)
    action.ec2_client = ec2_client  # Inject the client for the stubber

    with Stubber(ec2_client) as stubber:
        # 1. Mock the describe_network_acls call
        describe_filter = [
            {"Name": "association.subnet-id", "Values": ["subnet-12345678"]}
        ]
        describe_response = {
            "NetworkAcls": [
                {
                    "NetworkAclId": "nacl-abcdef12",
                    "Entries": [
                        {"RuleNumber": 50, "Egress": False},  # Existing inbound
                        {"RuleNumber": 20, "Egress": True},  # Existing outbound
                    ],
                }
            ]
        }
        stubber.add_response(
            "describe_network_acls", describe_response, {"Filters": describe_filter}
        )

        # 2. Expect the inbound create_network_acl_entry call
        inbound_params = {
            "NetworkAclId": "nacl-abcdef12",
            "RuleNumber": 51,  # 50 + 1
            "Protocol": "-1",
            "RuleAction": "deny",
            "Egress": False,
            "CidrBlock": "198.51.100.5/32",
        }
        stubber.add_response("create_network_acl_entry", {}, inbound_params)

        # 3. Expect the outbound create_network_acl_entry call
        outbound_params = {
            "NetworkAclId": "nacl-abcdef12",
            "RuleNumber": 21,  # 20 + 1
            "Protocol": "-1",
            "RuleAction": "deny",
            "Egress": True,
            "CidrBlock": "198.51.100.5/32",
        }
        stubber.add_response("create_network_acl_entry", {}, outbound_params)

        # --- Act ---
        result = action.execute(port_probe_finding)

        # --- Assert ---
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

    with Stubber(ec2_client) as stubber:
        stubber.add_response(
            "describe_network_acls",
            {"NetworkAcls": []},
            {
                "Filters": [
                    {"Name": "association.subnet-id", "Values": ["subnet-12345678"]}
                ]
            },
        )

        result = action.execute(port_probe_finding)

        assert result["status"] == "error"
        assert "No network ACL found" in result["details"]


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
