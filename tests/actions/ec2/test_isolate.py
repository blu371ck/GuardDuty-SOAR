import copy
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import ANY, Stubber

from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction


@pytest.fixture
def finding_with_vpc(guardduty_finding_detail):
    """Adds a VpcId to the base finding fixture for these tests."""
    finding = copy.deepcopy(guardduty_finding_detail)
    finding["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
        "VpcId"
    ] = "vpc-12345"
    return finding


def test_isolate_action_success(finding_with_vpc, mock_app_config):
    """
    Tests the full, successful execution path of the dynamic isolation action.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    instance_id = finding_with_vpc["Resource"]["InstanceDetails"]["InstanceId"]
    vpc_id = finding_with_vpc["Resource"]["InstanceDetails"]["NetworkInterfaces"][0][
        "VpcId"
    ]
    new_sg_id = "sg-newly-created"

    # 1. Expect the call to create the security group, now including TagSpecifications
    create_sg_params = {
        "GroupName": ANY,
        "Description": ANY,
        "VpcId": vpc_id,
        "TagSpecifications": ANY,
    }
    create_sg_response = {"GroupId": new_sg_id}
    stubber.add_response("create_security_group", create_sg_response, create_sg_params)

    # 2. Expect the call to revoke the default egress rule (this is unchanged)
    stubber.add_response(
        "revoke_security_group_egress",
        {},
        {
            "GroupId": new_sg_id,
            "IpPermissions": [
                {"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
            ],
        },
    )

    # 3. Expect the final call to modify the instance's security groups (this is unchanged)
    stubber.add_response(
        "modify_instance_attribute",
        {},
        {"InstanceId": instance_id, "Groups": [new_sg_id]},
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = IsolateInstanceAction(mock_session, mock_app_config)
        result = action.execute(finding_with_vpc)

        assert result["status"] == "success"
        assert f"applying new security group {new_sg_id}" in result["details"]

    stubber.assert_no_pending_responses()


def test_isolate_action_fails_on_create_sg(finding_with_vpc, mock_app_config):
    """
    Tests that the action fails gracefully if the create_security_group call fails.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    stubber.add_client_error("create_security_group", "VpcLimitExceeded")

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = IsolateInstanceAction(mock_session, mock_app_config)
        result = action.execute(finding_with_vpc)

        assert result["status"] == "error"
        assert "Failed to isolate instance" in result["details"]
        assert "VpcLimitExceeded" in result["details"]

    stubber.assert_no_pending_responses()


def test_isolate_action_fails_with_missing_vpc_id(
    guardduty_finding_detail, mock_app_config
):
    """
    Tests that the action returns an error if the finding is missing the VpcId.
    """
    # Use the base fixture which does not have a VpcId
    malformed_finding = guardduty_finding_detail

    action = IsolateInstanceAction(MagicMock(), mock_app_config)
    result = action.execute(malformed_finding)

    assert result["status"] == "error"
    assert "No VPC ID found" in result["details"]
