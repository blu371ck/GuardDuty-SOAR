from datetime import datetime
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.quarantine import QuarantineInstanceProfileAction


@pytest.fixture
def finding_with_profile(guardduty_finding_detail):
    """Adds a mock IamInstanceProfile to the base finding."""
    finding = guardduty_finding_detail.copy()
    finding["Resource"]["InstanceDetails"]["IamInstanceProfile"] = {
        "Arn": "arn:aws:iam::123456789012:instance-profile/test-instance-profile"
    }
    return finding


def test_quarantine_action_success(finding_with_profile, mock_app_config):
    """
    Tests the successful execution path where the AWS managed 'AWSDenyAll'
    policy is attached to the role.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    iam_client = boto3.client("iam", region_name="us-east-1")
    ec2_stubber = Stubber(ec2_client)
    iam_stubber = Stubber(iam_client)

    instance_id = finding_with_profile["Resource"]["InstanceDetails"]["InstanceId"]
    profile_arn = finding_with_profile["Resource"]["InstanceDetails"][
        "IamInstanceProfile"
    ]["Arn"]
    profile_name = "test-instance-profile"
    role_name = "test-ec2-role"
    # The action now uses the hardcoded AWS managed policy ARN
    deny_policy_arn = "arn:aws:iam::aws:policy/AWSDenyAll"
    mock_app_config.iam_deny_all_policy_arn = deny_policy_arn

    # 1. Expect a call to describe_instances
    describe_instances_response = {
        "Reservations": [{"Instances": [{"IamInstanceProfile": {"Arn": profile_arn}}]}]
    }
    ec2_stubber.add_response(
        "describe_instances",
        describe_instances_response,
        {"InstanceIds": [instance_id]},
    )

    # 2. Expect a call to get_instance_profile
    get_profile_response = {
        "InstanceProfile": {
            "Path": "/",
            "InstanceProfileName": profile_name,
            "InstanceProfileId": "AIPAJ55O33A3EXAMPLE",
            "Arn": profile_arn,
            "CreateDate": datetime(2025, 1, 1),
            "Roles": [
                {
                    "Path": "/",
                    "RoleName": role_name,
                    "RoleId": "AROA1234567890ABCDE",
                    "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
                    "CreateDate": datetime(2025, 1, 1),
                    "AssumeRolePolicyDocument": "{}",
                }
            ],
        }
    }
    iam_stubber.add_response(
        "get_instance_profile",
        get_profile_response,
        {"InstanceProfileName": profile_name},
    )

    # 3. Expect a call to attach_role_policy with the correct ARN
    iam_stubber.add_response(
        "attach_role_policy", {}, {"RoleName": role_name, "PolicyArn": deny_policy_arn}
    )

    with ec2_stubber, iam_stubber:
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda service_name: {
            "ec2": ec2_client,
            "iam": iam_client,
        }[service_name]

        # Pass the standard mock_app_config
        action = QuarantineInstanceProfileAction(mock_session, mock_app_config)
        result = action.execute(finding_with_profile)

        assert result["status"] == "success"

    ec2_stubber.assert_no_pending_responses()
    iam_stubber.assert_no_pending_responses()


def test_quarantine_fails_on_attach_policy_error(finding_with_profile, mock_app_config):
    """
    Tests that the action fails gracefully if the attach_role_policy call fails.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    iam_client = boto3.client("iam", region_name="us-east-1")
    ec2_stubber = Stubber(ec2_client)
    iam_stubber = Stubber(iam_client)

    instance_id = finding_with_profile["Resource"]["InstanceDetails"]["InstanceId"]
    profile_arn = finding_with_profile["Resource"]["InstanceDetails"][
        "IamInstanceProfile"
    ]["Arn"]
    profile_name = "test-instance-profile"
    role_name = "test-ec2-role"
    mock_app_config.iam_deny_all_policy_arn = "arn:aws:iam::aws:policy/AWSDenyAll"

    # Mock the successful describe and get calls
    ec2_stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [{"IamInstanceProfile": {"Arn": profile_arn}}]}
            ]
        },
        {"InstanceIds": [instance_id]},
    )

    get_profile_response = {
        "InstanceProfile": {
            "Path": "/",
            "InstanceProfileName": profile_name,
            "InstanceProfileId": "AIPAJ55O33A3EXAMPLE",
            "Arn": profile_arn,
            "CreateDate": datetime(2025, 1, 1),
            "Roles": [
                {
                    "Path": "/",
                    "RoleName": role_name,
                    "RoleId": "AROA1234567890ABCDE",
                    "Arn": f"arn:aws:iam::123456789012:role/{role_name}",
                    "CreateDate": datetime(2025, 1, 1),
                    "AssumeRolePolicyDocument": "{}",
                }
            ],
        }
    }
    iam_stubber.add_response(
        "get_instance_profile",
        get_profile_response,
        {"InstanceProfileName": profile_name},
    )

    # Mock a client error on the final attach call
    iam_stubber.add_client_error("attach_role_policy", "AccessDenied")

    with ec2_stubber, iam_stubber:
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda service_name: {
            "ec2": ec2_client,
            "iam": iam_client,
        }[service_name]

        # Pass the standard mock_app_config
        action = QuarantineInstanceProfileAction(mock_session, mock_app_config)
        result = action.execute(finding_with_profile)

        assert result["status"] == "error"
        assert "AccessDenied" in result["details"]

    ec2_stubber.assert_no_pending_responses()
    iam_stubber.assert_no_pending_responses()
