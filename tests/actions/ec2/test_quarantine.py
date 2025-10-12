from datetime import datetime
from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.quarantine import QuarantineInstanceProfileAction


def test_quarantine_action_success(
    finding_with_profile, mock_app_config_with_deny_policy
):
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
    deny_policy_arn = mock_app_config_with_deny_policy.iam_deny_all_policy_arn

    describe_instances_response = {
        "Reservations": [{"Instances": [{"IamInstanceProfile": {"Arn": profile_arn}}]}]
    }
    ec2_stubber.add_response(
        "describe_instances",
        describe_instances_response,
        {"InstanceIds": [instance_id]},
    )

    # Use a complete mock response with valid placeholder IDs
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
    iam_stubber.add_response(
        "attach_role_policy", {}, {"RoleName": role_name, "PolicyArn": deny_policy_arn}
    )

    with ec2_stubber, iam_stubber:
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda service_name: {
            "ec2": ec2_client,
            "iam": iam_client,
        }[service_name]
        action = QuarantineInstanceProfileAction(
            mock_session, mock_app_config_with_deny_policy
        )
        result = action.execute(finding_with_profile)

        assert result["status"] == "success"

    ec2_stubber.assert_no_pending_responses()
    iam_stubber.assert_no_pending_responses()


def test_quarantine_skips_if_no_instance_profile(
    guardduty_finding_detail, mock_app_config
):
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    describe_instances_response = {
        "Reservations": [{"Instances": [{"InstanceId": instance_id}]}]
    }
    stubber.add_response(
        "describe_instances",
        describe_instances_response,
        {"InstanceIds": [instance_id]},
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client
        action = QuarantineInstanceProfileAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "success"
        assert "has no IAM instance profile. Skipping" in result["details"]

    stubber.assert_no_pending_responses()


def test_quarantine_fails_on_attach_policy_error(
    finding_with_profile, mock_app_config_with_deny_policy
):
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

    ec2_stubber.add_response(
        "describe_instances",
        {
            "Reservations": [
                {"Instances": [{"IamInstanceProfile": {"Arn": profile_arn}}]}
            ]
        },
        {"InstanceIds": [instance_id]},
    )

    # Use the same complete mock response here as well
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
    iam_stubber.add_client_error("attach_role_policy", "AccessDenied")

    with ec2_stubber, iam_stubber:
        mock_session = MagicMock()
        mock_session.client.side_effect = lambda service_name: {
            "ec2": ec2_client,
            "iam": iam_client,
        }[service_name]
        action = QuarantineInstanceProfileAction(
            mock_session, mock_app_config_with_deny_policy
        )
        result = action.execute(finding_with_profile)

        assert result["status"] == "error"
        assert "AccessDenied" in result["details"]

    ec2_stubber.assert_no_pending_responses()
    iam_stubber.assert_no_pending_responses()
