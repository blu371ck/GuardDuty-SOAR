from unittest.mock import MagicMock

import boto3
import pytest
from botocore.exceptions import ClientError
from botocore.stub import ANY, Stubber

from guardduty_soar.actions.ec2.snapshot import CreateSnapshotAction


def test_snapshot_action_success_multiple_volumes(
    guardduty_finding_detail, mock_app_config
):
    """
    Tests the success path where an instance has multiple EBS volumes and all snapshots are created.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # --- Mock describe_instances call ---
    describe_response = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "BlockDeviceMappings": [
                            {"Ebs": {"VolumeId": "vol-1111"}},
                            {"Ebs": {"VolumeId": "vol-2222"}},
                        ]
                    }
                ]
            }
        ]
    }
    stubber.add_response(
        "describe_instances", describe_response, {"InstanceIds": [instance_id]}
    )

    # --- Mock create_snapshot calls for EACH volume ---
    snapshot_response_1 = {"SnapshotId": "snap-1111"}
    snapshot_response_2 = {"SnapshotId": "snap-2222"}

    stubber.add_response(
        "create_snapshot",
        snapshot_response_1,
        {"VolumeId": "vol-1111", "Description": ANY, "TagSpecifications": ANY},
    )
    stubber.add_response(
        "create_snapshot",
        snapshot_response_2,
        {"VolumeId": "vol-2222", "Description": ANY, "TagSpecifications": ANY},
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = CreateSnapshotAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "success"
        assert "Successfully created snapshots for all volumes" in result["details"]

    stubber.assert_no_pending_responses()


def test_snapshot_action_no_volumes(guardduty_finding_detail, mock_app_config):
    """
    Tests the graceful exit path where the instance has no EBS volumes.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # Mock describe_instances to return an instance with no block devices
    describe_response = {"Reservations": [{"Instances": [{"BlockDeviceMappings": []}]}]}
    stubber.add_response(
        "describe_instances", describe_response, {"InstanceIds": [instance_id]}
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = CreateSnapshotAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "success"
        assert "no EBS volumes attached" in result["details"]

    stubber.assert_no_pending_responses()


def test_snapshot_action_describe_failure(guardduty_finding_detail, mock_app_config):
    """
    Tests the graceful exit path where the describe_instances call fails.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # Mock describe_instances to return an error
    stubber.add_client_error("describe_instances", "InvalidInstanceID.NotFound")

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = CreateSnapshotAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        # This is still a "success" for the playbook, as there's no action to take.
        assert result["status"] == "success"
        assert "could not be described" in result["details"]

    stubber.assert_no_pending_responses()


def test_snapshot_action_partial_failure(guardduty_finding_detail, mock_app_config):
    """
    Tests the case where one snapshot succeeds and another fails.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # Mock describe_instances call with two volumes
    describe_response = {
        "Reservations": [
            {
                "Instances": [
                    {
                        "BlockDeviceMappings": [
                            {"Ebs": {"VolumeId": "vol-1111"}},
                            {"Ebs": {"VolumeId": "vol-2222"}},
                        ]
                    }
                ]
            }
        ]
    }
    stubber.add_response(
        "describe_instances", describe_response, {"InstanceIds": [instance_id]}
    )

    # Mock a success for the first snapshot
    stubber.add_response(
        "create_snapshot",
        {"SnapshotId": "snap-1111"},
        {"VolumeId": "vol-1111", "Description": ANY, "TagSpecifications": ANY},
    )
    # Mock a failure for the second snapshot
    stubber.add_client_error("create_snapshot", "SnapshotLimitExceeded")

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = CreateSnapshotAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        # The overall status should be 'error' if any snapshot fails
        assert result["status"] == "error"
        assert "Succeeded for volumes: ['vol-1111']" in result["details"]
        assert "Failed for volumes: ['vol-2222']" in result["details"]

    stubber.assert_no_pending_responses()
