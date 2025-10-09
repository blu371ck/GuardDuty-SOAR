from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.isolate import IsolateInstanceAction


def test_isolate_instance_action_success(guardduty_finding_detail, mock_app_config):
    """
    Tests the IsolateInstanceAction's success path using a botocore Stubber.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]
    quarantine_sg = "sg-quarantine"

    # Set the quarantine_sg_id on the mock config object
    mock_app_config.quarantine_sg_id = quarantine_sg

    expected_params = {"InstanceId": instance_id, "Groups": [quarantine_sg]}
    response = {"ResponseMetadata": {"HTTPStatusCode": 200}}

    stubber.add_response("modify_instance_attribute", response, expected_params)

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = IsolateInstanceAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "success"
        assert f"Successfully isolated instance: {instance_id}." in result["details"]

    stubber.assert_no_pending_responses()


def test_isolate_instance_action_failure(guardduty_finding_detail, mock_app_config):
    """
    Tests the IsolateInstanceAction's failure path when a ClientError occurs.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]
    quarantine_sg = "sg-quarantine"
    mock_app_config.quarantine_sg_id = quarantine_sg

    # Tell the stubber to raise a ClientError when 'modify_instance_attribute' is called.
    stubber.add_client_error(
        "modify_instance_attribute",
        service_error_code="InvalidInstanceID.NotFound",
        service_message="The instance ID does not exist",
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = IsolateInstanceAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "error"
        assert "Failed to isolate instance" in result["details"]
        assert "InvalidInstanceID.NotFound" in result["details"]

    stubber.assert_no_pending_responses()
