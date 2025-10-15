from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.terminate import TerminateInstanceAction


def test_terminate_action_success(guardduty_finding_detail, mock_app_config):
    """
    Tests the success path where termination is enabled and the API call succeeds.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    mock_app_config.allow_terminate = True
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    expected_params = {"InstanceIds": [instance_id]}
    response = {"TerminatingInstances": [{"InstanceId": instance_id}]}

    stubber.add_response("terminate_instances", response, expected_params)

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = TerminateInstanceAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "success"
        assert (
            f"Successfully initiated termination for instance {instance_id}"
            in result["details"]
        )

    stubber.assert_no_pending_responses()


def test_terminate_action_disabled_in_config(guardduty_finding_detail, mock_app_config):
    """
    Tests the safety-check path where termination is disabled in the config.
    Ensures no AWS API call is made.
    """
    mock_app_config.allow_terminate = False

    # Create a mock for the ec2_client that will be created in __init__
    mock_ec2_client = MagicMock()

    # Create a mock session that returns our mock client
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client

    action = TerminateInstanceAction(mock_session, mock_app_config)
    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "skipped"
    assert "Termination is disabled" in result["details"]

    # Assert that the 'terminate_instances' method on the client was never called.
    mock_ec2_client.terminate_instances.assert_not_called()


def test_terminate_action_api_failure(guardduty_finding_detail, mock_app_config):
    """
    Tests the failure path where the terminate_instances call raises a ClientError.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    mock_app_config.allow_terminate = True

    stubber.add_client_error(
        "terminate_instances",
        service_error_code="InvalidInstanceID.NotFound",
        service_message="The instance ID does not exist",
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = TerminateInstanceAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "error"
        assert "Failed to terminate instance" in result["details"]
        assert "InvalidInstanceID.NotFound" in result["details"]

    stubber.assert_no_pending_responses()
