from unittest.mock import MagicMock

import boto3
import pytest
from botocore.stub import Stubber

from guardduty_soar.actions.ec2.enrich import EnrichFindingWithInstanceMetadataAction
from guardduty_soar.models import EnrichedEC2Finding


def test_enrich_action_success(guardduty_finding_detail, mock_app_config):
    """
    Tests the success path where describe_instances returns valid metadata.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # This is a sample of the rich metadata returned by the real API call
    mock_instance_metadata = {
        "InstanceId": instance_id,
        "VpcId": "vpc-12345678",
        "SubnetId": "subnet-87654321",
        "Tags": [{"Key": "Name", "Value": "MyWebServer"}],
    }

    describe_response = {"Reservations": [{"Instances": [mock_instance_metadata]}]}
    stubber.add_response(
        "describe_instances", describe_response, {"InstanceIds": [instance_id]}
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = EnrichFindingWithInstanceMetadataAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "success"

        # Verify the structure of the enriched finding in the details
        enriched_finding: EnrichedEC2Finding = result["details"]
        assert enriched_finding["guardduty_finding"] == guardduty_finding_detail
        assert enriched_finding["instance_metadata"] == mock_instance_metadata

    stubber.assert_no_pending_responses()


def test_enrich_action_instance_not_found(guardduty_finding_detail, mock_app_config):
    """
    Tests the graceful exit path where the instance ID does not exist.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # Mock describe_instances to return an empty list, simulating a terminated instance
    describe_response = {"Reservations": []}
    stubber.add_response(
        "describe_instances", describe_response, {"InstanceIds": [instance_id]}
    )

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = EnrichFindingWithInstanceMetadataAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        # This is a graceful exit, so the status should be 'success'
        assert result["status"] == "success"
        assert "not found" in result["details"]

    stubber.assert_no_pending_responses()


def test_enrich_action_api_failure(guardduty_finding_detail, mock_app_config):
    """
    Tests the failure path where the describe_instances call raises an unexpected error.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)
    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # Mock a generic API error
    stubber.add_client_error("describe_instances", "ThrottlingException")

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = EnrichFindingWithInstanceMetadataAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail)

        assert result["status"] == "error"
        assert "Failed to describe instance" in result["details"]
        assert "ThrottlingException" in result["details"]

    stubber.assert_no_pending_responses()
