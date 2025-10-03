from unittest.mock import MagicMock

import boto3
from botocore.stub import ANY, Stubber

from guardduty_soar.actions.ec2.tag import TagInstanceAction
from guardduty_soar.config import AppConfig


def test_tag_instance_action_success(guardduty_finding_detail, mock_app_config):
    """
    Tests the TagInstanceAction using a botocore Stubber to mock the AWS API.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]
    expected_params = {
        "Resources": [instance_id],
        "Tags": [
            {"Key": "GUARDDUTY-SOAR-ID", "Value": guardduty_finding_detail["Id"]},
            {"Key": "SOAR-Status", "Value": "Remediation-In-Progress"},
            {"Key": "SOAR-Action-Time-UTC", "Value": ANY},
            {"Key": "SOAR-Finding-Type", "Value": guardduty_finding_detail["Type"]},
            {"Key": "SOAR-Finding-Severity", "Value": "HIGH"},
            {"Key": "SOAR-Playbook", "Value": "TestPlaybook"},
        ],
    }
    response = {"ResponseMetadata": {"HTTPStatusCode": 200}}
    stubber.add_response("create_tags", response, expected_params)

    with stubber:
        mock_session = MagicMock()
        mock_session.client.return_value = ec2_client

        action = TagInstanceAction(mock_session, mock_app_config)
        result = action.execute(guardduty_finding_detail, playbook_name="TestPlaybook")

        assert result["status"] == "success"
    stubber.assert_no_pending_responses()
