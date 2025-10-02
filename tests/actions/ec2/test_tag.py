import boto3
import pytest
from botocore.stub import ANY, Stubber

from guardduty_soar.actions.ec2.tag import TagInstanceAction


def test_tag_instance_action_success(guardduty_finding_detail):
    """
    Tests the TagInstanceAction using a botocore Stubber to mock the AWS API.
    """
    ec2_client = boto3.client("ec2", region_name="us-east-1")
    stubber = Stubber(ec2_client)

    instance_id = guardduty_finding_detail["Resource"]["InstanceDetails"]["InstanceId"]

    # Define the exact parameters the test expects the API call to receive.
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
        # Create a mock session that returns our stubbed client
        mock_session = boto3.Session()

        def mock_client(service_name, **kwargs):
            if service_name == "ec2":
                return ec2_client
            # This part is important for other potential clients in a session
            return boto3.Session().client(service_name, **kwargs)

        mock_session.client = mock_client

        action = TagInstanceAction(mock_session)
        result = action.execute(guardduty_finding_detail, playbook_name="TestPlaybook")

        assert result["status"] == "success"

    stubber.assert_no_pending_responses()
