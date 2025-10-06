from unittest.mock import MagicMock, mock_open, patch

import boto3
import pytest
from botocore.stub import ANY, Stubber

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction

# Mock templates for testing
STARTING_TEMPLATE = "Subject: [SOAR] Response Started: {finding_type}\n\nPlaybook {playbook_name} has been initiated for a {finding_severity} severity finding."
COMPLETE_TEMPLATE = "Subject: {final_status_emoji} [SOAR] Response Complete: {finding_type}\n\nInstance ID: {instance_id}\nPublic IP: {public_ip}"


def test_ses_action_sends_starting_notification(
    guardduty_finding_detail, mock_app_config
):
    """
    Tests the success path for a 'starting' notification with a basic event.
    """
    ses_client = boto3.client("ses", region_name="us-east-1")
    stubber = Stubber(ses_client)

    mock_app_config.allow_ses = True
    mock_app_config.registered_email_address = "test@example.com"

    expected_params = {
        "Source": "test@example.com",
        "Destination": {"ToAddresses": ["test@example.com"]},
        "Message": {
            "Subject": {
                "Data": "[SOAR] Response Started: UnauthorizedAccess:EC2/TorClient"
            },
            "Body": {"Text": {"Data": ANY}, "Html": {"Data": ANY}},
        },
    }
    # FIX 1: Provide a valid mock response that includes the required MessageId
    mock_response = {"MessageId": "test-message-id-123"}
    stubber.add_response("send_email", mock_response, expected_params)

    # FIX 2: Use the correct pattern for mocking file reading
    with patch("builtins.open", mock_open(read_data=STARTING_TEMPLATE)):
        with stubber:
            mock_session = MagicMock()
            mock_session.client.return_value = ses_client

            action = SendSESNotificationAction(mock_session, mock_app_config)
            result = action.execute(
                guardduty_finding_detail,
                playbook_name="TestPlaybook",
                template_type="starting",
            )

            assert result["status"] == "success"
    stubber.assert_no_pending_responses()


def test_ses_action_sends_complete_notification(enriched_ec2_finding, mock_app_config):
    """
    Tests the success path for a 'complete' notification with an enriched event.
    """
    ses_client = boto3.client("ses", region_name="us-east-1")
    stubber = Stubber(ses_client)

    mock_app_config.allow_ses = True
    mock_app_config.registered_email_address = "test@example.com"

    expected_params = {
        "Source": "test@example.com",
        "Destination": {"ToAddresses": ["test@example.com"]},
        "Message": {
            "Subject": {
                "Data": "✅ [SOAR] Response Complete: UnauthorizedAccess:EC2/TorClient"
            },
            "Body": {
                "Text": {"Data": "\nInstance ID: i-99999999\nPublic IP: 198.51.100.1"},
                "Html": {
                    "Data": "<p>Instance ID: i-99999999\nPublic IP: 198.51.100.1</p>"
                },
            },
        },
    }
    mock_response = {"MessageId": "test-message-id-456"}
    stubber.add_response("send_email", mock_response, expected_params)

    with patch("builtins.open", mock_open(read_data=COMPLETE_TEMPLATE)):
        with stubber:
            mock_session = MagicMock()
            mock_session.client.return_value = ses_client

            action = SendSESNotificationAction(mock_session, mock_app_config)
            result = action.execute(
                enriched_ec2_finding, template_type="complete", final_status_emoji="✅"
            )

            assert result["status"] == "success"
    stubber.assert_no_pending_responses()


def test_ses_action_disabled_in_config(guardduty_finding_detail, mock_app_config):
    """
    Tests that no API call is made if allow_ses is False.
    """
    mock_app_config.allow_ses = False

    # Create a mock for the ses_client that will be created in __init__
    mock_ses_client = MagicMock()

    # Create a mock session that returns our mock client
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ses_client

    action = SendSESNotificationAction(mock_session, mock_app_config)
    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    assert "disabled" in result["details"]

    # FIX 3: Assert that the 'send_email' method on the client was never called.
    mock_ses_client.send_email.assert_not_called()
