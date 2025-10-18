import json
from datetime import datetime
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction


@pytest.fixture
def mock_notification_kwargs_starting():
    """Provides a sample dictionary of kwargs for a 'starting' notification."""
    # A mock resource object must have a .model_dump() method.
    mock_resource = MagicMock()
    mock_resource.model_dump.return_value = {
        "resource_type": "Instance",
        "instance_id": "i-12345",
    }

    return {
        "finding": {"Type": "Test:EC2/Finding"},
        "playbook_name": "TestPlaybook",
        "template_type": "starting",
        "resource": mock_resource,
    }


@pytest.fixture
def mock_notification_kwargs_complete(mock_notification_kwargs_starting):
    """
    Provides a full sample of kwargs for a 'complete' notification,
    including enriched data with a datetime object to test serialization.
    """
    # Start with the basic 'starting' kwargs and add the completion fields
    kwargs = mock_notification_kwargs_starting.copy()
    kwargs.update(
        {
            "template_type": "complete",
            "enriched_data": {
                "instance_details": {"ImageId": "ami-12345"},
                "created_at": datetime(
                    2025, 10, 17, 12, 0, 0
                ),  # For testing datetime serialization
            },
            "final_status_emoji": "✅",
            "final_status_message": "Playbook completed successfully.",
            "actions_summary": "Action1: SUCCESS\nAction2: SKIPPED",
        }
    )
    return kwargs


@pytest.fixture
def mock_boto_session():
    """Provides a mock boto3 session and a mock SNS client."""
    mock_session = MagicMock()
    mock_sns_client = MagicMock()
    mock_session.client.return_value = mock_sns_client
    return mock_session, mock_sns_client


@pytest.fixture
def sns_action(mock_boto_session, mock_app_config):
    """Initializes the SendSNSNotificationAction with mock dependencies."""
    session, _ = mock_boto_session
    mock_app_config.allow_sns = True
    mock_app_config.sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
    return SendSNSNotificationAction(session, mock_app_config)


def get_published_message(mock_sns_client: MagicMock) -> dict:
    """Helper to get the args from the publish call and parse the JSON message."""
    mock_sns_client.publish.assert_called_once()
    # Get the 'Message' keyword argument from the call
    message_str = mock_sns_client.publish.call_args[1]["Message"]
    return json.loads(message_str)


def test_sns_action_success_complete(
    sns_action, mock_boto_session, mock_notification_kwargs_complete
):
    """
    GIVEN a 'complete' notification with enriched data.
    WHEN the action is executed.
    THEN it should build a full JSON payload and publish it.
    """
    _, mock_sns_client = mock_boto_session

    result = sns_action.execute(**mock_notification_kwargs_complete)

    assert result["status"] == "success"

    # Parse the message that was sent to SNS
    message_data = get_published_message(mock_sns_client)

    # Verify the structure and content
    assert message_data["event_type"] == "playbook_completed"
    assert message_data["playbook_name"] == "TestPlaybook"
    assert message_data["status_emoji"] == "✅"
    assert "resource" in message_data
    assert "enriched_data" in message_data
    # Verify datetime was correctly converted to a string
    assert message_data["enriched_data"]["created_at"] == "2025-10-17 12:00:00"


def test_sns_action_success_starting(
    sns_action, mock_boto_session, mock_notification_kwargs_starting
):
    """
    GIVEN a 'starting' notification.
    WHEN the action is executed.
    THEN it should build a minimal JSON payload and publish it.
    """
    _, mock_sns_client = mock_boto_session

    result = sns_action.execute(**mock_notification_kwargs_starting)

    assert result["status"] == "success"

    message_data = get_published_message(mock_sns_client)

    assert message_data["event_type"] == "playbook_started"
    assert message_data["playbook_name"] == "TestPlaybook"
    # Verify completion-specific fields are not present
    assert "status_message" not in message_data
    assert "enriched_data" not in message_data


def test_sns_action_skipped_when_disabled(
    sns_action, mock_boto_session, mock_app_config
):
    """
    GIVEN SNS is disabled in the configuration.
    WHEN the action is executed.
    THEN it should return a 'skipped' status.
    """
    _, mock_sns_client = mock_boto_session
    mock_app_config.allow_sns = False  # Disable the action

    result = sns_action.execute()

    assert result["status"] == "skipped"
    mock_sns_client.publish.assert_not_called()


def test_sns_action_handles_boto3_error(
    sns_action, mock_boto_session, mock_notification_kwargs_starting
):
    """
    GIVEN the boto3 SNS client raises an error.
    WHEN the action is executed.
    THEN it should return an 'error' status.
    """
    _, mock_sns_client = mock_boto_session
    mock_sns_client.publish.side_effect = ClientError(
        error_response={"Error": {"Code": "InvalidParameter"}}, operation_name="Publish"
    )

    result = sns_action.execute(**mock_notification_kwargs_starting)

    assert result["status"] == "error"
    assert "InvalidParameter" in result["details"]
