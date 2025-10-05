from unittest.mock import MagicMock, patch

import pytest

from guardduty_soar.notifications.manager import NotificationManager


# We patch the concrete action classes that the manager imports and uses
@patch("guardduty_soar.notifications.manager.SendSESNotificationAction")
def test_manager_initialization(MockSESAction, mock_app_config):
    """Tests that the manager initializes all its notification actions."""
    mock_session = MagicMock()
    manager = NotificationManager(mock_session, mock_app_config)

    MockSESAction.assert_called_once_with(mock_session, mock_app_config)
    assert manager.ses_action == MockSESAction.return_value


@patch("guardduty_soar.notifications.manager.SendSESNotificationAction")
def test_send_starting_notification(
    MockSESAction, guardduty_finding_detail, mock_app_config
):
    """Tests that the starting notification calls the correct actions."""
    mock_session = MagicMock()
    manager = NotificationManager(mock_session, mock_app_config)
    mock_ses_action_instance = MockSESAction.return_value

    manager.send_starting_notification(guardduty_finding_detail, "TestPlaybook")

    # Assert that the SES action's execute method was called with 'starting' params
    mock_ses_action_instance.execute.assert_called_once_with(
        guardduty_finding_detail, playbook_name="TestPlaybook", template_type="starting"
    )


@patch("guardduty_soar.notifications.manager.SendSESNotificationAction")
def test_send_complete_notification_with_failure(
    MockSESAction, enriched_ec2_finding, mock_app_config
):
    """
    Tests that the complete notification correctly identifies a failure in the action results.
    """
    mock_session = MagicMock()
    manager = NotificationManager(mock_session, mock_app_config)
    mock_ses_action_instance = MockSESAction.return_value

    # Simulate a failed action result
    failed_results = [
        {"status": "error", "details": "It broke", "action_name": "Test Action"}
    ]

    manager.send_complete_notification(
        data=enriched_ec2_finding,
        playbook_name="TestPlaybook",
        action_results=failed_results,
    )

    mock_ses_action_instance.execute.assert_called_once()
    call_args = mock_ses_action_instance.execute.call_args

    # Verify that the correct failure emoji and message were passed to the template data
    assert call_args.kwargs["final_status_emoji"] == "❌"
    assert "PLAYBOOK FAILED" in call_args.kwargs["final_status_message"]
