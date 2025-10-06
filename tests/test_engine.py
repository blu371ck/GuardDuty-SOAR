from unittest.mock import MagicMock, patch

import pytest

from guardduty_soar.engine import Engine
from guardduty_soar.exceptions import PlaybookActionFailedError


@patch("guardduty_soar.engine.boto3.Session")
@patch("guardduty_soar.engine.NotificationManager")
def test_engine_initialization(
    MockNotificationManager, MockBotoSession, guardduty_finding_detail, mock_app_config
):
    """Tests that the Engine initializes correctly and sets up its components."""
    engine = Engine(guardduty_finding_detail, mock_app_config)

    assert engine.event == guardduty_finding_detail
    assert engine.config == mock_app_config
    MockBotoSession.assert_called_once()
    MockNotificationManager.assert_called_once_with(
        MockBotoSession.return_value, mock_app_config
    )


@patch("guardduty_soar.engine.NotificationManager")
@patch("guardduty_soar.engine.get_playbook_instance")
def test_handle_finding_success(
    mock_get_playbook,
    MockNotificationManager,
    guardduty_finding_detail,
    mock_app_config,
):
    """
    Tests the full success path of the engine's handle_finding method.
    """
    mock_playbook = MagicMock()
    mock_playbook.run.return_value = (
        [],
        {"enriched": "data"},
    )  # Mock the playbook's return value
    mock_get_playbook.return_value = mock_playbook

    engine = Engine(guardduty_finding_detail, mock_app_config)
    mock_notification_manager = MockNotificationManager.return_value

    engine.handle_finding()

    # Assert starting notification was sent
    mock_notification_manager.send_starting_notification.assert_called_once()

    # Assert playbook was retrieved and run
    mock_get_playbook.assert_called_once_with(
        guardduty_finding_detail["Type"], mock_app_config
    )
    mock_playbook.run.assert_called_once_with(guardduty_finding_detail)

    # Assert complete notification was sent with the enriched data
    mock_notification_manager.send_complete_notification.assert_called_once()
    call_args = mock_notification_manager.send_complete_notification.call_args
    assert call_args.kwargs["data"] == {"enriched": "data"}
    assert call_args.kwargs["action_results"] == []


@patch("guardduty_soar.engine.NotificationManager")
@patch("guardduty_soar.engine.get_playbook_instance")
def test_handle_finding_playbook_fails(
    mock_get_playbook,
    MockNotificationManager,
    guardduty_finding_detail,
    mock_app_config,
):
    """
    Tests the path where the playbook's run method raises an exception.
    """
    mock_playbook = MagicMock()
    mock_playbook.run.side_effect = PlaybookActionFailedError("Action failed!")
    mock_get_playbook.return_value = mock_playbook

    engine = Engine(guardduty_finding_detail, mock_app_config)
    mock_notification_manager = MockNotificationManager.return_value

    engine.handle_finding()

    # Assert that the complete notification is still sent in the 'finally' block
    mock_notification_manager.send_complete_notification.assert_called_once()
    call_args = mock_notification_manager.send_complete_notification.call_args
    # Check that the failure was correctly added to the action_results
    assert len(call_args.kwargs["action_results"]) == 1
    assert call_args.kwargs["action_results"][0]["status"] == "error"
