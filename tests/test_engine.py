from unittest.mock import MagicMock, patch

import pytest

from guardduty_soar.engine import Engine
from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.models import PlaybookResult


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
@patch("guardduty_soar.engine.map_resource_to_model")  # Add patch for the mapper
def test_handle_finding_success(
    mock_map_resource,
    mock_get_playbook,
    MockNotificationManager,
    guardduty_finding_detail,
    mock_app_config,
):
    """
    Tests the full success path of the engine's handle_finding method.
    """
    # --- Arrange ---
    # THE FIX 1: Mock the playbook's return value as the new PlaybookResult dictionary
    mock_playbook_result: PlaybookResult = {
        "action_results": [
            {"status": "success", "action_name": "test", "details": "Mock details"}
        ],
        "enriched_data": {"instance_metadata": {"InstanceId": "i-99999999"}},
    }
    mock_playbook = MagicMock()
    mock_playbook.run.return_value = mock_playbook_result
    mock_get_playbook.return_value = mock_playbook

    # Mock the resource model that the engine will create
    mock_resource_model = MagicMock()
    mock_map_resource.return_value = mock_resource_model

    engine = Engine(guardduty_finding_detail, mock_app_config)
    mock_notification_manager = MockNotificationManager.return_value

    # --- Act ---
    engine.handle_finding()

    # --- Assert ---
    # THE FIX 2: Verify send_complete_notification is called with the new named arguments
    mock_notification_manager.send_complete_notification.assert_called_once_with(
        finding=guardduty_finding_detail,
        playbook_name=mock_playbook.__class__.__name__,
        action_results=mock_playbook_result["action_results"],
        resource=mock_resource_model,
        enriched_data=mock_playbook_result["enriched_data"],
    )


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
