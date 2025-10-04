import logging
from unittest.mock import MagicMock, patch

import pytest

from guardduty_soar.engine import Engine

# Note: We now include 'mock_app_config' in the function signature for each test.


def test_engine_initialization_success(
    guardduty_finding_detail, mock_app_config, caplog
):
    """Tests that the Engine class initializes correctly with a valid event."""
    # The fixture data now has the correct keys, so this will pass.
    with caplog.at_level(logging.INFO):
        engine = Engine(guardduty_finding_detail, mock_app_config)

        assert engine.event == guardduty_finding_detail
        assert engine.config == mock_app_config
        assert "Incoming GuardDuty event" in caplog.text


def test_engine_initialization_failure(mock_app_config):
    """Tests that the Engine class raises a ValueError for an incomplete event."""
    incomplete_event = {"Id": "123"}  # Still missing required keys
    with pytest.raises(ValueError, match="Event not complete."):
        Engine(incomplete_event, mock_app_config)


def test_handle_finding_success(guardduty_finding_detail, mock_app_config):
    """
    Tests that handle_finding successfully gets a playbook from the registry
    and calls its run method.
    """
    engine = Engine(guardduty_finding_detail, mock_app_config)

    mock_playbook = MagicMock()
    with patch(
        "guardduty_soar.engine.get_playbook_instance", return_value=mock_playbook
    ) as mock_get_playbook:
        engine.handle_finding()

        mock_get_playbook.assert_called_once_with(
            guardduty_finding_detail["Type"], mock_app_config
        )
        mock_playbook.run.assert_called_once_with(guardduty_finding_detail)


def test_handle_finding_failure_logs_critical(
    guardduty_finding_detail, mock_app_config, caplog
):
    """
    Tests that handle_finding logs a critical error if no playbook is found.
    """
    engine = Engine(guardduty_finding_detail, mock_app_config)

    with patch(
        "guardduty_soar.engine.get_playbook_instance",
        side_effect=ValueError("Test error"),
    ):
        with caplog.at_level(logging.CRITICAL):
            engine.handle_finding()
            assert "No playbook registered" in caplog.text
