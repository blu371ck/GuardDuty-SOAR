import logging
from unittest.mock import MagicMock, patch

import pytest

from guardduty_soar.engine import Engine

def test_engine_initialization_success(guardduty_finding_detail, caplog):
    """Tests that the Engine class initializes correctly with a valid event."""
    with caplog.at_level(logging.INFO):
        engine = Engine(guardduty_finding_detail)
        assert engine.event == guardduty_finding_detail
        assert "Incoming GuardDuty event" in caplog.text
        assert guardduty_finding_detail["Description"] in caplog.text


def test_engine_initialization_failure():
    """Tests that the Engine class raises a ValueError for an incomplete event."""
    incomplete_event = {"Id": "123"}  # Missing Type and Description
    with pytest.raises(ValueError, match="Event not complete."):
        Engine(incomplete_event)


def test_handle_finding_success(guardduty_finding_detail):
    """
    Tests that handle_finding successfully gets a playbook from the registry
    and calls its run method.
    """
    engine = Engine(guardduty_finding_detail)

    # Mock the get_playbook_instance function to isolate the test.
    with patch("guardduty_soar.engine.get_playbook_instance") as mock_get_playbook:
        # Create a mock playbook object that the registry will "return".
        mock_playbook_instance = MagicMock()
        mock_get_playbook.return_value = mock_playbook_instance

        engine.handle_finding()

        # Assert that the registry was called with the correct finding type.
        mock_get_playbook.assert_called_once_with(guardduty_finding_detail["Type"])

        # Assert that the run method of the returned playbook was called.
        mock_playbook_instance.run.assert_called_once_with(guardduty_finding_detail)


def test_handle_finding_failure_logs_critical(guardduty_finding_detail, caplog):
    """
    Tests that handle_finding logs a critical error if no playbook is found.
    """
    engine = Engine(guardduty_finding_detail)
    error_message = f"No playbook registered for finding type: {engine.event['Type']}"

    # Mock get_playbook_instance to simulate a failure.
    with patch(
        "guardduty_soar.engine.get_playbook_instance",
        side_effect=ValueError(error_message),
    ):
        with caplog.at_level(logging.CRITICAL):
            engine.handle_finding()

            # Assert that a critical error was logged with the correct message.
            assert error_message in caplog.text
