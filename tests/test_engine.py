import logging
import pytest
from unittest.mock import patch, MagicMock
from guardduty_soar.engine import Engine


def test_engine_initialization_success(guardduty_finding_detail, caplog):
    """
    Tests that the Engine class initializes correctly with a valid event.
    """
    with caplog.at_level(logging.INFO):
        engine = Engine(guardduty_finding_detail)
        assert engine.event == guardduty_finding_detail
        assert "Incoming GuardDuty event" in caplog.text


def test_engine_initialization_failure():
    """
    Tests that the Engine class raises a ValueError for an incomplete event.
    """
    incomplete_event = {"Id": "123"}  # Missing Type and Description
    with pytest.raises(ValueError, match="Event not complete."):
        Engine(incomplete_event)


def test_handle_finding_success(guardduty_finding_detail):
    """
    Tests that handle_finding successfully finds and runs a playbook.
    """
    engine = Engine(guardduty_finding_detail)

    # Mock the get_playbook_instance function within the engine module
    with patch("guardduty_soar.engine.get_playbook_instance") as mock_get_playbook:
        # --- Setup Mock ---
        mock_playbook = MagicMock()
        mock_get_playbook.return_value = mock_playbook

        # --- Call Method ---
        engine.handle_finding()

        # --- Assertions ---
        # 1. Check that the playbook registry was called correctly.
        mock_get_playbook.assert_called_once_with(guardduty_finding_detail["Type"])

        # 2. Check that the playbook's run method was called with the event detail.
        mock_playbook.run.assert_called_once_with(guardduty_finding_detail)


def test_handle_finding_failure_logs_critical(guardduty_finding_detail, caplog):
    """
    Tests that handle_finding logs a critical error when no playbook is found.
    """
    engine = Engine(guardduty_finding_detail)

    # Mock get_playbook_instance to raise a ValueError
    with patch(
        "guardduty_soar.engine.get_playbook_instance",
        side_effect=ValueError("No playbook registered."),
    ):
        with caplog.at_level(logging.CRITICAL):
            engine.handle_finding()

            # Assert that a critical error was logged
            assert "No playbook registered" in caplog.text

