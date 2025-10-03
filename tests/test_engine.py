import logging
import pytest
from unittest.mock import patch, MagicMock

from guardduty_soar.engine import Engine

# Note: We now include 'mock_app_config' in the function signature for each test.

def test_engine_initialization_success(guardduty_finding_detail, mock_app_config, caplog):
    """Tests that the Engine class initializes correctly with a valid event."""
    with caplog.at_level(logging.INFO):
        # We now pass the mock config to the Engine constructor
        engine = Engine(guardduty_finding_detail, mock_app_config)
        
        assert engine.event == guardduty_finding_detail
        assert engine.config == mock_app_config
        assert "Incoming GuardDuty event" in caplog.text

def test_engine_initialization_failure(mock_app_config):
    """Tests that the Engine class raises a ValueError for an incomplete event."""
    incomplete_event = {"Id": "123"}  # Missing Type and Description
    with pytest.raises(ValueError, match="Event not complete."):
        Engine(incomplete_event, mock_app_config)

def test_handle_finding_success(guardduty_finding_detail, mock_app_config):
    """
    Tests that handle_finding successfully gets a playbook from the registry
    and calls its run method.
    """
    engine = Engine(guardduty_finding_detail, mock_app_config)
    
    mock_playbook = MagicMock()
    # Patch the get_playbook_instance function within the engine module
    with patch("guardduty_soar.engine.get_playbook_instance", return_value=mock_playbook) as mock_get_playbook:
        engine.handle_finding()
        
        # Assert that the factory was called with the correct finding type and config
        mock_get_playbook.assert_called_once_with(
            guardduty_finding_detail["Type"], mock_app_config
        )
        # Assert that the playbook's run method was called
        mock_playbook.run.assert_called_once()

def test_handle_finding_failure_logs_critical(guardduty_finding_detail, mock_app_config, caplog):
    """
    Tests that handle_finding logs a critical error if no playbook is found.
    """
    engine = Engine(guardduty_finding_detail, mock_app_config)
    
    # Configure the mock to raise a ValueError, simulating a failed lookup
    with patch("guardduty_soar.engine.get_playbook_instance", side_effect=ValueError("Test error")):
        with caplog.at_level(logging.CRITICAL):
            engine.handle_finding()
            assert "No playbook registered" in caplog.text

