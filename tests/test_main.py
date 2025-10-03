import logging
import pytest
from unittest.mock import patch, MagicMock

from guardduty_soar.main import setup_logging, main
from guardduty_soar.exceptions import PlaybookActionFailedError

def test_setup_logging(mock_app_config):
    """
    Tests that the setup_logging function correctly configures the root logger.
    """
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config) as mock_get_config:
        with patch("logging.basicConfig") as mock_basic_config:
            setup_logging()
            mock_get_config.assert_called_once()
            mock_basic_config.assert_called_once()

def test_main_handler_success(valid_guardduty_event, mock_app_config, caplog):
    """
    Tests the main handler's "happy path".
    """
    # We now need to patch get_config as well
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("guardduty_soar.main.Engine") as MockEngine:
            mock_engine_instance = MockEngine.return_value
            result = main(valid_guardduty_event, {})

            assert result["statusCode"] == 200
            # Check that Engine was called with the event detail AND the config
            MockEngine.assert_called_once_with(valid_guardduty_event["detail"], mock_app_config)
            mock_engine_instance.handle_finding.assert_called_once()

def test_main_handler_engine_failure(valid_guardduty_event, mock_app_config, caplog):
    """
    Tests that the main handler catches a ValueError/KeyError from the Engine.
    """
    error_message = "Invalid event structure"
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        # Make the Engine constructor raise an error
        with patch("guardduty_soar.main.Engine", side_effect=ValueError(error_message)):
            with caplog.at_level(logging.ERROR):
                result = main(valid_guardduty_event, {})

                assert result["statusCode"] == 400
                assert result["message"] == error_message
                assert "Failed to process finding" in caplog.text

def test_main_handler_playbook_action_failure(valid_guardduty_event, mock_app_config, caplog):
    """
    Tests that the main handler catches a PlaybookActionFailedError.
    """
    error_message = "The tag action failed"
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("guardduty_soar.main.Engine") as MockEngine:
            mock_engine_instance = MockEngine.return_value
            mock_engine_instance.handle_finding.side_effect = PlaybookActionFailedError(error_message)

            with caplog.at_level(logging.CRITICAL):
                result = main(valid_guardduty_event, {})

                assert result["statusCode"] == 500
                assert f"Internal playbook error: {error_message}" in result["message"]
                assert "A playbook action failed" in caplog.text

