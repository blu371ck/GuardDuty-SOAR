import logging
from unittest.mock import MagicMock, call, patch

import pytest

from guardduty_soar.exceptions import PlaybookActionFailedError
from guardduty_soar.main import handler, setup_logging


def test_setup_logging(mock_app_config):
    """
    Tests that the setup_logging function correctly configures application and boto loggers.
    """
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("logging.basicConfig") as mock_basic_config:
            with patch("logging.getLogger") as mock_get_logger:
                # Create a mock logger object that will be returned by getLogger
                mock_boto_logger = MagicMock()
                mock_get_logger.return_value = mock_boto_logger

                setup_logging()

                # Assert that basicConfig was called with the app's log level
                mock_basic_config.assert_called_once()
                call_kwargs = mock_basic_config.call_args.kwargs
                assert call_kwargs["level"] == logging.INFO

                # Assert that the correct loggers were retrieved
                expected_calls = [
                    call("main"),
                    call("boto3"),
                    call("botocore"),
                    call("urllib3"),
                ]
                mock_get_logger.assert_has_calls(expected_calls, any_order=True)

                # Assert that the setLevel method was called on the logger object
                # for the boto-related loggers
                boto_level_calls = [
                    call(logging.WARNING)
                ] * 3  # for boto3, botocore, urllib3
                mock_boto_logger.setLevel.assert_has_calls(boto_level_calls)


def test_main_handler_success(valid_guardduty_event, mock_app_config):
    """
    Tests the main handler's "happy path".
    """
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("guardduty_soar.main.Engine") as MockEngine:
            mock_engine_instance = MockEngine.return_value
            result = handler(valid_guardduty_event, {})

            assert result["statusCode"] == 200
            MockEngine.assert_called_once_with(
                valid_guardduty_event["detail"], mock_app_config
            )
            mock_engine_instance.handle_finding.assert_called_once()


def test_main_handler_engine_failure(valid_guardduty_event, mock_app_config, caplog):
    """
    Tests that the main handler catches a ValueError/KeyError from the Engine.
    """
    error_message = "Invalid event structure"
    with patch("guardduty_soar.main.get_config", return_value=mock_app_config):
        with patch("guardduty_soar.main.Engine", side_effect=ValueError(error_message)):
            # Explicitly target the 'main' logger to ensure capture
            with caplog.at_level(logging.ERROR, logger="main"):
                result = handler(valid_guardduty_event, {})

                assert result["statusCode"] == 400
                assert result["message"] == error_message
                assert "Failed to process finding" in caplog.text
