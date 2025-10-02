import logging
from unittest.mock import MagicMock, patch

from guardduty_soar.main import main

# This test file focuses only on the main handler's responsibility:
# creating an Engine and calling it.


def test_main_handler_success(valid_guardduty_event, caplog):
    """
    Tests the main handler's "happy path".
    It should create an Engine and call its handle_finding method.
    """
    # We patch the Engine class within the main module.
    with patch("guardduty_soar.main.Engine") as MockEngine:
        # Create a mock instance that will be returned when Engine() is called.
        mock_engine_instance = MockEngine.return_value

        # Call the main handler.
        result = main(valid_guardduty_event, {})

        # 1. Assert that the handler returned a success response.
        assert result["statusCode"] == 200
        assert "success" in result["message"]

        # 2. Assert that the Engine was instantiated correctly with the event's detail.
        MockEngine.assert_called_once_with(valid_guardduty_event["detail"])

        # 3. Assert that the handle_finding method was called on the engine instance.
        mock_engine_instance.handle_finding.assert_called_once()


def test_main_handler_engine_failure(valid_guardduty_event, caplog):
    """
    Tests that the main handler catches errors raised by the Engine
    and returns a 400 status code.
    """
    error_message = "Something went wrong in the engine"
    # Patch the Engine and make its handle_finding method raise an error.
    with patch("guardduty_soar.main.Engine") as MockEngine:
        mock_engine_instance = MockEngine.return_value
        mock_engine_instance.handle_finding.side_effect = ValueError(error_message)

        with caplog.at_level(logging.ERROR):
            result = main(valid_guardduty_event, {})

            # 1. Assert that the handler returned a client error response.
            assert result["statusCode"] == 400
            assert result["message"] == error_message

            # 2. Assert that the error was logged.
            assert error_message in caplog.text
