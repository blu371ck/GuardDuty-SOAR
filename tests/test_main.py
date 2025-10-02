import pytest
from unittest.mock import patch
from guardduty_soar.main import main


def test_main_handler_success(valid_guardduty_event):
    """
    Tests that the main handler successfully instantiates and calls the Engine.
    """
    # We patch the Engine class within the main module.
    with patch("guardduty_soar.main.Engine") as MockEngine:
        # Get a reference to the instance that will be created
        mock_engine_instance = MockEngine.return_value

        # Call the main handler
        result = main(valid_guardduty_event, {})

        # --- Assertions ---
        # 1. Check that the handler returned a success status.
        assert result["statusCode"] == 200
        assert "success" in result["message"].lower()

        # 2. Check that an Engine was created with the correct data.
        MockEngine.assert_called_once_with(valid_guardduty_event["detail"])

        # 3. Check that the engine's handle_finding method was called.
        mock_engine_instance.handle_finding.assert_called_once()


def test_main_handler_engine_failure(valid_guardduty_event):
    """
    Tests that the main handler returns an error if the Engine fails.
    """
    # Patch the Engine and make its handle_finding method raise an error.
    with patch("guardduty_soar.main.Engine") as MockEngine:
        mock_engine_instance = MockEngine.return_value
        mock_engine_instance.handle_finding.side_effect = ValueError("Engine processing failed.")

        # Call the main handler
        result = main(valid_guardduty_event, {})

        # --- Assertions ---
        # 1. Check that the handler caught the exception and returned a 400 error.
        assert result["statusCode"] == 400
        assert "Engine processing failed" in result["message"]

