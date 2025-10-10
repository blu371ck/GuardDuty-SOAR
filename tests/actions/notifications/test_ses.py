from unittest.mock import MagicMock, patch

import boto3
from botocore.stub import Stubber

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction


def test_ses_action_execute(mocker):
    """
    Tests the execute method of the SES action, verifying it calls helpers
    and the boto3 client correctly.
    """
    mock_config = MagicMock(allow_ses=True, registered_email_address="test@example.com")
    action = SendSESNotificationAction(MagicMock(), mock_config)

    # Mock the internal methods and the boto3 client
    mock_build_context = mocker.patch.object(
        action, "_build_template_context", return_value={"title": "Test Title"}
    )
    mock_render = mocker.patch.object(
        action, "_render_template", return_value="Subject: Test\nBody"
    )
    mock_send_email = mocker.patch.object(action.ses_client, "send_email")

    # Define the input kwargs that the Engine would provide
    input_kwargs = {
        "finding": {"Type": "TestFinding"},
        "resource": MagicMock(),
        "enriched_data": None,
        "template_type": "starting",
    }

    result = action.execute(**input_kwargs)

    assert result["status"] == "success"
    # Call the assertion methods on the captured mock objects
    mock_build_context.assert_called_once_with(**input_kwargs)
    mock_render.assert_called_once_with(
        "ses", "starting.md.j2", {"title": "Test Title"}
    )
    mock_send_email.assert_called_once()
