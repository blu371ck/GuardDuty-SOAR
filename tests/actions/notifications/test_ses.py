from unittest.mock import MagicMock, patch

import boto3
from botocore.stub import Stubber

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction


# This test now mocks the base class methods, decoupling it from the template logic
def test_ses_action_execute_success(guardduty_finding_detail, mock_app_config, mocker):
    """
    Tests that the SES action correctly renders a template and calls the SES API.
    """
    # Arrange
    mock_app_config.allow_ses = True
    mock_app_config.registered_email_address = "test@example.com"

    ses_client = boto3.client("ses", region_name="us-east-1")
    stubber = Stubber(ses_client)

    # Mock the return value of the template rendering
    rendered_template = "Subject: Test Subject\nThis is the email body."
    expected_html = "<p>This is the email body.</p>"

    expected_params = {
        "Source": "test@example.com",
        "Destination": {"ToAddresses": ["test@example.com"]},
        "Message": {
            "Subject": {"Data": "Test Subject"},
            "Body": {
                "Text": {"Data": "This is the email body."},
                "Html": {"Data": expected_html},
            },
        },
    }
    stubber.add_response("send_email", {"MessageId": "123"}, expected_params)

    mock_session = MagicMock()
    mock_session.client.return_value = ses_client

    action = SendSESNotificationAction(mock_session, mock_app_config)

    # Mock the helper methods on the base class
    mocker.patch.object(
        action, "_build_template_context", return_value={"finding": "test"}
    )
    mocker.patch.object(action, "_render_template", return_value=rendered_template)

    # Act
    with stubber:
        result = action.execute(guardduty_finding_detail, template_type="starting")

    # Assert
    assert result["status"] == "success"
    stubber.assert_no_pending_responses()
    action._build_template_context.assert_called_once_with(
        guardduty_finding_detail, template_type="starting"
    )
    action._render_template.assert_called_once_with(
        "ses", "starting.md.j2", {"finding": "test"}
    )


def test_ses_action_disabled_in_config(guardduty_finding_detail, mock_app_config):
    """
    Tests that no API call is made if allow_ses is False.
    """
    mock_app_config.allow_ses = False
    mock_session = MagicMock()
    action = SendSESNotificationAction(mock_session, mock_app_config)

    # Act
    result = action.execute(guardduty_finding_detail)

    # Assert
    assert result["status"] == "success"
    assert "disabled" in result["details"]
    mock_session.client.return_value.send_email.assert_not_called()
