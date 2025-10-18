from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction


@pytest.fixture
def mock_boto_session():
    """Provides a mock boto3 session and a mock SES client."""
    mock_session = MagicMock()
    mock_ses_client = MagicMock()
    mock_session.client.return_value = mock_ses_client
    return mock_session, mock_ses_client


@pytest.fixture
def ses_action(mock_boto_session, mock_app_config):
    """Initializes the SendSESNotificationAction with mock dependencies."""
    session, _ = mock_boto_session
    mock_app_config.allow_ses = True
    mock_app_config.registered_email_address = "test@example.com"
    return SendSESNotificationAction(session, mock_app_config)


@pytest.fixture
def mock_notification_kwargs():
    """Provides a sample dictionary of kwargs that the NotificationManager would send."""
    return {
        "finding": {"Type": "Test:S3/Finding"},
        "playbook_name": "TestPlaybook",
        "template_type": "complete",
        "resource": MagicMock(template_name="partials/_s3bucketdetails.md.j2"),
        "enriched_data": {"versioning": "Enabled"},
        "final_status_emoji": "✅",
        "final_status_message": "Playbook completed successfully.",
        "actions_summary": "- TagS3Bucket: SUCCESS",
    }


def test_ses_action_success(
    ses_action, mock_boto_session, mock_app_config, mock_notification_kwargs
):
    """
    GIVEN a valid set of notification data and SES is enabled.
    WHEN the action is executed.
    THEN it should render the template with all kwargs and send an email.
    """
    _, mock_ses_client = mock_boto_session

    # Mock the Jinja2 environment and template
    mock_template = MagicMock()
    # Define a realistic rendered output for the test
    mock_template.render.return_value = (
        "Subject: Test Subject\n\n<p>This is the body.</p>"
    )

    # Patch the get_template call within the action's instance
    with patch.object(
        ses_action.jinja_env, "get_template", return_value=mock_template
    ) as mock_get_template:
        result = ses_action.execute(**mock_notification_kwargs)

    assert result["status"] == "success"

    #  Verify the correct HTML template was loaded
    mock_get_template.assert_called_once_with("ses/complete.html.j2")

    # Verify the template was rendered with all the context it received
    mock_template.render.assert_called_once_with(**mock_notification_kwargs)

    # Verify the email was sent with the correct, parsed content
    mock_ses_client.send_email.assert_called_once()
    sent_args = mock_ses_client.send_email.call_args[1]  # Get keyword arguments
    assert sent_args["Message"]["Subject"]["Data"] == "Test Subject"
    assert "<p>This is the body.</p>" in sent_args["Message"]["Body"]["Html"]["Data"]


def test_ses_action_skipped_when_disabled(
    ses_action, mock_boto_session, mock_app_config
):
    """
    GIVEN SES is disabled in the configuration.
    WHEN the action is executed.
    THEN it should return a 'skipped' status and not send an email.
    """
    _, mock_ses_client = mock_boto_session
    mock_app_config.allow_ses = False  # Disable the action

    result = ses_action.execute()

    assert result["status"] == "skipped"
    assert "SES notifications are disabled" in result["details"]
    mock_ses_client.send_email.assert_not_called()


def test_ses_action_handles_boto3_error(
    ses_action, mock_boto_session, mock_notification_kwargs
):
    """
    GIVEN the boto3 SES client raises an error.
    WHEN the action is executed.
    THEN it should catch the exception and return an 'error' status.
    """
    _, mock_ses_client = mock_boto_session
    mock_ses_client.send_email.side_effect = ClientError(
        error_response={"Error": {"Code": "MessageRejected"}},
        operation_name="SendEmail",
    )

    # Configure the mock template to return a valid, splittable string.
    mock_template = MagicMock()
    mock_template.render.return_value = "Subject: Test Subject\n\nBody content."

    with patch.object(ses_action.jinja_env, "get_template", return_value=mock_template):
        result = ses_action.execute(**mock_notification_kwargs)

    assert result["status"] == "error"
    assert "MessageRejected" in result["details"]


def test_ses_action_handles_template_render_error(ses_action, mock_notification_kwargs):
    """
    GIVEN the Jinja2 template rendering fails.
    WHEN the action is executed.
    THEN it should catch the exception and return an 'error' status.
    """
    mock_template = MagicMock()
    mock_template.render.side_effect = Exception("Jinja rendering failed")

    with patch.object(ses_action.jinja_env, "get_template", return_value=mock_template):
        result = ses_action.execute(**mock_notification_kwargs)

    assert result["status"] == "error"
    assert "Jinja rendering failed" in result["details"]
