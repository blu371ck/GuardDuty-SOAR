from unittest.mock import MagicMock

import boto3
from botocore.stub import Stubber

from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction


def test_sns_action_execute_success(guardduty_finding_detail, mock_app_config, mocker):
    """
    Tests that the SNS action correctly renders a JSON template and calls the SNS API.
    """
    # setup testing
    mock_app_config.allow_sns = True
    mock_app_config.sns_topic_arn = "arn:aws:sns:us-east-1:123456789012:MyTopic"

    sns_client = boto3.client("sns", region_name="us-east-1")
    stubber = Stubber(sns_client)

    rendered_json = '{"key": "value"}'

    expected_params = {
        "TopicArn": mock_app_config.sns_topic_arn,
        "Message": rendered_json,
        "Subject": "GuardDuty-SOAR Event: UnauthorizedAccess:EC2/TorClient",
        "MessageStructure": "raw",
    }
    stubber.add_response("publish", {"MessageId": "123"}, expected_params)

    mock_session = MagicMock()
    mock_session.client.return_value = sns_client

    action = SendSNSNotificationAction(mock_session, mock_app_config)

    # Mock the context build to include the finding for the subject line
    context = {"finding": guardduty_finding_detail}
    mocker.patch.object(action, "_build_template_context", return_value=context)
    mocker.patch.object(action, "_render_template", return_value=rendered_json)

    with stubber:
        result = action.execute(guardduty_finding_detail, template_type="complete")

    assert result["status"] == "success"
    stubber.assert_no_pending_responses()
    action._render_template.assert_called_once_with("sns", "complete.json.j2", context)


def test_sns_action_disabled_in_config(guardduty_finding_detail, mock_app_config):
    """Tests that no API call is made if allow_sns is False."""
    mock_app_config.allow_sns = False
    mock_session = MagicMock()
    action = SendSNSNotificationAction(mock_session, mock_app_config)

    result = action.execute(guardduty_finding_detail)

    assert result["status"] == "success"
    assert "disabled" in result["details"]
    mock_session.client.return_value.publish.assert_not_called()
