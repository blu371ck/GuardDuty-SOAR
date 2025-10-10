from unittest.mock import MagicMock

import boto3
from botocore.stub import Stubber

from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction


def test_sns_action_execute(mocker):
    """
    Tests the execute method of the SNS action, verifying it calls helpers
    and the boto3 client correctly.
    """
    mock_config = MagicMock(
        allow_sns=True, sns_topic_arn="arn:aws:sns:us-east-1:123456789012:MyTopic"
    )
    action = SendSNSNotificationAction(MagicMock(), mock_config)

    # Mock the internal methods and the boto3 client
    context = {"finding": {"Type": "TestFinding"}}
    mock_build_context = mocker.patch.object(
        action, "_build_template_context", return_value=context
    )
    mock_render = mocker.patch.object(
        action, "_render_template", return_value='{"key": "value"}'
    )
    mock_publish = mocker.patch.object(action.sns_client, "publish")

    input_kwargs = {
        "finding": {"Type": "TestFinding"},
        "resource": MagicMock(),
        "enriched_data": None,
        "template_type": "complete",
    }

    result = action.execute(**input_kwargs)

    assert result["status"] == "success"
    # Call the assertion methods on the captured mock objects
    mock_build_context.assert_called_once_with(**input_kwargs)
    mock_render.assert_called_once_with("sns", "complete.json.j2", context)
    mock_publish.assert_called_once()
