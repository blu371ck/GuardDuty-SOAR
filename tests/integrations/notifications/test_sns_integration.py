import dataclasses
import json
import logging
from datetime import datetime

import boto3
import pytest

from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction
from guardduty_soar.schemas import map_resource_to_model

pytestmark = pytest.mark.integration
logger = logging.getLogger(__name__)


def test_sns_notification_action_integration(
    real_app_config,
    s3_guardduty_event,
    e2e_notification_channel,
    sqs_poller,
):
    """
    Tests that the SendSNSNotificationAction can successfully publish a
    correctly formatted and serialized JSON message to a live SNS topic,
    which is then received by a subscribed SQS queue.
    """
    # A live SNS/SQS channel and an enabled SNS config
    queue_url = e2e_notification_channel["queue_url"]
    test_config = dataclasses.replace(real_app_config, allow_sns=True)

    session = boto3.Session()
    action = SendSNSNotificationAction(session, test_config)

    # Prepare realistic context for the action
    finding = s3_guardduty_event["detail"]
    resource = map_resource_to_model(finding.get("Resource", {}))
    test_datetime = datetime(2025, 10, 17, 12, 0, 0)

    kwargs = {
        "finding": finding,
        "playbook_name": "SNSIntegrationTestPlaybook",
        "template_type": "complete",
        "resource": resource,
        "enriched_data": {"creation_date": test_datetime},
        "final_status_emoji": "✅",
        "final_status_message": "Playbook completed successfully.",
        "actions_summary": "- TestAction: SUCCESS",
    }

    # The action is executed, publishing a message to the live SNS topic
    logger.info("Executing SNS action to publish to a live topic...")
    result = action.execute(**kwargs)

    # The action should report success
    assert result["status"] == "success"

    # A correctly formatted JSON message should be received in the SQS queue
    logger.info(f"Polling SQS queue {queue_url} for the SNS message...")
    messages = sqs_poller(queue_url=queue_url, expected_count=1)

    # The e2e_notification_channel fixture enables RawMessageDelivery,
    # so the SQS message body is the raw JSON string.
    message_data = json.loads(messages[0]["Body"])

    assert message_data["playbook_name"] == "SNSIntegrationTestPlaybook"
    assert message_data["status_emoji"] == "✅"
    assert message_data["event_type"] == "playbook_completed"
    assert "resource" in message_data
    assert "enriched_data" in message_data
    # Verify that the datetime object was successfully serialized to a string
    assert message_data["enriched_data"]["creation_date"] == "2025-10-17 12:00:00"
    logger.info("Successfully received and validated the SNS JSON message.")
