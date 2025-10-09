import logging

import boto3
import pytest

from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)


def test_sns_action_integration(guardduty_finding_detail, real_app_config, aws_region):
    """
    Tests the SendSNSNotificationAction against the REAL AWS SNS service.
    """
    if not real_app_config.allow_sns or "123456789012" in real_app_config.sns_topic_arn:
        pytest.skip(
            "Skipping SNS test: 'allow_sns' is not True or 'sns_topic_arn' is not configured."
        )

    session = boto3.Session(region_name=aws_region)
    action = SendSNSNotificationAction(session, real_app_config)
    result = action.execute(
        guardduty_finding_detail,
        playbook_name="IntegrationTestPlaybook",
        template_type="complete",
        final_status_emoji="✅",
        actions_summary="- TestAction: SUCCESS",
        final_status_message="Playbook completed successfully.",
    )

    assert result["status"] == "success"
    assert "Successfully sent notification via SNS" in result["details"]
    logger.info(
        f"Successfully sent SNS test notification to {real_app_config.sns_topic_arn}."
    )
