import boto3
import pytest

from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction

# Mark all tests in this file as 'integration' tests
pytestmark = pytest.mark.integration


def test_sns_action_integration(guardduty_finding_detail, real_app_config):
    """
    This test runs the SendSNSNotificationAction against the REAL AWS SNS service.
    It requires a valid SNS Topic ARN to be configured in gd.test.cfg.
    """
    session = boto3.Session()
    action = SendSNSNotificationAction(session, real_app_config)

    # Check if the user has configured a real SNS topic for testing
    if not real_app_config.allow_sns or "123456789012" in real_app_config.sns_topic_arn:
        pytest.skip(
            "Skipping SNS integration test: 'allow_sns' is not True or 'sns_topic_arn' is not configured in gd.test.cfg"
        )

    result = action.execute(
        guardduty_finding_detail,
        playbook_name="IntegrationTestPlaybook",
        template_type="complete",
        # Add mock completion details for a realistic test
        final_status_emoji="✅",
        actions_summary="- TagInstance: SUCCESS\n- IsolateInstance: SUCCESS",
        final_status_message="Playbook completed successfully.",
    )

    assert result["status"] == "success"
    assert "Successfully sent notification via SNS" in result["details"]

    print(
        f"\n✅ Successfully sent SNS test notification to {real_app_config.sns_topic_arn}. Please check your topic subscription."
    )
