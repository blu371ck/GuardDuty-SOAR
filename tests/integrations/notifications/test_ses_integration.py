import boto3
import pytest

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction

# Mark all tests in this file as 'integration' tests
pytestmark = pytest.mark.integration


def test_ses_action_integration(guardduty_finding_detail, real_app_config):
    """
    This test runs the SendSESNotificationAction against the REAL AWS SES service.
    It requires a verified email address to be configured in gd.test.cfg[cite: 8].
    """
    session = boto3.Session()
    action = SendSESNotificationAction(session, real_app_config)

    # Check if the user has configured a real email address for testing [cite: 9]
    if (
        not real_app_config.allow_ses
        or "example.com" in real_app_config.registered_email_address
    ):
        pytest.skip(
            "Skipping SES integration test: 'allow_ses' is not True or 'registered_email_address' is not configured in gd.test.cfg"
        )

    result = action.execute(
        guardduty_finding_detail,
        playbook_name="IntegrationTestPlaybook",
        template_type="starting",
    )

    assert result["status"] == "success"
    assert "Successfully sent notification via SES" in result["details"]

    print(
        f"\n✅ Successfully sent SES test email to {real_app_config.registered_email_address}. Please check your inbox."
    )
