import boto3
import pytest

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction
from guardduty_soar.config import get_config

pytestmark = pytest.mark.integration


@pytest.fixture(scope="module")
def real_app_config():
    """Provides a real AppConfig instance for integration tests."""
    return get_config()


def test_ses_action_integration(guardduty_finding_detail, real_app_config):
    """
    This test runs the SendSESNotificationAction against the REAL AWS SES service.
    It requires a verified email address to be configured in gd.test.cfg.
    """
    session = boto3.Session()
    action = SendSESNotificationAction(session, real_app_config)

    # Check if the user has configured an email address for testing
    if "example.com" in real_app_config.registered_email_address:
        pytest.skip(
            "Skipping SES integration test: 'registered_email_address' is not configured in gd.test.cfg"
        )

    result = action.execute(
        guardduty_finding_detail,
        playbook_name="IntegrationTestPlaybook",
        template_type="starting",
    )

    assert result["status"] == "success"
    assert "Successfully sent notification via SES" in result["details"]

    print(
        f"\nSuccessfully sent test email to {real_app_config.registered_email_address}. Please check your inbox."
    )
