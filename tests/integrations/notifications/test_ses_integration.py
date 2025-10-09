import logging

import boto3
import pytest

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)


def test_ses_action_integration(guardduty_finding_detail, real_app_config, aws_region):
    """
    Tests the SendSESNotificationAction against the REAL AWS SES service.
    """
    if (
        not real_app_config.allow_ses
        or "example.com" in real_app_config.registered_email_address
    ):
        pytest.skip(
            "Skipping SES test: 'allow_ses' is not True or 'registered_email_address' is not configured."
        )

    session = boto3.Session(region_name=aws_region)
    action = SendSESNotificationAction(session, real_app_config)
    result = action.execute(
        guardduty_finding_detail,
        playbook_name="IntegrationTestPlaybook",
        template_type="starting",
    )

    assert result["status"] == "success"
    assert "Successfully sent notification via SES" in result["details"]
    logger.info(
        f"Successfully sent SES test email to {real_app_config.registered_email_address}."
    )
