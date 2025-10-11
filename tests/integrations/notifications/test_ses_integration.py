import logging

import boto3
import pytest

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction
from guardduty_soar.schemas import map_resource_to_model

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)


def test_ses_action_integration(guardduty_finding_detail, real_app_config):
    """
    Tests the SendSESNotificationAction against the REAL AWS SES service.
    """
    if not real_app_config.allow_ses or not real_app_config.registered_email_address:
        pytest.skip(
            "Skipping SES test: 'allow_ses' is not True or 'registered_email_address' is not configured."
        )

    session = boto3.Session()
    action = SendSESNotificationAction(session, real_app_config)

    # 1. Create the base resource model
    resource_model = map_resource_to_model(guardduty_finding_detail.get("Resource", {}))

    # 2. Call execute with named arguments
    result = action.execute(
        finding=guardduty_finding_detail,
        resource=resource_model,
        enriched_data=None,  # For a 'starting' notification, enriched_data is usually None
        playbook_name="IntegrationTestPlaybook",
        template_type="starting",
    )

    assert result["status"] == "success"
    assert "Successfully sent notification via SES" in result["details"]
    logger.info(
        f"Successfully sent SES test email to {real_app_config.registered_email_address}."
    )
