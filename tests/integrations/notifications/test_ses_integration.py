# In tests/integrations/notifications/test_ses_integration.py

import dataclasses
import logging

import boto3
import pytest

from guardduty_soar.actions.notifications.ses import SendSESNotificationAction
from guardduty_soar.schemas import map_resource_to_model

pytestmark = pytest.mark.integration
logger = logging.getLogger(__name__)


def test_ses_notification_action_integration(real_app_config, s3_guardduty_event):
    """
    Tests that the SendSESNotificationAction can successfully send a real email
    using the configured, verified email address.
    """
    # The real application config, ensuring SES is enabled
    # The 'registered_email_address' from your .env file will be used as both sender and receiver.
    test_config = dataclasses.replace(real_app_config, allow_ses=True)

    # Ensure a verified email is actually configured before running
    if not test_config.registered_email_address:
        pytest.skip(
            "No registered_email_address is configured to run SES integration test."
        )

    session = boto3.Session()
    action = SendSESNotificationAction(session, test_config)

    # Prepare a realistic context for the template
    finding = s3_guardduty_event["detail"]
    resource = map_resource_to_model(finding.get("Resource", {}))

    kwargs = {
        "finding": finding,
        "playbook_name": "SESIntegrationTestPlaybook",
        "template_type": "complete",
        "resource": resource,
        "enriched_data": {
            "versioning": "Enabled",
            "tags": [{"Key": "Test", "Value": "True"}],
        },
        "final_status_emoji": "✅",
        "final_status_message": "Playbook completed successfully.",
        "actions_summary": "- TestAction1: SUCCESS\n- TestAction2: SKIPPED",
    }

    # WHEN: The action is executed, making a real API call to the SES service
    logger.info(
        f"Executing SES action to send a real email to {test_config.registered_email_address}..."
    )
    result = action.execute(**kwargs)

    # THEN: The action should report success, indicating a successful API call
    assert result["status"] == "success"
    logger.info("Successfully verified that the SES action made a successful API call.")
