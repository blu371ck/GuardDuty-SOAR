import logging

import boto3
import pytest

from guardduty_soar.actions.notifications.sns import SendSNSNotificationAction
from guardduty_soar.schemas import map_resource_to_model

pytestmark = pytest.mark.integration

logger = logging.getLogger(__name__)


def test_sns_action_integration(enriched_ec2_finding, real_app_config):
    """
    Tests the SendSNSNotificationAction against the REAL AWS SNS service
    using an enriched finding.
    """
    if not real_app_config.allow_sns or not real_app_config.sns_topic_arn:
        pytest.skip(
            "Skipping SNS test: 'allow_sns' is not True or 'sns_topic_arn' is not configured."
        )

    session = boto3.Session()
    action = SendSNSNotificationAction(session, real_app_config)

    finding = enriched_ec2_finding["guardduty_finding"]
    instance_metadata = enriched_ec2_finding["instance_metadata"]

    # 1. Create the resource model using the enriched metadata
    resource_model = map_resource_to_model(
        finding.get("Resource", {}), instance_metadata=instance_metadata
    )

    # 2. Call execute with named arguments
    result = action.execute(
        finding=finding,
        resource=resource_model,
        enriched_data=enriched_ec2_finding,  # Pass the full enriched data
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
