import json
import logging
from typing import Union

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.notifications.base import BaseNotificationAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse

logger = logging.getLogger(__name__)


class SendSNSNotificationAction(BaseNotificationAction):
    """
    An action to send formatted JSON notifications via AWS SNS. This notifications
    are more machine-friendly, and can be linked to other services and functionality
    like SIEM solutions, Jira ticketing, etc.

    :param session: a Boto3 Session object to make clients with.
    :param config: the Applications configurations.

    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.sns_client = self.session.client("sns")

    def execute(self, **kwargs) -> ActionResponse:
        if not self.config.allow_sns:
            logger.warning("SNS notifications are disabled in the configuration.")
            return {
                "status": "skipped",
                "details": "SNS notifications are disabled in config.",
            }

        logger.warning("ACTION: Executing SNS action.")
        try:
            # Build the payload as a Python dictionary instead of using a template.
            finding = kwargs.get("finding", {})
            resource = kwargs.get("resource")
            enriched_data = kwargs.get("enriched_data")
            template_type = kwargs.get("template_type", "starting")

            # Start building the payload dictionary
            payload = {
                "event_type": (
                    "playbook_started"
                    if template_type == "starting"
                    else "playbook_completed"
                ),
                "playbook_name": kwargs.get("playbook_name"),
                "finding": {
                    "id": finding.get("Id"),
                    "type": finding.get("Type"),
                    "severity": finding.get("Severity"),
                    "account_id": finding.get("AccountId"),
                    "region": finding.get("Region"),
                    "title": finding.get("Title"),
                },
            }

            # Add fields that only exist for 'complete' notifications
            if template_type == "complete":
                payload.update(
                    {
                        "status_emoji": kwargs.get("final_status_emoji"),
                        "status_message": kwargs.get("final_status_message"),
                        "actions_summary": kwargs.get("actions_summary", "").replace(
                            "\n", "; "
                        ),
                    }
                )

            # Add resource and enriched_data using their direct dictionary representations
            if resource:
                payload["resource"] = resource.model_dump(mode="json")

            if enriched_data:
                payload["enriched_data"] = enriched_data

            # Serialize the entire dictionary to a JSON string at the very end.
            # Use default=str to handle non-serializable types like datetime.
            message_body = json.dumps(
                payload, default=str, indent=2, ensure_ascii=False
            )

            subject = f"GuardDuty-SOAR Event: {finding.get('Type', 'Unknown')}"[:100]

            self.sns_client.publish(
                TopicArn=self.config.sns_topic_arn,
                Message=message_body,
                Subject=subject,
                MessageStructure="raw",
            )
            details = "Successfully sent notification via SNS."
            logger.info(details)
            return {"status": "success", "details": details}
        except Exception as e:
            details = f"An unexpected error occurred in SNS action: {e}."
            logger.error(details, exc_info=True)
            return {"status": "error", "details": details}
