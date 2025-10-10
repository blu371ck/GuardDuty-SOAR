import logging
from typing import Union

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.notifications.base import BaseNotificationAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, EnrichedEC2Finding, GuardDutyEvent

logger = logging.getLogger(__name__)


class SendSNSNotificationAction(BaseNotificationAction):
    """An action to send a formatted JSON notification via AWS SNS."""

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.sns_client = self.session.client("sns")

    def execute(self, **kwargs) -> ActionResponse:
        if not self.config.allow_sns:
            return {
                "status": "success",
                "details": "SNS notifications are disabled in config.",
            }

        logger.info("Executing SNS action.")
        try:
            context = self._build_template_context(**kwargs)
            template_type = kwargs.get("template_type", "starting")

            # Render the SNS-specific JSON template
            message_body = self._render_template(
                "sns", f"{template_type}.json.j2", context
            )
            subject = f"GuardDuty-SOAR Event: {context['finding']['Type']}"[:100]

            self.sns_client.publish(
                TopicArn=self.config.sns_topic_arn,
                Message=message_body,
                Subject=subject,
                MessageStructure="raw",  # We use 'raw' since we are publishing JSON
            )
            details = "Successfully sent notification via SNS."
            logger.info(details)
            return {"status": "success", "details": details}
        except ClientError as e:
            details = f"Failed to publish to SNS: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            details = f"An unexpected error occurred in SNS action: {e}."
            logger.error(details, exc_info=True)
            return {"status": "error", "details": details}
