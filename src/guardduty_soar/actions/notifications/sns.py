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

    :param session: a Boto3 Session object to create clients with.
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
