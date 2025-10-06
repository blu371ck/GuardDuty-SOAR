import logging
from typing import Union

import boto3
from botocore.exceptions import ClientError
import markdown
from guardduty_soar.actions.notifications.base import BaseNotificationAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import (ActionResponse, EnrichedEC2Finding,
                                   GuardDutyEvent)

logger = logging.getLogger(__name__)


class SendSESNotificationAction(BaseNotificationAction):
    """
    An action to send a formatted notification via AWS SES.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ses_client = self.session.client("ses")

    def execute(
        self, data: Union[GuardDutyEvent, EnrichedEC2Finding], **kwargs
    ) -> ActionResponse:
        if not self.config.allow_ses:
            return {
                "status": "success",
                "details": "SES notifications are disabled in config.",
            }

        template_type = kwargs.get("template_type", "starting")
        template_content = self._get_template("ses", template_type)
        if not template_type:
            return {
                "status": "error",
                "details": f"SES template '{template_type}' not found.",
            }

        try:
            subject_line, body = template_content.split("\n", 1)
            subject = subject_line.replace("Subject: ", "").strip()
        except ValueError:
            subject = "GuardDuty-SOAR Notification"
            body = template_content

        template_data = self._build_template_data(data, **kwargs)
        message_body = body.format(**template_data)
        html_data = markdown.markdown(message_body)
        try:
            self.ses_client.send_email(
                Source=self.config.registered_email_address,
                Destination={"ToAddresses": [self.config.registered_email_address]},
                Message={
                    "Subject": {"Data": subject.format(**template_data)},
                    "Body": {"Text": {"Data": message_body}, "Html": {"Data": html_data}},
                },
            )
            details = "Successfully sent notification via SES."
            logger.info(details)
            return {"status": "success", "details": details}
        except ClientError as e:
            details = f"Failed to send SES email: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except KeyError as e:
            details = f"Failed to format SES template. Missing placeholder: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
