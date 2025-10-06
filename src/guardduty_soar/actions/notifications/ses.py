import logging
from typing import Union

import boto3
import markdown
from botocore.exceptions import ClientError

from guardduty_soar.actions.notifications.base import BaseNotificationAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, EnrichedEC2Finding, GuardDutyEvent

logger = logging.getLogger(__name__)


class SendSESNotificationAction(BaseNotificationAction):
    """An action to send a formatted notification via AWS SES."""

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
        logger.info("Executing SES action.")
        try:
            context = self._build_template_context(data, **kwargs)
            template_type = kwargs.get("template_type", "starting")

            rendered_content = self._render_template(
                "ses", f"{template_type}.md.j2", context
            )

            subject, body = rendered_content.split("\n", 1)
            subject = subject.replace("Subject: ", "").strip()
            html_body = markdown.markdown(body)

            self.ses_client.send_email(
                Source=self.config.registered_email_address,
                Destination={"ToAddresses": [self.config.registered_email_address]},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {"Text": {"Data": body}, "Html": {"Data": html_body}},
                },
            )
            details = "Successfully sent notification via SES."
            logger.info(details)
            return {"status": "success", "details": details}
        except ClientError as e:
            details = f"Failed to send SES email: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            details = f"An unexpected error occurred in SES action: {e}."
            logger.error(details, exc_info=True)
            return {"status": "error", "details": details}
