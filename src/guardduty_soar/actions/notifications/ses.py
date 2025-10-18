import logging

import boto3

from guardduty_soar.actions.notifications.base import BaseNotificationAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse

logger = logging.getLogger(__name__)


class SendSESNotificationAction(BaseNotificationAction):
    """
    An action to send formatted notifications via AWS SES. SES notifications
    are more human-readable and friendly emails.

    :param session: a Boto3 Session object to create clients with.
    :param config: the Applications configurations.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ses_client = self.session.client("ses")

    def execute(self, **kwargs) -> ActionResponse:
        logger.warning("ACTION: Executing SES action.")
        if not self.config.allow_ses:
            logger.warning("SES is disabled in the configuration.")
            return {"status": "skipped", "details": "SES notifications are disabled."}

        try:
            template_type = kwargs.get("template_type", "starting")
            template = self.jinja_env.get_template(f"ses/{template_type}.html.j2")
            rendered_content = template.render(**kwargs)

            subject, body = rendered_content.strip().split("\n", 1)
            subject = subject.replace("Subject: ", "").strip()

            # The template now generates HTML directly.
            # We no longer need the markdown library. 'body' is now 'html_body'.
            html_body = body

            self.ses_client.send_email(
                Source=self.config.registered_email_address,
                Destination={"ToAddresses": [self.config.registered_email_address]},
                Message={
                    "Subject": {"Data": subject},
                    "Body": {
                        "Text": {
                            "Data": "Please view this email in an HTML-compatible client."
                        },
                        "Html": {"Data": html_body},
                    },
                },
            )
            logger.info("Successfully sent notification via SES.")
            return {
                "status": "success",
                "details": "Successfully sent notification via SES.",
            }
        except Exception as e:
            details = f"An unexpected error occurred in SES action: {e}"
            logger.error(details, exc_info=True)
            return {"status": "error", "details": details}
