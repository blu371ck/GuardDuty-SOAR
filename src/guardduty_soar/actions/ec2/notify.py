import logging
import os
from typing import Any, Dict, Union

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import (ActionResponse, EnrichedEC2Finding,
                                   GuardDutyEvent)

logger = logging.getLogger(__name__)


class SendNotificationAction(BaseAction):
    """An action to send notifications to configured channels (SES, SNS, etc.)."""

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ses_client = self.session.client("ses")
        # Initialize other clients (sns, etc.) here as you add them

    def _get_template(self, channel: str, template_type: str) -> str:
        """Loads a specific template file from the filesystem."""
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "templates",
            channel,
            f"{template_type}.md",
        )
        try:
            with open(template_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Template not found at: {template_path}")
            return ""

    def _build_template_data(
        self,
        data: Union[GuardDutyEvent, EnrichedEC2Finding],
        playbook_name: str,
        **kwargs,
    ) -> Dict[str, Any]:
        """
        Creates a dictionary of values to populate templates, handling both basic
        and enriched finding data structures.
        """
        finding = data
        metadata = kwargs.get("enriched_data", {})

        # --- 2. Extract Data with Safe Fallbacks ---
        instance_tags = metadata.get("Tags", [])
        formatted_tags = (
            ", ".join([f"{tag['Key']}={tag['Value']}" for tag in instance_tags])
            or "N/A"
        )

        template_data = {
            "finding_id": finding.get("Id", "N/A"),
            "finding_type": finding.get("Type", "N/A"),
            "finding_title": finding.get("Title", "N/A"),
            "finding_severity": finding.get("Severity", "N/A"),
            "finding_description": finding.get("Description", "N/A"),
            "account_id": finding.get("AccountId", "N/A"),
            "region": finding.get("Region", "N/A"),
            "playbook_name": playbook_name,
            "console_link": f"https://{finding.get('Region', 'us-east-1')}.console.aws.amazon.com/guardduty/home?region={finding.get('Region', 'us-east-1')}#/findings?macros=current&fId={finding.get('Id', '')}",
            # --- Enriched Fields ---
            "instance_id": metadata.get("InstanceId", "N/A"),
            "instance_type": metadata.get("InstanceType", "N/A"),
            "public_ip": metadata.get("PublicIpAddress", "N/A"),
            "private_ip": metadata.get("PrivateIpAddress", "N/A"),
            "vpc_id": metadata.get("VpcId", "N/A"),
            "subnet_id": metadata.get("SubnetId", "N/A"),
            "iam_profile": metadata.get("IamInstanceProfile", {}).get("Arn", "N/A"),
            "instance_tags": formatted_tags,
            # --- Fields for 'complete' template ---
            "final_status_emoji": kwargs.get("final_status_emoji", ""),
            "actions_summary": kwargs.get("actions_summary", "No actions were taken."),
            "final_status_message": kwargs.get(
                "final_status_message", "Playbook execution finished."
            ),
        }
        return template_data

    def _send_ses_email(
        self,
        data: Union[GuardDutyEvent, EnrichedEC2Finding],
        playbook_name: str,
        template_type: str,
        **kwargs,
    ):
        """Formats and sends a notification via AWS SES."""
        template_content = self._get_template("ses", template_type)
        if not template_content:
            return

        try:
            subject_line, body = template_content.split("\n", 1)
            subject = subject_line.replace("Subject: ", "").strip()
        except ValueError:
            subject = "GuardDuty-SOAR Notification"
            body = template_content

        template_data = self._build_template_data(data, playbook_name, **kwargs)

        try:
            self.ses_client.send_email(
                Source=self.config.registered_email_address,
                Destination={"ToAddresses": [self.config.registered_email_address]},
                Message={
                    "Subject": {"Data": subject.format(**template_data)},
                    "Body": {"Text": {"Data": body.format(**template_data)}},
                },
            )
            logger.info("Successfully sent notification via SES.")
        except ClientError as e:
            logger.error(f"Failed to send SES email: {e}")
        except KeyError as e:
            logger.error(f"Failed to format SES template. Missing placeholder: {e}")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        playbook_name = kwargs.get("playbook_name", "UnknownPlaybook")
        template_type = kwargs.get("template_type", "starting")

        if self.config.allow_ses:
            self._send_ses_email(event, playbook_name, template_type, **kwargs)

        # ... (logic for other channels) ...

        return {"status": "success", "details": "Notification action complete."}
