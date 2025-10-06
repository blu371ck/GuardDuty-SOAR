import logging
import os
from typing import Any, Dict, Union, cast

import boto3

from guardduty_soar.config import AppConfig
from guardduty_soar.models import (ActionResponse, EnrichedEC2Finding,
                                   GuardDutyEvent)

logger = logging.getLogger(__name__)


class BaseNotificationAction:
    """
    An abstract base class for all notification actions. It defines a common
    interface and provides helper methods for templating.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        """
        Initializes the action with a boto3 session and the application config.
        """
        self.session = session
        self.config = config

    def _get_template(self, channel: str, template_type: str) -> str:
        """Loads a specific template file from the filesystem."""
        # This path navigates up from /actions/notifications/ to the project root
        template_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            "templates",
            channel,
            f"{template_type}.md",  # Assuming .md for now
        )
        try:
            with open(template_path, "r") as f:
                return f.read()
        except FileNotFoundError:
            logger.error(f"Template not found at: {template_path}")
            return ""

    def _build_template_data(
        self, data: Union[GuardDutyEvent, EnrichedEC2Finding], **kwargs
    ) -> Dict[str, Any]:
        """
        Creates a dictionary of values to populate templates, handling both basic
        and enriched finding data structures.
        """
        # This check is now type-safe because the execute method's signature allows for the Union
        if isinstance(data, dict) and "guardduty_finding" in data:
            enriched_data = cast(EnrichedEC2Finding, data)
            finding = enriched_data["guardduty_finding"]
            metadata = enriched_data.get("instance_metadata", {})
        else:
            finding = data
            metadata = {}

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
            "playbook_name": kwargs.get("playbook_name", "UnknownPlaybook"),
            "console_link": f"https://{finding.get('Region', 'us-east-1')}.console.aws.amazon.com/guardduty/home?region={finding.get('Region', 'us-east-1')}#/findings?macros=current&fId={finding.get('Id', '')}",
            "resource_id": finding.get("Resource", {}).get("InstanceDetails", {}).get("InstanceId", "N/A"),
            "instance_id": metadata.get("InstanceId", "N/A"),
            "instance_type": metadata.get("InstanceType", "N/A"),
            "public_ip": metadata.get("PublicIpAddress", "N/A"),
            "private_ip": metadata.get("PrivateIpAddress", "N/A"),
            "vpc_id": metadata.get("VpcId", "N/A"),
            "subnet_id": metadata.get("SubnetId", "N/A"),
            "iam_profile": metadata.get("IamInstanceProfile", {}).get("Arn", "N/A"),
            "instance_tags": formatted_tags,
            "final_status_emoji": kwargs.get("final_status_emoji", ""),
            "actions_summary": kwargs.get("actions_summary", "No actions were taken."),
            "final_status_message": kwargs.get(
                "final_status_message", "Playbook execution finished."
            ),
        }

        return template_data

    def execute(
        self, data: Union[GuardDutyEvent, EnrichedEC2Finding], **kwargs
    ) -> ActionResponse:
        """
        The main entry point for the action. Each child notification class
        MUST implement this method.
        """
        raise NotImplementedError
