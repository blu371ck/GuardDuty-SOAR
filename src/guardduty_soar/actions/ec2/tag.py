import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class TagInstanceAction(BaseAction):
    """
    An action to tag an EC2 instance. Indicating an event has occurred
    and provides visibility that the playbook has worked on that
    instance.
    """

    def __init__(self, boto3_session: boto3.Session, config: AppConfig):
        super().__init__(boto3_session, config)
        # We only need to create the specific boto3 client once, for each
        # action. Creating a disposable client.
        self.ec2_client = self.session.client("ec2")

    def _calculate_severity(self, severity: float) -> str:
        """
        Simple function to take the numerical severity and return
        a more human-friendly label. Used in tagging.
        """
        if 9.0 <= severity <= 10.0:
            return "CRITICAL"
        elif 7.0 <= severity <= 8.9:
            return "HIGH"
        elif 4.0 <= severity <= 6.9:
            return "MEDIUM"
        else:
            return "LOW"

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
        playbook_name = kwargs.get("playbook_name", "UnknownPlaybook")

        logger.warning(f"ACTION: Tagging instance: {instance_id}")
        try:
            self.ec2_client.create_tags(
                Resources=[instance_id],
                Tags=[
                    {"Key": "GUARDDUTY-SOAR-ID", "Value": event["Id"]},
                    {"Key": "SOAR-Status", "Value": "Remediation-In-Progress"},
                    {
                        "Key": "SOAR-Action-Time-UTC",
                        "Value": datetime.now(timezone.utc).isoformat(),
                    },
                    {"Key": "SOAR-Finding-Type", "Value": event["Type"]},
                    {
                        "Key": "SOAR-Finding-Severity",
                        "Value": self._calculate_severity(float(event["Severity"])),
                    },
                    {"Key": "SOAR-Playbook", "Value": playbook_name},
                ],
            )
            details = f"Successfully added SOAR tags to instance: {instance_id}."
            logger.info(details)
            return {"status": "success", "details": details}
        except ClientError as e:
            details = f"Failed to add tags to instance: {instance_id}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            # Generic catch all
            details = f"An unknown error occurred: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
