import logging

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class TerminateInstanceAction(BaseAction):
    """
    An action to terminate a compromised EC2 instance.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]

        # CRITICAL SAFETY CHECK: Verify that termination is allowed in the config.
        if not self.config.allow_terminate:
            details = (
                f"Termination is disabled in the configuration (allow_terminate=False). "
                f"Skipping termination for instance {instance_id}."
            )
            logger.warning(details)
            # Return 'success' because this is an intentional stop, not an error.
            return {"status": "success", "details": details}

        logger.warning(f"ACTION: Terminating instance: {instance_id}")

        try:
            self.ec2_client.terminate_instances(InstanceIds=[instance_id])
            details = f"Successfully initiated termination for instance {instance_id}."
            logger.info(details)
            return {"status": "success", "details": details}
        except ClientError as e:
            details = f"Failed to terminate instance {instance_id}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
