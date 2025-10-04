import logging

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class IsolateInstanceAction(BaseAction):
    """
    An action to isolate an EC2 instance. We utilize an isolation
    security group (or quarantined security group) and remove all
    other security groups from the instance. Ideally, the
    quarantined security group should be a security group with no
    rules.
    """

    def __init__(self, boto3_session: boto3.Session, config: AppConfig):
        super().__init__(boto3_session, config)
        # We only need to create the specific boto3 client once, for each
        # action. Creating a disposable client.
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
        quarantine_sg_id = self.config.quarantine_sg_id

        logger.warning(
            f"ACTION: Isolating instance: {instance_id} with security group: {quarantine_sg_id}."
        )
        try:
            self.ec2_client.modify_instance_attribute(
                InstanceId=instance_id, Groups=[quarantine_sg_id]
            )
            details = f"Successfully isolated instance: {instance_id}."
            logger.info(details)
            return {"status": "success", "details": details}
        except ClientError as e:
            details = f"Failed to isolate instance: {instance_id}. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
        except Exception as e:
            # Generic catch-all
            details = f"An unknown error occurred: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
