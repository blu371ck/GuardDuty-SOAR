import logging

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, EnrichedEC2Finding, GuardDutyEvent

logger = logging.getLogger(__name__)


class EnrichFindingWithInstanceMetadataAction(BaseAction):
    """
    An action to enrich the GuardDuty finding with detailed metadata
    about the affected EC2 instance by calling the describe_instances
    API call.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]

        logger.info(f"ACTION: Obtaining instance metadata for {instance_id}.")

        try:
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])

            # Make sure instances were returned
            if not response.get("Reservations") or not response["Reservations"][0].get(
                "Instances"
            ):
                raise ClientError({"Error": {"Code": "NotFound"}}, "DescribeInstances")

            instance_metadata = response["Reservations"][0]["Instances"][0]

            # Create the enriched data structure
            enriched_finding: EnrichedEC2Finding = {
                "guardduty_finding": event,
                "instance_metadata": instance_metadata,
            }
            logger.info("Returning newly enriched dataset.")

            return {"status": "success", "details": enriched_finding}

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            if error_code == "InvalidInstanceId.NotFound" or error_code == "NotFound":
                details = f"Instance {instance_id} not found (may already be terminated). Cannot enrich finding."
                logger.warning(details)
                # Return success because there's no further action to be taken.
                return {"status": "success", "details": details}

            details = f"Failed to describe instance {instance_id}: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
