import logging

import boto3
from botocore.exceptions import ClientError

from guardduty_soar.actions.base import BaseAction
from guardduty_soar.config import AppConfig
from guardduty_soar.models import ActionResponse, GuardDutyEvent

logger = logging.getLogger(__name__)


class QuarantineInstanceProfileAction(BaseAction):
    """
    An action to quarantine an EC2 instance's IAM role by attaching a
    'deny-all' policy to it. This action correctly looks up the role
    associated with the instance profile.
    """

    def __init__(self, session: boto3.Session, config: AppConfig):
        super().__init__(session, config)
        self.iam_client = self.session.client("iam")
        self.ec2_client = self.session.client("ec2")

    def execute(self, event: GuardDutyEvent, **kwargs) -> ActionResponse:
        instance_id = event["Resource"]["InstanceDetails"]["InstanceId"]
        logger.info(
            f"ACTION: Attempting to quarantine instance profile attached to instance: {instance_id}."
        )
        try:
            # Step 1: Get live instance metadata
            response = self.ec2_client.describe_instances(InstanceIds=[instance_id])

            if not response.get("Reservations") or not response["Reservations"][0].get(
                "Instances"
            ):
                details = f"Instance {instance_id} not found. Skipping role quarantine."
                logger.warning(details)
                return {"status": "skipped", "details": details}

            instance_metadata = response["Reservations"][0]["Instances"][0]
            iam_profile = instance_metadata.get("IamInstanceProfile")

            if not iam_profile or not iam_profile.get("Arn"):
                details = f"Instance {instance_id} has no IAM instance profile. Skipping role quarantine."
                logger.info(details)
                return {"status": "skipped", "details": details}

            # Step 2: Get the Instance Profile Name from its ARN
            instance_profile_arn = iam_profile["Arn"]
            instance_profile_name = instance_profile_arn.split("/")[-1]

            # Step 3: Call GetInstanceProfile to find the associated Role Name
            profile_details = self.iam_client.get_instance_profile(
                InstanceProfileName=instance_profile_name
            )

            roles = profile_details.get("InstanceProfile", {}).get("Roles")
            if not roles:
                details = (
                    f"Instance profile {instance_profile_name} has no associated roles."
                )
                logger.error(details)
                return {"status": "error", "details": details}

            role_name = roles[0]["RoleName"]  # This is the correct role name
            logger.info(f"Found instance role: {role_name}.")
            deny_policy_arn = "arn:aws:iam::aws:policy/AWSDenyAll"

            # Step 4: Attach the deny policy to the correct role
            logger.warning(
                f"ACTION: Attaching deny-all policy ({deny_policy_arn}) to IAM role ({role_name})."
            )
            self.iam_client.attach_role_policy(
                RoleName=role_name, PolicyArn=deny_policy_arn
            )

            details = f"Successfully attached deny-all policy to role {role_name}."
            logger.info(details)
            return {"status": "success", "details": details}

        except ClientError as e:
            # Handle cases where the instance might have been terminated mid-process
            if "NotFound" in e.response.get("Error", {}).get("Code", ""):
                details = f"Instance {instance_id} or its profile not found. Skipping role quarantine."
                logger.warning(details)
                return {"status": "success", "details": details}

            details = f"Failed to attach deny policy. Error: {e}."
            logger.error(details)
            return {"status": "error", "details": details}
